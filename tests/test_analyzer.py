"""Self-tests. Standard library only:  python -m unittest discover -s tests -v"""
import io
import os
import subprocess
import sys
import tempfile
import unittest
import datetime as dt
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import splunk_log_analyzer as A  # noqa: E402

SAMPLES = None


def setUpModule():
    global SAMPLES
    SAMPLES = tempfile.mkdtemp(prefix="sla_samples_")
    subprocess.check_call([sys.executable, os.path.join(ROOT, "examples", "generate_samples.py"), SAMPLES],
                          stdout=subprocess.DEVNULL)


def run(files, when, reason, **kw):
    inc, _ = A.parse_user_time(when)
    an = A.Analyzer(inc, reason, **kw)
    for f in files:
        an.feed(os.path.join(SAMPLES, f))
    return an.report()


class TimeParsing(unittest.TestCase):
    def check(self, text, expected, dayfirst=False):
        tp = A.TimeParser(dayfirst=dayfirst, ref=dt.datetime(2026, 10, 9))
        r = tp.parse(text)
        self.assertIsNotNone(r, text)
        self.assertEqual(r[0], expected, text)

    def test_formats(self):
        E = dt.datetime(2026, 10, 9, 14, 23, 45)
        self.check("2026-10-09T14:23:45.000+05:30 x", E)
        self.check("2026-10-09 14:23:45,000 ERROR x", E)
        self.check("10-09-2026 14:23:45.000 +0000 ERROR TcpOutputFd", E)          # splunkd
        self.check("10/9/2026 2:23:45 PM Error", E)                               # Windows
        self.check('1.2.3.4 - - [09/Oct/2026:14:23:45 +0530] "GET / HTTP/1.1" 200', E)  # Apache
        self.check("09-Oct-2026 14:23:45.000 SEVERE [main]", E)                   # Tomcat
        self.check("Oct 09, 2026 2:23:45 PM org.x", E)                            # Java
        self.check("[Fri Oct 09 14:23:45.000 2026] [core:error]", E)              # Apache error
        self.check("Oct  9 14:23:45 web01 kernel: x", E)                          # syslog
        self.check("09/10/2026 14:23:45 x", E, dayfirst=True)

    def test_user_time(self):
        self.assertEqual(A.parse_user_time("2026-10-09 14:30")[0], dt.datetime(2026, 10, 9, 14, 30))
        self.assertEqual(A.parse_user_time("Oct 9 2026 2:30 PM")[0], dt.datetime(2026, 10, 9, 14, 30))
        self.assertIsNone(A.parse_user_time("tomorrow-ish"))

    def test_timezone_conversion(self):
        tp = A.TimeParser(ref=dt.datetime(2026, 10, 9), target_offset=330)
        self.assertEqual(tp.parse("2026-10-09T08:53:45Z x")[0], dt.datetime(2026, 10, 9, 14, 23, 45))


class Signatures(unittest.TestCase):
    def test_keyword_gate_matches_full_regex(self):
        """The fast keyword pre-check must never hide a regex match."""
        lines = []
        for root, _, names in os.walk(SAMPLES):
            for f in names:
                with open(os.path.join(root, f), errors="replace") as fh:
                    lines.extend(fh.read().splitlines()[:5000])
        for l in lines:
            fast = {s.key for s in A.match_signatures(l)}
            slow = {s.key for s in A.SIGS if s.rx.search(l)}
            self.assertEqual(fast, slow, l[:120])

    def test_known_lines(self):
        cases = {
            "java.lang.OutOfMemoryError: Java heap space": "java_oom",
            "kernel: Out of memory: Killed process 4321 (java)": "os_oom_kill",
            "write failed: No space left on device": "disk_full",
            "Communications link failure": "db_conn",
            "javax.net.ssl.SSLHandshakeException: PKIX path building failed": "tls_fail",
            "x509: certificate has expired or is not yet valid": "cert_expired",
            "upstream timed out (110: Connection timed out) while reading response header": "bad_gateway",
            "Failed password for invalid user admin from 1.2.3.4": "auth_fail",
            "group=queue, name=indexqueue, blocked=true": "splunk_queue",
            "EventCode=6008 The previous system shutdown was unexpected": "unexpected_shutdown",
            # Splunk's own logs
            "Received fatal signal 6 (Aborted) on PID 4242.": "splunk_crash",
            " Last errno: 12": "native_oom",
            "WARN  TailReader - Could not send data to output queue (parsingQueue), retrying...": "splunk_queue",
            'INFO  PeriodicHealthReporter - feature="Ingestion Latency" color=red': "splunk_health",
            "WARN  CMMaster - event=handleReplicationError peer=idx02 status=Down": "splunk_cluster",
            "WARN  DiskMon - MinFreeSpace=5000. The diskspace remaining=4812 is less than that threshold.": "splunk_disk",
        }
        for line, key in cases.items():
            self.assertIn(key, {s.key for s in A.match_signatures(line)}, line)

    def test_no_false_matches(self):
        self.assertEqual(A.match_signatures('INFO  PeriodicHealthReporter - feature="X" color=green'), [])
        keys = {s.key for s in A.match_signatures("TcpInputProc - Queues blocked for more than 300 seconds")}
        self.assertNotIn("hung_task", keys)          # Splunk queue message is not a frozen kernel task

    def test_secrets_masked(self):
        self.assertNotIn("S3cret", A.clean_text("db password=S3cret user=x", False))
        self.assertNotIn("abc.def.ghi", A.clean_text("Authorization: Bearer abc.def.ghijkl", False))
        self.assertIn("[email]", A.clean_text("user=dr.smith@clinic.org", True))


class FileHandling(unittest.TestCase):
    def test_crash_log_is_text_not_json(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "crash-2026-10-09-14-05-12.log")
        with open(p, "w") as fh:
            fh.write("[build abc] 2026-10-09 14:05:12\nReceived fatal signal 6 (Aborted) on PID 1.\n")
        self.assertEqual(A.sniff_format(p), "raw")
        with open(p, "w") as fh:
            fh.write('{"a": 1}\n{"a": 2}\n')
        self.assertEqual(A.sniff_format(p), "json")

    def test_rotated_files(self):
        self.assertEqual(A.log_base_name("splunkd.log.3"), "splunkd.log")
        self.assertEqual(A.log_base_name("access.log.2026-10-08.gz"), "access.log")
        order = sorted(["x/splunkd.log", "x/splunkd.log.1", "x/splunkd.log.2"], key=A.rotation_key)
        self.assertEqual(order, ["x/splunkd.log.2", "x/splunkd.log.1", "x/splunkd.log"])

    def test_host_in_message_is_not_the_logging_server(self):
        line = "10-09-2026 14:00:00.000 +0000 WARN  TcpOutputFd - Connection to host=10.0.2.5:9997 failed"
        self.assertIsNone(A.guess_host(line, (0, 29)))
        self.assertEqual(A.guess_host("Oct  9 14:00:00 web01 kernel: x", (0, 15)), "web01")


class Scenarios(unittest.TestCase):
    def test_a_java_oom_crash(self):
        R = run(["app.log", "syslog.log"], "2026-10-09 14:30", "server crashed")
        self.assertEqual(R["verdict"]["confidence"], "High")
        self.assertIn(R["findings"][0]["key"], ("java_oom", "os_oom_kill"))
        self.assertTrue(any(s["kind"] == "gap" and s["dur"] > 200 for s in R["silences"]))
        self.assertTrue(any(f["status"] == "NORMAL" for f in R["noise"]))   # statsd errors = background

    def test_b_flood_then_oom_then_502(self):
        R = run(["splunk_export.csv"], "2026-10-09 10:25", "website down, users getting errors")
        keys = [f["key"] for f in R["findings"]]
        self.assertEqual(keys[0], "java_oom")
        self.assertIn("traffic_flood", keys)
        self.assertIn("triggered", R["verdict"]["headline"])
        self.assertEqual(R["traffic"]["top_ips"][0][0], "203.0.113.77")

    def test_c_splunk_disk(self):
        R = run(["splunk_export.json"], "2026-10-09 18:10", "splunk not receiving data")
        self.assertEqual(R["findings"][0]["key"], "splunk_disk")

    def test_d_splunk_internal_logs_folder(self):
        folder = os.path.join(SAMPLES, "splunk_home", "var", "log", "splunk")
        files, _ = A.expand_paths([os.path.join(SAMPLES, "splunk_home")])      # recursive, skips splunkd.pid
        self.assertFalse(any(f.endswith(".pid") for f in files))
        inc, _ = A.parse_user_time("2026-10-09 14:10")
        an = A.Analyzer(inc, "splunk went down, searches not working")
        for f in files:
            an.feed(f)
        R = an.report()
        self.assertEqual(R["findings"][0]["key"], "splunk_crash")
        self.assertEqual(R["verdict"]["confidence"], "High")
        by_name = {f["name"]: f for f in R["files"]}
        self.assertGreater(by_name["mongod.log"]["events"], 0)                    # KV store JSON format read
        self.assertEqual(by_name["crash-2026-10-09-14-05-12.log"]["format"], "raw")
        hosts = {h["host"] for h in R["hosts"]}
        self.assertNotIn("10.0.2.5", hosts)                                      # host= inside a message
        self.assertNotIn("web01", hosts)
        self.assertNotIn("splunkd.log.1", hosts)                                 # rotated = same source
        groups = A.Analyzer.silence_groups(R["silences"])
        self.assertTrue(any(len(g) >= 4 for g in groups))                        # everything went quiet together
        self.assertTrue(os.path.isdir(folder))

    def test_wrong_time_is_inconclusive(self):
        R = run(["app.log"], "2026-10-01 09:00", "server crashed")
        self.assertEqual(R["verdict"]["confidence"], "Inconclusive")
        self.assertIn("cover", R["verdict"]["headline"])

    def test_cli_writes_html(self):
        out = os.path.join(SAMPLES, "r.html")
        with redirect_stdout(io.StringIO()):
            rc = A.main(["-f", os.path.join(SAMPLES, "app.log"), "-t", "2026-10-09 14:30",
                         "-r", "server crashed", "-o", out, "--no-color"])
        self.assertEqual(rc, 0)
        with open(out, encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("Most likely cause", html)
        self.assertNotIn("http://", html.replace("http://www.w3.org/2000/svg", ""))  # nothing external


if __name__ == "__main__":
    unittest.main()
