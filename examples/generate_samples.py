"""Generate three realistic incident scenarios for trying splunk_log_analyzer.py.

Usage:  python examples/generate_samples.py [output_dir]   (default: examples/samples)

  A) app.log + syslog.log      Java app runs out of memory and is killed (14:22), restarts 14:26
  B) splunk_export.csv         Bot traffic flood (10:12) -> app02 out of memory -> nginx 502s
  C) splunk_export.json        Splunk indexer disk low (17:58) -> indexing paused, queues blocked
"""
import csv, datetime as dt, json, os, random, sys

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
os.makedirs(out, exist_ok=True)
random.seed(7)
D = dt.datetime(2026, 10, 9)

# ---------------- Scenario A: Java app OOM crash (raw app.log + syslog) ----------------
app, sysl = [], []
t = D.replace(hour=13, minute=0)
end = D.replace(hour=14, minute=50)
crash, restart = D.replace(hour=14, minute=22, second=6), D.replace(hour=14, minute=26, second=30)
while t < end:
    t += dt.timedelta(seconds=random.uniform(1, 3))
    if crash < t < restart:
        continue
    ts = t.strftime("%Y-%m-%d %H:%M:%S,") + "%03d" % random.randint(0, 999)
    r = random.random()
    if r < 0.85:
        app.append(f"{ts} INFO  [http-nio-8080-exec-{random.randint(1,40)}] c.e.api.PatientController - GET /api/v2/encounters/{random.randint(1000,99999)} completed in {random.randint(20,180)}ms user=dr.smith{random.randint(1,9)}@clinic.org")
    elif r < 0.95:
        app.append(f"{ts} WARN  [http-nio-8080-exec-{random.randint(1,40)}] c.e.api.ReportService - Slow request /api/v2/reports took {random.randint(1500,3000)}ms")
    else:
        app.append(f"{ts} INFO  [scheduler-1] c.e.jobs.SyncJob - Sync batch {random.randint(1,999)} done")
    if t.second % 50 == 0 and t.minute % 5 == 0:
        app.append(f"{ts} ERROR [metrics-1] c.e.metrics.StatsdClient - Failed to send metrics to statsd 10.0.0.9:8125: Connection refused")
    # deployment at 14:05
    if D.replace(hour=14, minute=5) <= t < D.replace(hour=14, minute=5, second=3):
        app.append(f"{ts} INFO  [main] c.e.deploy.Hooks - Deployment of release 4.2.1 completed (build 8812) password=Sup3rS3cret")
    # GC thrash from 14:12
    if D.replace(hour=14, minute=12) <= t < crash and random.random() < 0.08:
        app.append(f"{ts} WARN  [gc-monitor] c.e.jvm.GcWatcher - [Full GC (Allocation Failure) 3980M->3975M(4096M), 4.21 secs] heap at 97%")
    if D.replace(hour=14, minute=21, second=58) <= t < crash:
        app.append(f"{ts} ERROR [http-nio-8080-exec-{random.randint(1,40)}] c.e.api.ReportService - Request failed for /api/v2/reports/export")
        app.append("java.lang.OutOfMemoryError: Java heap space")
        app.append("\tat java.util.Arrays.copyOf(Arrays.java:3537)")
        app.append("\tat com.ecw.report.PdfExporter.render(PdfExporter.java:211)")
        app.append("\tat com.ecw.api.ReportService.export(ReportService.java:88)")
        app.append("\t... 42 more")
    if restart <= t < restart + dt.timedelta(seconds=3):
        app.append(f"{ts} INFO  [main] o.a.catalina.startup.Catalina - Server startup in 15234 ms")

for i, (tt, host, msg) in enumerate([
    (D.replace(hour=13, minute=10), "web01", "systemd[1]: Started Session 412 of user ops."),
    (D.replace(hour=13, minute=40), "web01", "CRON[2211]: (root) CMD (/usr/local/bin/backup.sh)"),
    (D.replace(hour=14, minute=22, second=6), "web01", "kernel: [884512.1201] java invoked oom-killer: gfp_mask=0x100cca, order=0, oom_score_adj=0"),
    (D.replace(hour=14, minute=22, second=6), "web01", "kernel: [884512.1305] Out of memory: Killed process 4321 (java) total-vm:9123456kB, anon-rss:4120332kB"),
    (D.replace(hour=14, minute=22, second=7), "web01", "systemd[1]: tomcat.service: Main process exited, code=killed, status=9/KILL"),
    (D.replace(hour=14, minute=22, second=7), "web01", "systemd[1]: tomcat.service: Failed with result 'signal'."),
    (D.replace(hour=14, minute=26, second=12), "web01", "systemd[1]: Starting Apache Tomcat Web Application Container..."),
    (D.replace(hour=14, minute=26, second=30), "web01", "systemd[1]: Started Apache Tomcat Web Application Container."),
]):
    sysl.append(tt.strftime("%b %e %H:%M:%S") + f" {host} {msg}")
open(os.path.join(out, "app.log"), "w").write("\n".join(app) + "\n")
open(os.path.join(out, "syslog.log"), "w").write("\n".join(sysl) + "\n")

# ---------------- Scenario B: Splunk CSV export, nginx 502 + flood ----------------
rows = []
t = D.replace(hour=9, minute=0)
end = D.replace(hour=10, minute=50)
flood_start, up_down, up_back = D.replace(hour=10, minute=12), D.replace(hour=10, minute=18), D.replace(hour=10, minute=31)
normal_ips = ["198.51.100.%d" % i for i in range(1, 60)]
while t < end:
    flood = flood_start <= t < up_back
    t += dt.timedelta(seconds=random.uniform(0.2, 0.6) if not flood else random.uniform(0.01, 0.03))
    ip = "203.0.113.77" if flood and random.random() < 0.8 else random.choice(normal_ips)
    path = random.choice(["/login", "/api/v2/schedule", "/api/v2/patients/%d" % random.randint(1, 9999), "/static/app.js"])
    status = 200
    if up_down <= t < up_back:
        status = 502 if random.random() < 0.85 else 200
    elif random.random() < 0.003:
        status = 500
    raw = '%s - - [%s] "GET %s HTTP/1.1" %d %d "-" "Mozilla/5.0"' % (ip, t.strftime("%d/%b/%Y:%H:%M:%S +0530"), path, status, random.randint(200, 9000))
    rows.append([t.strftime("%Y-%m-%dT%H:%M:%S.000+05:30"), raw, "lb01", "/var/log/nginx/access.log", "nginx:access"])
    if status == 502 and random.random() < 0.05:
        err = '%s [error] 1122#1122: *8812 connect() failed (111: Connection refused) while connecting to upstream, client: %s, upstream: "http://10.0.1.21:8080/api"' % (t.strftime("%Y/%m/%d %H:%M:%S"), ip)
        rows.append([t.strftime("%Y-%m-%dT%H:%M:%S.000+05:30"), err, "lb01", "/var/log/nginx/error.log", "nginx:error"])
rows.append([D.replace(hour=10, minute=17, second=55).strftime("%Y-%m-%dT%H:%M:%S.000+05:30"),
             "2026-10-09 10:17:55,100 ERROR [main] app - java.lang.OutOfMemoryError: unable to create new native thread", "app02", "/opt/app/app.log", "app"])
rows.sort(key=lambda r: r[0], reverse=True)  # Splunk exports newest first
with open(os.path.join(out, "splunk_export.csv"), "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["_time", "_raw", "host", "source", "sourcetype"])
    w.writerows(rows)

# ---------------- Scenario C: Splunk JSON export, splunkd forwarding issue ----------------
lines = []
t = D.replace(hour=17, minute=0)
end = D.replace(hour=18, minute=40)
while t < end:
    t += dt.timedelta(seconds=random.uniform(2, 6))
    ts = t.strftime("%m-%d-%Y %H:%M:%S.") + "%03d +0000" % random.randint(0, 999)
    raw = ts + " INFO  Metrics - group=queue, name=parsingqueue, current_size_kb=%d, largest_size=12" % random.randint(0, 50)
    if D.replace(hour=17, minute=58) <= t:
        raw = ts + " INFO  Metrics - group=queue, name=indexqueue, blocked=true, max_size_kb=500, current_size_kb=499"
        if random.random() < 0.3:
            lines.append({"preview": False, "result": {"_time": t.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"), "host": "idx01",
                          "_raw": ts + " WARN  DiskMon - MinFreeSpace=5000. The diskspace remaining=4812 is less than that threshold. Pausing indexing."}})
    if D.replace(hour=18, minute=1) <= t and random.random() < 0.2:
        lines.append({"preview": False, "result": {"_time": t.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"), "host": "uf-web01",
                      "_raw": ts + " WARN  TcpOutputProc - The TCP output processor has paused the data flow. Forwarding to host_dest=10.0.2.5 inside output group default-autolb-group from host_src=uf-web01 has been blocked for blocked_seconds=120."}})
    if random.random() < 0.02:
        lines.append({"preview": False, "result": {"_time": t.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"), "host": "idx01",
                      "_raw": ts + " ERROR ExecProcessor - message from \"python3 /opt/splunk/etc/apps/x/bin/poll.py\" ConnectionError: timeout"}})
    lines.append({"preview": False, "result": {"_time": t.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"), "host": "idx01", "_raw": raw}})
with open(os.path.join(out, "splunk_export.json"), "w") as fh:
    for l in lines:
        fh.write(json.dumps(l) + "\n")
print("ok", len(app), len(rows), len(lines))
