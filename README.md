# Splunk_Logs_Analyzer

This is Splunk logs analysing script to help with analysing logs given by the user from splunk server to find out what went wrong based on the event logs.

**Offline, single-file incident analyzer for Splunk exports and server logs.**
Give it a log file, the time the problem happened, and what went wrong in plain words.
It tells you — in simple terms — what most likely caused it, and proves it with the exact
log lines (line/row numbers) behind every claim.

- **One file, zero dependencies** — Python 3.6+ standard library only. No `pip install`.
- **Never touches the network** — safe for PHI/PII and air-gapped environments.
- **Evidence-first** — every conclusion links to real log lines, plus an honest *Data gaps* section.
- **Two outputs** — a readable terminal summary and a self-contained HTML report (light/dark, mobile-friendly).

```text
VERDICT  [HIGH confidence]
Most likely cause: Application ran out of memory (Java) in app.log. First seen at 14:21:58
(8m 02s before the reported time); 5 time(s) in the window - new - not seen in the 60 min before.
It was preceded by: Java was struggling to free memory (GC thrashing) at 14:12:15, which likely triggered it.
  - Backed up by a logging silence on app.log (4m 26s with no logs).
  - Backed up by a restart at 14:26:12.
```

See [`examples/sample_report.html`](examples/sample_report.html) for a full report.

---

## Quick start

```bash
# Interactive: it asks for the file, the time and what went wrong
python splunk_log_analyzer.py

# One-liner
python splunk_log_analyzer.py -f export.csv -t "2026-10-09 14:30" -r "server went down"

# Several files, look further back, open the report when done
python splunk_log_analyzer.py -f app.log syslog.gz -t "today 2:30 PM" -r "site very slow" --before 60 --open
```

On Windows you can also double-click the script and answer the three questions; drag-and-drop the log file into the window for its path.

### Try it on the bundled examples

```bash
python examples/generate_samples.py        # also creates the large CSV scenario
python splunk_log_analyzer.py -f examples/samples/app.log examples/samples/syslog.log -t "2026-10-09 14:30" -r "server crashed"
python splunk_log_analyzer.py -f examples/samples/splunk_export.csv  -t "2026-10-09 10:25" -r "website down, users getting errors"
python splunk_log_analyzer.py -f examples/samples/splunk_export.json -t "2026-10-09 18:10" -r "splunk not receiving data"
```

| Scenario | What the tool concludes |
|---|---|
| A — `app.log` + `syslog.log` | Deployment → GC thrashing → Java out of memory → OS OOM-killer → 4.5 min log silence → restart |
| B — Splunk CSV (72k rows) | Bot flood from one IP (75% of traffic) → app02 out of memory → nginx 502s → 54% of user requests failed |
| C — Splunk JSON | Indexer disk below `minFreeSpace` → indexing paused → queues blocked (symptom) |

---

## How it decides

1. **Window** — looks at the period around your time (default 30 min before, 15 after).
2. **Baseline** — compares it with the hour before the window, so errors that *always* happen are labelled **background noise**, not blamed.
3. **Known patterns** — ~50 plain-English failure signatures: out of memory, OOM-killer, disk full, segfault/crash, unexpected reboot, kernel panic, DB connection/lock/space, deadlocks, DNS, connection refused/timeouts, 502/503/health checks, TLS/cert expiry, LDAP/Kerberos/SSO, config/class-loading errors, deployments/changes, IIS app pools, Windows Event IDs, Splunk queues/forwarders/disk/license/KV store, WAF/attack traffic.
4. **Silences** — a host that stops writing logs (longer than its normal quiet spells) was usually down, frozen or restarting. Shows the last lines before and first lines after.
5. **Restarts & stops** — startup/boot markers; a clean shutdown with no crash before it is flagged as a *deliberate stop* (deploy, admin, patching, autoscaling).
6. **Web traffic** — request surges, floods from a few IPs (possible bot/DoS), 5xx onset, traffic drops.
7. **Unknown errors** — anything new or spiking that matches no pattern is still grouped and shown.
8. **Ranking** — `severity × relevance to your complaint × timing (before vs after) × novelty (new vs normal) × cause-vs-symptom`. Symptoms (502s, timeouts, refused connections) rank below the causes that produce them, and an earlier strong cause is called out as the likely *trigger*.

Confidence is **High / Medium / Low / Inconclusive**, with the reasons listed.

## Supported input

| Source | Notes |
|---|---|
| Splunk CSV export | Uses `_time`, `_raw`, `host`, `source`, `sourcetype`, level fields |
| Splunk JSON / JSON-lines export | `{"result": {...}}` rows, REST `{"results": [...]}`, generic JSON app logs |
| Raw text | Java/Tomcat, Python, .NET, nginx/Apache/IIS, syslog/journal, splunkd.log, Windows event text |
| Encodings | UTF-8, UTF-8 BOM, UTF-16 (Windows exports), `.gz` |
| Multi-line | Stack traces are attached to their parent event |
| Several files / folder / wildcard | `-f app.log db.log`, `-f logs/`, `-f "logs/*.log"` |

Timestamp formats recognised include ISO-8601 (with offsets), `MM-DD-YYYY HH:MM:SS.mmm +0000` (splunkd), `M/D/YYYY h:mm:ss AM` (Windows), Apache `[09/Oct/2026:14:23:45 +0530]`, Tomcat `09-Oct-2026 14:23:45`, Java `Oct 09, 2026 2:23:45 PM`, ctime, syslog (`Oct  9 14:23:45`), and epoch seconds/ms in `_time`.

## Options

| Option | Default | Meaning |
|---|---|---|
| `-f, --file` | — | Log file(s), folder or wildcard |
| `-t, --time` | — | When it happened: `"2026-10-09 14:30"`, `"10/09/2026 2:30 PM"`, `"today 14:30"`, `"yesterday 23:10"` |
| `-r, --reason` | — | What went wrong, in your words (`"server crashed"`, `"site slow"`, `"logins failing"`) |
| `--before` / `--after` | 30 / 15 | Minutes analysed before / after the time |
| `--baseline` | 60 | Minutes of "normal" data compared |
| `--gap` | 60 | Minimum seconds of no logs to call a silence |
| `--tz` | — | Timezone of the time you typed (`+05:30`, `UTC`, `IST`, `local`); logs with offsets are converted |
| `--dayfirst` | off | Read `09/10/2026` as 9 Oct |
| `-o, --out` | auto | HTML report path |
| `--no-html` | off | Terminal output only |
| `--json PATH` | — | Also save all findings as JSON (for tickets/automation) |
| `--redact` | off | Mask emails, phone/SSN-like numbers, long numeric IDs in evidence |
| `--max-evidence` | 3 | Evidence lines per finding |
| `--open` | off | Open the HTML report in your browser |

Passwords, tokens, API keys and `Bearer` credentials in evidence lines are **always** masked.

## Exporting from Splunk

Run a search covering **at least 1–2 hours before** the incident (so the tool can learn what "normal" looks like) through a bit after it, then **Export → CSV, JSON or Raw**. Include every relevant `index`/`host`/`sourcetype` — app, web/LB, OS and DB logs together give the best answer.

Tips:
- If your Splunk timezone differs from the time you type, add `--tz`.
- A CSV with exactly 10,000 / 50,000 rows probably hit an export cap — the report warns about it.

## Limits (read the *Data gaps* section of every report)

- It can only see what is in the files. If the real cause lives in another tier (DB, load balancer, network, hypervisor), the report says the trail points elsewhere and suggests what to export.
- Pattern matching is heuristic. Treat the verdict as a well-evidenced lead, and confirm with the linked lines.
- Throughput is roughly 10k events/second for the analysed window (events outside it are only time-parsed).

## Tests

```bash
python -m unittest discover -s tests -v
```

Covers timestamp formats, timezone conversion, the fast keyword gate (must never hide a regex match), secret masking, the three scenarios, and the CLI.
