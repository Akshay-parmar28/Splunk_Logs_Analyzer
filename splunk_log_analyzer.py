#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Splunk Log Analyzer - offline "what went wrong?" helper
========================================================
One file. Python 3.6+. Standard library only. Never touches the network.

Give it:  a log file  +  when the problem happened  +  what the problem was.
It explains in plain English what most likely went wrong and shows the exact
log lines (with line/row numbers) that prove it.

HOW IT DECIDES
  1. Looks at the window around your time (default 30 min before, 15 after).
  2. Compares it with the hour before that window ("normal behaviour"),
     so errors that ALWAYS happen are labelled noise, not blamed.
  3. Matches ~50 known failure patterns (out of memory, disk full, crash,
     DB down, cert expired, 502/503, DNS, Splunk queues blocked, ...).
  4. Detects log silences (server stopped writing logs = down/frozen),
     restarts, deliberate shutdowns, deployments/changes, traffic floods.
  5. Ranks causes by severity x relevance to your complaint x timing
     (before vs after your time) x novelty (new vs normal).

WORKS WITH
  * Splunk exports: CSV (_raw/_time columns), JSON / JSON-lines, raw text
  * Plain logs: Java/Tomcat, Python, .NET, nginx/Apache/IIS, Linux syslog,
    Windows event exports, splunkd.log, JSON app logs
  * .gz files, UTF-8/UTF-16, multi-line stack traces, several files at once

QUICK START
  python splunk_log_analyzer.py                        (asks you questions)
  python splunk_log_analyzer.py -f export.csv -t "2026-10-09 14:30" -r "server went down"
  python splunk_log_analyzer.py -f app.log syslog.gz -t "today 2:30 PM" -r "site very slow" --open

TIME FORMATS FOR -t
  "2026-10-09 14:30"   "10/09/2026 2:30 PM"   "09-Oct-2026 14:30"
  "Oct 9 2026 14:30"   "today 14:30"          "yesterday 23:10"
  Add --dayfirst if you write dates as DD/MM/YYYY.

PRIVACY
  Everything runs locally. Passwords/tokens/API keys in evidence lines are
  always masked. Add --redact to also mask emails, phone/SSN-like numbers
  and long digit IDs (useful for healthcare/PII logs).
"""

import argparse
import array
import collections
import csv
import datetime as dt
import glob
import gzip
import html
import io
import json
import math
import os
import re
import shutil
import statistics
import sys
import textwrap
import time
import webbrowser

VERSION = "1.0.0"
EPOCH0 = dt.datetime(1970, 1, 1)
TWO_MIN = dt.timedelta(minutes=2)


def _secs(d):
    return (d - EPOCH0).total_seconds()


def _from_secs(s):
    return EPOCH0 + dt.timedelta(seconds=s)


# ============================================================================
# 1. TIMESTAMP PARSING
# ============================================================================
_MONTHS = {}
for _i, _n in enumerate(("january", "february", "march", "april", "may", "june", "july",
                         "august", "september", "october", "november", "december"), 1):
    _MONTHS[_n] = _i
    _MONTHS[_n[:3]] = _i
_MONTHS["sept"] = 9

_HMS = r"(?P<h>\d{1,2}):(?P<mi>\d{2}):(?P<s>\d{2})"
_FRAC = r"(?:[.,](?P<f>\d{1,9}))?"
_AMPM = r"(?:\s?(?P<ampm>[AaPp]\.?[Mm]\.?)(?![A-Za-z]))?"
_TZ = r"(?:\s?(?P<tz>Z|UTC|GMT|[+-]\d{2}:?\d{2})(?![\d:]))?"

TS_REGEXES = [
    # 2026-10-09T14:23:45.123+05:30 | 2026/10/09 14:23:45,123
    re.compile(r"(?<!\d)(?P<Y>(?:19|20)\d{2})[-/.](?P<M>\d{1,2})[-/.](?P<D>\d{1,2})(?:T|\s+)"
               + _HMS + _FRAC + _AMPM + _TZ),
    # 10-09-2026 14:23:45.123 +0000 (splunkd) | 10/9/2026 2:23:45 PM (Windows)
    re.compile(r"(?<!\d)(?P<A>\d{1,2})[-/.](?P<B>\d{1,2})[-/.](?P<Y>(?:19|20)\d{2})(?:T|\s+|:)"
               + _HMS + _FRAC + _AMPM + _TZ),
    # 09/Oct/2026:14:23:45 +0530 (Apache) | 09-Oct-2026 14:23:45.123 (Tomcat)
    re.compile(r"(?<!\d)(?P<D>\d{1,2})[-/ ](?P<Mon>[A-Za-z]{3,9})\.?[-/ ,]+(?P<Y>(?:19|20)\d{2})(?:T|\s+|:)"
               + _HMS + _FRAC + _AMPM + _TZ),
    # Oct 09, 2026 2:23:45 PM (Java) | October 9 2026 14:23:45
    re.compile(r"\b(?P<Mon>[A-Za-z]{3,9})\.?\s+(?P<D>\d{1,2})(?:st|nd|rd|th)?,?\s+(?P<Y>(?:19|20)\d{2}),?\s+"
               + _HMS + _FRAC + _AMPM + _TZ),
    # Fri Oct  9 14:23:45 2026 (ctime / Apache error log)
    re.compile(r"\b(?P<Mon>[A-Za-z]{3,9})\s+(?P<D>\d{1,2})\s+" + _HMS + _FRAC
               + r"(?:\s+[A-Z]{2,5})?\s+(?P<Y>(?:19|20)\d{2})\b"),
    # Oct  9 14:23:45 (syslog, no year)
    re.compile(r"\b(?P<Mon>[A-Za-z]{3,9})\s+(?P<D>\d{1,2})\s+" + _HMS + _FRAC),
]
_HHMM = re.compile(r"\d:\d\d")
_EPOCH = re.compile(r"^\d{9,13}(?:\.\d+)?$")


class TimeParser(object):
    """Finds and parses a timestamp near the start of a line."""

    def __init__(self, dayfirst=False, ref=None, target_offset=None):
        self.dayfirst = dayfirst
        self.ref = ref or dt.datetime.now()
        self.target = target_offset          # minutes east of UTC, or None
        self.last = 0                        # index of the last pattern that worked
        self.offsets = collections.Counter()
        self.yearless = 0

    def _build(self, m):
        g = m.groupdict()
        try:
            if g.get("Mon"):
                mon = _MONTHS.get(g["Mon"].lower().rstrip("."))
                if not mon:
                    return None
                day = int(g["D"])
            elif g.get("A") is not None:
                a, b = int(g["A"]), int(g["B"])
                if a > 12:
                    day, mon = a, b
                elif b > 12:
                    mon, day = a, b
                elif self.dayfirst:
                    day, mon = a, b
                else:
                    mon, day = a, b
            else:
                mon, day = int(g["M"]), int(g["D"])
            yearless = g.get("Y") is None
            year = self.ref.year if yearless else int(g["Y"])
            hh, mi, ss = int(g["h"]), int(g["mi"]), int(g["s"])
            ampm = g.get("ampm")
            if ampm and hh <= 12:
                if hh == 12:
                    hh = 0
                if ampm[0] in "Pp":
                    hh += 12
            frac = g.get("f")
            us = int((frac + "000000")[:6]) if frac else 0
            d = dt.datetime(year, mon, day, hh, mi, ss, us)
        except (ValueError, TypeError):
            return None
        off = None
        tz = g.get("tz")
        if tz:
            if tz in ("Z", "UTC", "GMT"):
                off = 0
            else:
                sign = -1 if tz[0] == "-" else 1
                digits = tz[1:].replace(":", "")
                off = sign * (int(digits[:2]) * 60 + int(digits[2:4]))
        return d, off, yearless

    def parse_raw(self, text, scan=120):
        head = text[:scan]
        if not _HHMM.search(head):
            return None
        m = TS_REGEXES[self.last].search(head)
        if m is not None and m.start() <= 30:
            r = self._build(m)
            if r is not None:
                return r + (m.span(),)
        cands = []
        for i, rx in enumerate(TS_REGEXES):
            mm = rx.search(head)
            if mm is not None:
                cands.append((mm.start(), i, mm))
        cands.sort(key=lambda c: (c[0], c[1]))
        for _, i, mm in cands:
            r = self._build(mm)
            if r is not None:
                self.last = i
                return r + (mm.span(),)
        return None

    def _convert(self, d, off, yearless):
        if yearless:
            self.yearless += 1
            if d - self.ref > dt.timedelta(days=60):
                try:
                    d = d.replace(year=d.year - 1)
                except ValueError:
                    pass
        if off is not None:
            self.offsets[off] += 1
            if self.target is not None:
                d = d - dt.timedelta(minutes=off - self.target)
        return d

    def parse(self, text, scan=120):
        r = self.parse_raw(text, scan)
        if r is None:
            return None
        d, off, yearless, span = r
        return self._convert(d, off, yearless), span

    def parse_field(self, s):
        """Parse a dedicated time field (Splunk _time): ISO text or epoch seconds."""
        s = s.strip()
        if not s:
            return None
        if _EPOCH.match(s):
            v = float(s)
            if v > 1e11:
                v /= 1000.0
            return self._convert(EPOCH0 + dt.timedelta(seconds=v), 0, False)
        r = self.parse(s, scan=len(s) + 1)
        return r[0] if r else None


_TZ_NAMES = {"UTC": 0, "GMT": 0, "Z": 0, "IST": 330, "EST": -300, "EDT": -240, "CST": -360,
             "CDT": -300, "MST": -420, "MDT": -360, "PST": -480, "PDT": -420, "CET": 60,
             "CEST": 120, "BST": 60, "SGT": 480, "JST": 540, "AEST": 600, "GST": 240}


def parse_tz(s):
    if s is None:
        return None
    s = s.strip().upper()
    if s == "LOCAL":
        return int(round(-(time.altzone if time.localtime().tm_isdst > 0 else time.timezone) / 60.0))
    if s in _TZ_NAMES:
        return _TZ_NAMES[s]
    m = re.match(r"^(?:UTC|GMT)?\s*([+-])(\d{1,2}):?(\d{2})?$", s)
    if not m:
        raise ValueError("Unrecognised timezone '%s' (use e.g. +05:30, -0400, UTC, IST, local)" % s)
    mins = int(m.group(2)) * 60 + int(m.group(3) or 0)
    return mins if m.group(1) == "+" else -mins


def parse_user_time(s, dayfirst=False):
    """Returns (datetime, offset_minutes_or_None) or None."""
    if not s:
        return None
    s = s.strip()
    low = s.lower()
    today = dt.date.today()
    for word, delta in (("today", 0), ("yesterday", 1)):
        if low.startswith(word):
            s = (today - dt.timedelta(days=delta)).strftime("%Y-%m-%d") + " " + s[len(word):].strip()
            break
    s2 = re.sub(r"(?<![\d:])(\d{1,2}:\d{2})(?!:\d)", r"\1:00", s)
    p = TimeParser(dayfirst=dayfirst, ref=dt.datetime.now())
    r = p.parse_raw(s2, scan=len(s2) + 1)
    if r is None:
        return None
    return r[0], r[1]


# ============================================================================
# 2. KNOWLEDGE BASE - known failure patterns, in plain English
# ============================================================================
# (key, category, severity, title, regex, what it means, what to check next)
SIGNATURE_TABLE = [
    # ---------------- memory ----------------
    ("java_oom", "memory", "critical", "Application ran out of memory (Java)",
     r"OutOfMemoryError",
     "The Java application used up all the memory it is allowed. Requests start failing and the process usually freezes or dies soon after.",
     "Compare the heap limit (-Xmx) with real usage, capture a heap dump to see what filled memory, and check for a traffic jump or recent code change."),
    ("gc_thrash", "memory", "high", "Java was struggling to free memory (GC thrashing)",
     r"GC overhead limit exceeded|Full GC \((Allocation Failure|Ergonomics)\)|Pause Full|to-space exhausted|concurrent mode failure",
     "Memory was almost full, so Java kept pausing to clean it up. The app becomes very slow and often runs out of memory next.",
     "Check the heap usage trend before the incident; look for a memory leak or an unusually large request, report or batch job."),
    ("os_oom_kill", "memory", "critical", "Operating system killed a process - server ran out of memory",
     r"Out of memory: Kill(ed)? process|invoked oom-killer|oom-kill:|oom_reaper|Memory cgroup out of memory|OOMKilled",
     "The server (or container) ran out of RAM, so the operating system force-killed a process to survive. That process stopped instantly.",
     "Find which process was killed (see evidence), check its memory limit, and what else was using RAM at that time."),
    ("native_oom", "memory", "critical", "Program could not get more memory",
     r"System\.OutOfMemoryException|Cannot allocate memory|std::bad_alloc|\bMemoryError\b|\bENOMEM\b|failed to allocate|Insufficient (system )?memory|unable to allocate",
     "A program asked the system for memory and was refused. It usually crashes or fails the operation.",
     "Check free RAM / swap and memory limits for the process or container at that time."),
    ("win_low_mem", "memory", "high", "Windows reported low memory",
     r"Resource-Exhaustion-Detector|low virtual memory condition|EventCode=2004\b",
     "Windows detected that the machine was running out of memory and named the processes using the most.",
     "See which processes Windows listed as top memory users and whether one keeps growing."),
    # ---------------- disk ----------------
    ("disk_full", "disk", "critical", "Disk is full",
     r"No space left on device|\bENOSPC\b|not enough space on the disk|insufficient disk space|Disk quota exceeded|disk (is )?full|file ?system (is )?full|database or disk is full",
     "A disk ran out of free space. Applications cannot write files, logs or database data, which commonly makes them fail or hang.",
     "Check drive space (df -h), find what filled it (logs, temp files, dumps), free space, and add log rotation / disk alerts."),
    ("disk_io", "disk", "high", "Disk or file-system error",
     r"I/O error|Buffer I/O error|EXT4-fs error|XFS .{0,40}(error|corrupt)|blk_update_request|Read-only file system|remount(ing)? .{0,30}read-only|bad sector|EventCode=(7|51|153)\b",
     "The server had trouble reading or writing to a disk. It may have switched the disk to read-only, which breaks applications.",
     "Check storage/SAN health, kernel messages around this time, and whether the volume is now read-only."),
    # ---------------- resources ----------------
    ("too_many_files", "resource", "high", "Too many open files / connections",
     r"Too many open files|\bEMFILE\b|\bENFILE\b",
     "The process hit its limit of open files/sockets, so it could not accept new connections or open files.",
     "Check the service's open-file limit (ulimit -n) and look for connection or file-handle leaks."),
    ("threads_exhausted", "resource", "high", "Worker threads ran out (app could not take more requests)",
     r"unable to create (a )?new native thread|Thread ?pool .{0,40}(exhausted|full|starv)|RejectedExecutionException|maxThreads|all threads .{0,20}busy|thread starvation|server reached MaxRequestWorkers|worker_connections are not enough",
     "Every worker thread was busy, so new requests had to wait or were rejected. Users see slowness or timeouts.",
     "Find what the busy threads were waiting on (slow DB, slow downstream API) - a thread dump helps - before just raising the limit."),
    ("high_cpu", "resource", "medium", "High CPU usage reported",
     r"high cpu|cpu (usage|utili[sz]ation|load) .{0,20}\b(9\d|100)(\.\d+)?\s?%|processor time .{0,20}\b(9\d|100)",
     "The CPU was close to fully used, which makes everything on that server slow.",
     "Identify which process used the CPU at that time and what workload triggered it."),
    ("queue_backlog", "resource", "medium", "Queue/buffer full - work piling up",
     r"queue (is )?(full|blocked)|queue capacity|buffer (is )?full|backpressure|back-pressure|messages? (dropped|discarded)|dropping (events|messages)",
     "Work was arriving faster than it could be processed, so queues filled up and new work was delayed or dropped.",
     "Find the slow consumer/downstream system and check for a burst of incoming work."),
    # ---------------- OS / kernel ----------------
    ("hung_task", "kernel", "high", "Operating system reported a frozen task",
     r"blocked for more than \d+ seconds|hung_task|soft lockup|hard LOCKUP|rcu_sched .{0,30}stall|rcu_preempt .{0,30}stall",
     "Something on the server was stuck for a long time (often waiting on disk or a busy CPU). The server can appear frozen.",
     "Check disk/storage latency and CPU at that time; check the VM host / hypervisor health."),
    ("unexpected_shutdown", "kernel", "critical", "Server shut down or rebooted unexpectedly",
     r"EventCode=(6008|41)\b|previous system shutdown .{0,60}was unexpected|Kernel-Power|rebooted without cleanly shutting down|unexpected (shutdown|reboot|restart)|power (loss|failure)|watchdog .{0,30}(reset|reboot)",
     "The whole server went down without a clean shutdown - e.g. power loss, hard crash, or a forced reset from the virtualization host.",
     "Check hypervisor/cloud console events, power/hardware logs and any crash dump for that time."),
    ("kernel_panic", "kernel", "critical", "Operating system crashed (kernel panic / bugcheck)",
     r"Kernel panic|BUG: unable to handle|Oops: |general protection fault|Machine Check|\bMCE\b|watchdog: BUG|BugCheck|bugcheck|blue ?screen",
     "The operating system itself crashed, which takes down everything running on the server.",
     "Check recent kernel/driver updates, hardware health and the crash dump."),
    # ---------------- process crashes ----------------
    ("segfault", "process", "critical", "Program crashed (segmentation fault / core dump)",
     r"segfault|Segmentation fault|\bSIGSEGV\b|core dumped|signal 11\b|\bSIGABRT\b|\bSIGBUS\b",
     "A program crashed because of a low-level bug or corrupted memory and was terminated immediately.",
     "Find the crashing program/library in the evidence, check for a recent update, and keep the core dump for the vendor."),
    ("java_fatal", "process", "critical", "Java virtual machine crashed",
     r"A fatal error has been detected by the Java Runtime|hs_err_pid|StackOverflowError|Internal Error \(",
     "The Java runtime itself crashed (or hit runaway recursion) and the application stopped.",
     "Look for the hs_err_pid*.log file on the server; check JVM version and native libraries."),
    ("process_exit", "process", "critical", "Service/process stopped unexpectedly",
     r"Main process exited|exited with (exit )?(status|code) [1-9]|code=(exited|killed|dumped), status=|terminated unexpectedly|stopped unexpectedly|died unexpectedly|unexpectedly (terminated|exited|closed)|has exited unexpectedly|process .{0,40}\b(crashed|died)\b|exit code [1-9]|exit status [1-9]|Failed with result '(signal|core-dump|exit-code|oom-kill|watchdog)'",
     "The service's process ended when it was not supposed to. Until it is restarted, the service is down.",
     "Read the log lines just before the process stopped (see evidence) for the reason; check the service's own log for its last messages."),
    ("killed", "process", "high", "Process was force-killed",
     r"\bSIGKILL\b|killed by signal|signal 9\b|\bkill -9\b|status=9/KILL",
     "A process was killed forcefully (no clean shutdown). Common causes: the out-of-memory killer, a watchdog, or someone killing it.",
     "Check for out-of-memory messages near this time and for admin/automation that kills processes."),
    ("service_failed", "process", "high", "Service failed to start",
     r"Failed to start |Start request repeated too quickly|start operation timed out|could not be started",
     "The service tried to start but failed, so it stayed down.",
     "Read the error just before this line - usually a config error, a port already in use, or a missing dependency."),
    ("app_crash_win", "process", "critical", "Windows application/service crashed",
     r"Faulting application|Application Error|EventCode=(1000|1026|1002)\b|\.NET Runtime .{0,40}(fatal|terminated|unhandled)|Application Hang|EventCode=703[14]\b",
     "Windows recorded that an application or service crashed or hung.",
     "Note the faulting module named in the evidence; check Windows Event Viewer (Application/System) for the same time."),
    ("iis_pool", "process", "high", "IIS application pool stopped or recycled",
     r"application pool .{0,60}(disabled|shut ?down|failures|being automatically disabled)|Rapid-?Fail Protection|worker process .{0,60}(failed|terminated|crashed|unexpectedly)|EventCode=(5002|5009|5010|5011|5013|5117)\b",
     "The IIS worker process for the site crashed, was recycled or was disabled, so the website returned errors (often HTTP 503).",
     "Check the application pool state and why its worker process failed (Application event log)."),
    # ---------------- lifecycle ----------------
    ("stop", "lifecycle", "medium", "Service/server was told to stop (shutdown signal)",
     r"\b(Stopping|Stopped)\b .{0,60}\b(service|server|application|daemon|instance|unit|tomcat|jvm|nginx|httpd|apache|w3svc|splunkd|container)|shutting down|shutdown (initiated|requested|in progress|hook|command)|Received signal (15|SIGTERM|TERM)|\bSIGTERM\b|Stopping ProtocolHandler|Destroying ProtocolHandler|graceful(ly)? (stop|shut)|Server shutdown|is stopping|has initiated the (restart|power off)|system is going down|EventCode=(1074|6006)\b|The Event log service was stopped|reboot: (Restarting|Power down)",
     "A shutdown or stop was requested (a clean stop, not a crash). The service is unavailable until it starts again.",
     "Find who or what sent the stop: a deployment, an admin, patching/auto-reboot, auto-scaling, or a health-check restart."),
    ("start", "lifecycle", "info", "Service/server started",
     r"\b(Starting|Started)\b .{0,60}\b(service|server|application|daemon|instance|unit|tomcat|jvm|nginx|httpd|apache|w3svc|splunkd|container)|Server startup in|startup complete|Application started|Started \S+ in [\d.]+ seconds|ready to accept connections|Listening on (port|https?|\d)|Server started|Splunkd starting|Tomcat started",
     "", ""),
    ("boot", "lifecycle", "info", "Server booted",
     r"Linux version \d|Booting Linux|Command line: BOOT_IMAGE|Startup finished in|EventCode=(6005|6009)\b|The Event log service was started",
     "", ""),
    # ---------------- network ----------------
    ("conn_refused", "network", "high", "Connection refused (the target service was not running/listening)",
     r"Connection refused|\bECONNREFUSED\b|actively refused|No connection could be made|connect\(\) failed \(111",
     "Something tried to connect to another service and was refused immediately - that service was down, restarting, or not listening on that port.",
     "Identify the target host:port in the evidence and check whether that service was up at that time."),
    ("timeout", "network", "high", "Timeouts talking to another system",
     r"(connect|connection|read|write|socket|gateway|upstream|request|response|operation) ?(timed out|timeout)|\bETIMEDOUT\b|SocketTimeoutException|ConnectTimeoutException|timed out (while|waiting|after)|context deadline exceeded|TimeoutException",
     "Requests to another system (database, API, storage) took too long and were abandoned. Usually that system was overloaded, down, or the network was slow.",
     "Find which system it was waiting on (host/URL in the evidence) and check that system's health at that time."),
    ("conn_reset", "network", "medium", "Connections dropped mid-way",
     r"Connection reset|\bECONNRESET\b|Broken pipe|\bEPIPE\b|forcibly closed|Connection aborted|connection (was )?(unexpectedly )?closed|prematurely closed",
     "Open connections were cut off unexpectedly - the other side crashed/restarted, or a firewall/load balancer dropped them.",
     "Check whether the other side restarted at that moment, and idle-timeout settings on firewalls/load balancers."),
    ("dns", "network", "high", "Name lookup (DNS) failed",
     r"UnknownHostException|Name or service not known|Temporary failure in name resolution|getaddrinfo .{0,20}fail|\bNXDOMAIN\b|could not resolve|No such host|\bENOTFOUND\b|DNS .{0,30}(fail|timeout|error)|EAI_AGAIN",
     "The server could not turn a hostname into an IP address, so it could not reach that system at all.",
     "Check DNS server availability and whether the hostname in the evidence still exists."),
    ("net_unreachable", "network", "high", "Network path or host unreachable",
     r"No route to host|Network is unreachable|\bEHOSTUNREACH\b|\bENETUNREACH\b|Host is down|NIC Link is Down|link is down|carrier lost",
     "There was no network path to the other machine - a network outage, an interface down, or that host was off.",
     "Check network/switch/firewall changes and network interface status at that time."),
    ("port_in_use", "network", "high", "Port already in use (service could not start listening)",
     r"Address already in use|\bEADDRINUSE\b|bind\(\) .{0,40}failed|Only one usage of each socket address|port .{0,30}(already in use|already bound)",
     "A service tried to start but its network port was still taken (often by an old copy that did not stop), so it could not start.",
     "Check what process holds the port (netstat / ss -ltnp) and stop stale processes before restarting."),
    # ---------------- web / http ----------------
    ("bad_gateway", "http", "high", "Proxy/load balancer could not reach the application (502/504)",
     r"502 Bad Gateway|504 Gateway Time-?out|upstream (timed out|prematurely closed|connect error|sent invalid)|no live upstreams|connect\(\) failed .{0,60}upstream|proxy error|AH0111[0-9]|AH01102",
     "The front door (nginx/Apache/load balancer) was up, but the application behind it did not answer. Users saw 'bad gateway' or timeout errors.",
     "Check the application servers behind the proxy (the upstream named in the evidence) - they were down, overloaded or restarting."),
    ("unavailable_503", "http", "high", "Service reported unavailable / failed health checks",
     r"503 Service (Temporarily )?Unavailable|HTTP Error 503|health ?check .{0,40}(fail|unhealthy|timed out)|marked (as )?(down|unhealthy)|no healthy (hosts|upstream|backend|targets)|backend .{0,30}\b(down|unhealthy)\b|Service Unavailable",
     "The service (or the load balancer in front of it) declared itself unavailable - usually because the app was down, overloaded or failing health checks.",
     "Check why the health check failed - the app's own errors just before this time usually explain it."),
    ("rate_limited", "http", "medium", "Requests were rate-limited",
     r"429 Too Many Requests|rate.?limit(ed|ing| exceeded)|throttl(ed|ing)",
     "Too many requests arrived and some were rejected on purpose to protect the system.",
     "Check whether a client or bot sent a burst of traffic, or whether limits are too low."),
    # ---------------- database ----------------
    ("db_conn", "db", "critical", "Application could not connect to the database",
     r"(Cannot|Could not|Unable to|Failed to) (get|obtain|acquire|open|create|establish) (a |the )?(JDBC|database|DB|SQL|pooled) connection|Connection pool .{0,40}(exhausted|timeout|full)|HikariPool.{0,40}(timeout|not available|timed out)|Timeout waiting for (idle object|connection)|Too many connections|max_connections|remaining connection slots|ORA-(12519|12520|12541|12170|03113|03114|12514|12537)|Communications link failure|CommunicationsException|The connection is broken|Login timeout expired|network-related or instance-specific error|could not connect to server|MySQL server has gone away|Lost connection to MySQL",
     "The application could not get a working database connection (database down, too busy, or the connection pool was used up). Most pages that need data fail.",
     "Check that the database was up and reachable, its connection count vs. limit, and whether slow queries were holding connections."),
    ("db_lock", "db", "high", "Database locking problem (deadlock / lock wait)",
     r"deadlock|Lock wait timeout|ORA-00060|lock request time ?out|could not obtain lock|lock timeout",
     "Database transactions were blocking each other, so queries waited or were cancelled.",
     "Find the blocking queries/sessions in the DB at that time; check for a long-running job or batch."),
    ("db_slow", "db", "medium", "Slow or timed-out database queries",
     r"slow query|Query_time: [1-9]\d|statement timeout|canceling statement due to statement timeout|ORA-01013|Execution Timeout Expired|QueryTimeoutException",
     "Database queries took too long. Pages depending on them become slow or time out.",
     "Look at the slow queries in the evidence, DB load at that time, missing indexes, or a heavy batch job."),
    ("db_space", "db", "critical", "Database ran out of space",
     r"ORA-0165[0-9]|ORA-01688|ORA-01652|ORA-01536|tablespace .{0,40}full|transaction log for database .{0,60}is full|could not extend|PRIMARY filegroup is full",
     "The database could not store more data because its storage/tablespace/log was full. Writes fail.",
     "Free or extend the tablespace/log/disk; check log backups and retention jobs."),
    ("db_error", "db", "medium", "Database errors",
     r"\bORA-\d{5}\b|SQLException|\bSQLSTATE\b|PSQLException|SqlException|PG::\w+(Error|Bad)|OperationalError|DataAccessException",
     "Database calls returned errors.",
     "Read the exact database error code/message in the evidence."),
    # ---------------- auth ----------------
    ("auth_fail", "auth", "medium", "Failed logins / authentication errors",
     r"(authentication|login|logon|sign-?in) (failure|failed|error)|Failed password|invalid (user|username|password|credentials)|Access denied for user|EventCode=4625\b|401 Unauthorized|Bad credentials|BadCredentialsException|account (is |has been )?locked|EventCode=4740\b",
     "Logins were rejected - wrong password, locked account, or a broken login/identity service. A very large number can also mean a password-guessing attack.",
     "Check whether it is many users (identity service problem) or many attempts on few accounts/IPs (possible attack)."),
    ("permission", "auth", "medium", "Permission denied",
     r"Permission denied|\bEACCES\b|Access is denied|AccessDeniedException|403 Forbidden|not authori[sz]ed to",
     "Something was not allowed to read/write/execute what it needed - often after a permission, account or certificate change.",
     "Check what resource was denied (in the evidence) and any recent permission or service-account change."),
    ("directory_auth", "auth", "high", "Directory / Kerberos / SSO problem",
     r"LDAP.{0,40}(error|fail|timeout|unavailable|refused)|Kerberos.{0,40}(error|fail)|\bKDC\b|krb5|domain controller .{0,40}(unavailable|could not)|trust relationship .{0,80}failed|SAML.{0,40}(fail|invalid|error)|OIDC.{0,40}(fail|error)|invalid_grant",
     "The login/identity system (Active Directory, LDAP, Kerberos, SSO) was failing, so users or services could not authenticate.",
     "Check the identity provider / domain controllers at that time, clock sync, and expiring secrets."),
    # ---------------- TLS ----------------
    ("cert_expired", "tls", "critical", "Certificate expired or not yet valid",
     r"certificate (has )?expired|CertificateExpiredException|certificate is not yet valid|certificate .{0,40}expired",
     "A security certificate passed its expiry date, so secure (HTTPS/TLS) connections are refused.",
     "Find which certificate (host/name in the evidence) and renew it; add expiry monitoring."),
    ("tls_fail", "tls", "high", "Secure connection (SSL/TLS) failed",
     r"SSLHandshakeException|handshake (failure|failed)|SSL handshake|PKIX path building failed|unable to find valid certification path|certificate verify failed|self[- ]signed certificate|SSL routines|\bx509:|TLS .{0,30}(alert|error|fail)|SSLException|no cipher suites in common",
     "Two systems could not agree on a secure connection - certificate not trusted or mismatched, or TLS version/cipher not supported.",
     "Check certificate chains/trust stores and any recent TLS configuration change on either side."),
    # ---------------- config / change / code ----------------
    ("config_error", "config", "high", "Configuration / startup error",
     r"(configuration|config) (error|is invalid|invalid|failed|missing)|Invalid configuration|Unable to load (config|configuration|properties)|missing (required )?(property|parameter|setting|environment variable)|ConfigurationException|BeanCreationException|UnsatisfiedDependencyException|ApplicationContextException|ClassNotFoundException|NoClassDefFoundError|NoSuchMethodError|Could not find or load main class|ModuleNotFoundError|ImportError|Cannot find module|FileNotFoundException|No such file or directory",
     "The application could not start or run correctly because a setting, file or component it needs was missing or wrong. This often follows a deployment or config change.",
     "Compare configuration/files with the last working version; check what changed in the latest deployment."),
    ("change", "change", "medium", "A change was made (deployment / config / update)",
     r"\bdeploy(ed|ing|ment)\b|\brollout\b|\brelease\b .{0,20}\b(v?\d+\.\d+|deployed|started|complete)|\bupgrad(e|ed|ing)\b|\bhot ?fix\b|patch(ed|ing) |config(uration)? (changed|reload(ed)?|updated)|reloading (config|configuration)|\bSIGHUP\b|package .{0,40}(installed|updated|upgraded)|Installed: |Updated: |EventCode=(11707|11724|1033|19|43)\b|Windows Update|new version",
     "Something changed on the system shortly before the problem. Changes (deployments, config edits, patches) are the most common trigger of incidents.",
     "Review exactly what changed at that time and consider rolling it back if the timing lines up."),
    ("unhandled", "app", "high", "Unhandled error crashed a request or the app",
     r"Unhandled exception|uncaught exception|UnhandledPromiseRejection|Traceback \(most recent call last\)|\bpanic: |fatal error:|FATAL EXCEPTION|Unhandled rejection",
     "The code hit an error it was not written to handle. Depending on where, one request fails or the whole app stops.",
     "Read the error type and the first lines of the stack trace in the evidence - they point to the failing code."),
    ("null_ref", "app", "medium", "Code bug: missing value (null reference)",
     r"NullPointerException|NullReferenceException|Object reference not set to an instance|Cannot read propert(y|ies) of (undefined|null)|'NoneType' object has no attribute",
     "The code tried to use a value that did not exist - a software bug, often triggered by unexpected data or an empty response from a dependency.",
     "Check the stack trace for the failing code and whether a downstream system returned empty data at that time."),
    ("circuit_open", "app", "medium", "Circuit breaker opened (calls to a dependency were cut off)",
     r"circuit ?breaker .{0,40}(open|tripped)|CircuitBreaker .{0,40}OPEN|short-circuited|Hystrix .{0,40}open",
     "The app stopped calling a failing dependency to protect itself. Features relying on that dependency stop working.",
     "Find the dependency named in the evidence - its failures are the real problem."),
    # ---------------- Splunk platform ----------------
    ("splunk_queue", "splunk", "high", "Splunk processing queues blocked",
     r"blocked=true|(parsingQueue|aggQueue|typingQueue|indexQueue|tcpin_queue|splunktcpin)\b.{0,60}(blocked|full)|TcpOutputProc .{0,80}(blocked|paused)|Forwarding to (indexer|output) group .{0,60}(blocked|paused)",
     "Splunk could not push data through its pipeline fast enough, so queues filled up. Indexing slows or stops and forwarders back up.",
     "Check indexer disk speed/space and CPU, and whether one indexer is down so the others are overloaded."),
    ("splunk_fwd", "splunk", "high", "Splunk forwarder could not send data to indexers",
     r"TcpOutputFd .{0,80}(refused|failed|error|timed out)|Cooked connection to ip=.{0,60}timed out|Applying quarantine to ip|Read operation timed out expecting ACK|Connect to .{0,40}:9997 failed|Unable to (connect|send) to .{0,30}indexer",
     "The Splunk forwarder could not deliver logs to the indexer, so data is delayed or missing in Splunk.",
     "Check the indexer is up and its receiving port (usually 9997) is reachable from the forwarder; check SSL settings on both sides."),
    ("splunk_disk", "splunk", "high", "Splunk paused indexing because disk space is low",
     r"minFreeSpace|DiskMon|disk ?space .{0,40}(below|less than) .{0,30}(minimum|threshold)|IndexWriter .{0,40}paused|[Ii]ndexing has been paused",
     "Splunk stopped writing new data because free disk space dropped below its safety limit.",
     "Free disk on the indexer volume, or adjust retention / minFreeSpace."),
    ("splunk_search", "splunk", "medium", "Splunk searches skipped or failed",
     r"status=skipped|maximum number of concurrent .{0,40}searches .{0,40}reached|scheduled search .{0,60}skipped|DispatchManager .{0,60}(fail|quota|limit)",
     "Scheduled searches/alerts did not run (too many at once, or failures), so dashboards or alerts may be missing data.",
     "Check search concurrency limits and heavy/overlapping scheduled searches."),
    ("splunk_license", "splunk", "medium", "Splunk license warning/violation",
     r"[Ll]icense (warning|violation)|licenser .{0,40}(exceeded|violation|over quota)|daily indexing volume limit",
     "Splunk indexed more data than the license allows. Repeated violations can block searching.",
     "Find the source that sent unusual volume that day."),
    ("splunk_service", "splunk", "high", "Splunk service problem (splunkd / KV store)",
     r"splunkd .{0,30}(crash|exited|terminated|not responding|stopped)|crash-\d{4}-\d{2}-\d{2}|KV ?Store .{0,40}(fail|error|not ready|unavailable)|mongod .{0,40}(exit|fail|terminated)|HTTPServer .{0,40}(failed|Error binding)",
     "A core Splunk component crashed or was not working.",
     "Check splunkd.log and crash-*.log in $SPLUNK_HOME/var/log/splunk for the same time."),
    # ---------------- security ----------------
    ("waf_attack", "security", "medium", "Attack traffic / WAF blocks",
     r"ModSecurity|WAF .{0,40}(block|deny|alert)|Access denied with code 403|blocked by (the )?(WAF|web application firewall|firewall)|attack detected|SQL injection|XSS attack|cross[- ]site scripting|path traversal|DDoS|denial of service",
     "Security controls saw or blocked malicious-looking traffic. A large burst can overload the site or indicate an attack in progress.",
     "Check the source IPs and targeted URLs; confirm blocks are working and consider rate-limiting or blocking the sources."),
]

# Cheap lowercase keywords: a pattern's regex only runs if one of these appears in the
# line. Keeps the scan fast on millions of lines. Every regex branch is covered by one.
SIG_KEYWORDS = {
    "java_oom": ("outofmemoryerror",),
    "gc_thrash": ("gc overhead", "full gc", "pause full", "to-space exhausted", "concurrent mode failure"),
    "os_oom_kill": ("out of memory", "oom-kill", "oom_reaper", "memory cgroup", "oomkilled"),
    "native_oom": ("outofmemoryexception", "cannot allocate memory", "bad_alloc", "memoryerror", "enomem",
                   "failed to allocate", "insufficient", "unable to allocate"),
    "win_low_mem": ("resource-exhaustion", "low virtual memory", "eventcode=2004"),
    "disk_full": ("no space left", "enospc", "not enough space", "insufficient disk", "quota exceeded", "full"),
    "disk_io": ("i/o error", "ext4-fs error", "xfs", "blk_update_request", "read-only", "bad sector", "eventcode="),
    "too_many_files": ("too many open files", "emfile", "enfile"),
    "threads_exhausted": ("thread", "rejectedexecution", "maxrequestworkers", "worker_connections"),
    "high_cpu": ("cpu", "processor time"),
    "queue_backlog": ("queue", "buffer", "backpressure", "back-pressure", "dropped", "discarded", "dropping"),
    "hung_task": ("blocked for more than", "hung_task", "lockup", "stall"),
    "unexpected_shutdown": ("eventcode=", "unexpected", "kernel-power", "without cleanly", "power loss",
                            "power failure", "watchdog"),
    "kernel_panic": ("kernel panic", "bug:", "oops:", "general protection", "machine check", "mce", "watchdog",
                     "bugcheck", "blue screen", "bluescreen"),
    "segfault": ("segfault", "segmentation fault", "sigsegv", "core dumped", "signal 11", "sigabrt", "sigbus"),
    "java_fatal": ("fatal error has been detected", "hs_err_pid", "stackoverflowerror", "internal error ("),
    "process_exit": ("main process exited", "exited with", "code=", "unexpectedly", "crashed", "died",
                     "exit code", "exit status", "failed with result"),
    "killed": ("sigkill", "killed by signal", "signal 9", "kill -9", "9/kill"),
    "service_failed": ("failed to start", "entered failed state", "start request repeated", "start operation timed out",
                       "could not be started"),
    "app_crash_win": ("faulting application", "application error", "eventcode=", ".net runtime", "application hang"),
    "iis_pool": ("application pool", "rapid-fail", "rapidfail", "worker process", "eventcode="),
    "stop": ("stopping", "stopped", "shutting down", "shutdown", "signal", "sigterm", "protocolhandler", "graceful",
             "is stopping", "has initiated the", "going down", "eventcode=", "event log service", "reboot:"),
    "start": ("starting", "started", "server startup", "startup complete", "ready to accept", "listening on"),
    "boot": ("linux version", "booting linux", "boot_image", "startup finished", "eventcode=", "event log service"),
    "conn_refused": ("refused", "no connection could be made"),
    "timeout": ("timed out", "timeout", "etimedout", "deadline exceeded"),
    "conn_reset": ("connection reset", "econnreset", "broken pipe", "epipe", "forcibly closed", "connection aborted",
                   "closed"),
    "dns": ("unknownhost", "name or service not known", "name resolution", "getaddrinfo", "nxdomain",
            "could not resolve", "no such host", "enotfound", "dns", "eai_again"),
    "net_unreachable": ("no route to host", "unreach", "host is down", "link is down", "carrier lost"),
    "port_in_use": ("address already in use", "eaddrinuse", "bind()", "only one usage of each socket",
                    "already in use", "already bound"),
    "bad_gateway": ("502 bad gateway", "504 gateway", "upstream", "proxy error", "ah011"),
    "unavailable_503": ("503 service", "error 503", "health", "marked", "no healthy", "unhealthy", "service unavailable",
                        "backend"),
    "rate_limited": ("429 too many", "rate", "throttl"),
    "db_conn": ("connection", "hikaripool", "ora-", "communications link failure", "communicationsexception",
                "login timeout expired", "network-related", "could not connect to server", "gone away",
                "timeout waiting for"),
    "db_lock": ("deadlock", "lock wait", "ora-00060", "lock request time", "obtain lock", "lock timeout"),
    "db_slow": ("slow query", "query_time", "statement timeout", "ora-01013", "execution timeout", "querytimeout"),
    "db_space": ("ora-01", "tablespace", "transaction log", "could not extend", "filegroup is full"),
    "db_error": ("ora-", "sqlexception", "sqlstate", "psqlexception", "pg::", "operationalerror",
                 "dataaccessexception"),
    "auth_fail": ("authentication", "login", "logon", "sign-in", "signin", "failed password", "invalid",
                  "access denied for user", "eventcode=", "401 unauthorized", "bad credentials", "badcredentials", "locked"),
    "permission": ("permission denied", "eacces", "access is denied", "accessdenied", "403 forbidden", "not authori"),
    "directory_auth": ("ldap", "kerberos", "kdc", "krb5", "domain controller", "trust relationship", "saml",
                       "oidc", "invalid_grant"),
    "cert_expired": ("certificate",),
    "tls_fail": ("ssl", "handshake", "pkix", "certification path", "certificate verify", "self signed",
                 "self-signed", "x509:", "tls", "cipher"),
    "config_error": ("config", "missing", "exception", "classnotfound", "noclassdeffound", "nosuchmethod",
                     "main class", "modulenotfound", "importerror", "cannot find module", "filenotfound",
                     "no such file", "unable to load"),
    "change": ("deploy", "rollout", "release", "upgrad", "hot fix", "hotfix", "patch", "config", "reload",
               "sighup", "package", "installed: ", "updated: ", "eventcode=", "windows update", "new version"),
    "unhandled": ("unhandled", "uncaught", "traceback", "panic: ", "fatal error:", "fatal exception"),
    "null_ref": ("nullpointer", "nullreference", "object reference not set", "cannot read propert", "nonetype"),
    "circuit_open": ("circuit", "short-circuited", "hystrix"),
    "splunk_queue": ("blocked", "queue", "splunktcpin", "tcpoutputproc", "forwarding to"),
    "splunk_fwd": ("tcpoutputfd", "cooked connection", "quarantine", "expecting ack", ":9997", "indexer"),
    "splunk_disk": ("minfreespace", "diskmon", "disk space", "diskspace", "indexwriter", "indexing has been paused"),
    "splunk_search": ("status=skipped", "concurrent", "scheduled search", "dispatchmanager"),
    "splunk_license": ("license", "licenser", "daily indexing volume"),
    "splunk_service": ("splunkd", "crash-", "kv store", "kvstore", "mongod", "httpserver"),
    "waf_attack": ("modsecurity", "waf", "access denied with code 403", "blocked by", "attack", "sql injection",
                   "xss", "cross-site", "cross site", "path traversal", "ddos", "denial of service"),
}

# These describe what users/other systems FELT rather than WHY - ranked lower than causes.
SYMPTOMS = {"bad_gateway", "unavailable_503", "rate_limited", "conn_refused", "timeout",
            "conn_reset", "circuit_open", "queue_backlog", "http_5xx", "traffic_drop", "splunk_queue"}
SEV_WEIGHT = {"critical": 5, "high": 3, "medium": 2, "low": 1, "info": 0}
NOVELTY = {"NEW": 1.6, "SPIKE": 1.25, "UNKNOWN": 1.0, "ELEVATED": 0.8, "NORMAL": 0.3}
STATUS_ORDER = {"NEW": 0, "SPIKE": 1, "UNKNOWN": 2, "ELEVATED": 3, "NORMAL": 4}


class Sig(object):
    __slots__ = ("key", "cat", "sev", "title", "rx", "meaning", "check", "kw")

    def __init__(self, row):
        self.key, self.cat, self.sev, self.title, pat, self.meaning, self.check = row
        self.rx = re.compile(pat, re.I)
        self.kw = SIG_KEYWORDS[self.key]


SIGS = [Sig(r) for r in SIGNATURE_TABLE]
SIG_BY_KEY = {s.key: s for s in SIGS}


_ALL_KW = tuple(sorted({k for s in SIGS for k in s.kw}))
_KW_TO_SIGS = {}
for _idx, _s in enumerate(SIGS):
    for _k in _s.kw:
        _KW_TO_SIGS.setdefault(_k, set()).add(_idx)


def match_signatures(text):
    """Return the known patterns found in text. Keyword scan runs in C (filter), regex only on hits."""
    low = text.lower()
    hits = list(filter(low.__contains__, _ALL_KW))
    if not hits:
        return []
    idx = set()
    for k in hits:
        idx |= _KW_TO_SIGS[k]
    return [SIGS[i] for i in sorted(idx) if SIGS[i].rx.search(text)]


# Reason (user's words) -> which categories matter, weight 0..4
REASON_RULES = [
    ("crash", r"crash|died|dead|killed|terminat|abort|stopp|restart|reboot|went off|shut ?down|\bcore\b|segfault|exit|blue ?screen|bsod",
     {"process": 4, "memory": 4, "kernel": 4, "lifecycle": 3, "resource": 3, "disk": 2, "app": 2, "change": 2, "config": 2, "db": 1}),
    ("unavailable", r"down|unavailable|unreachable|not (responding|reachable|accessible|loading|working|opening|available)|outage|offline|inaccessible|\b50[0-9]\b|bad gateway|can'?t (access|connect|open|reach|load)|cannot (access|connect|open|reach|load)|unable to (access|connect|open|reach|load)|not able to|no response|error page|site|portal|\bpage\b",
     {"process": 3, "lifecycle": 3, "http": 4, "network": 3, "memory": 2, "db": 3, "disk": 2, "resource": 3, "tls": 2, "kernel": 3, "change": 2, "config": 2, "app": 1, "security": 1, "auth": 1}),
    ("slow", r"slow|latency|\blag|sluggish|hang|hung|freez|stuck|taking (long|time|forever)|delay|time ?out|timed out|cpu|performance|spinning",
     {"resource": 4, "db": 4, "memory": 3, "network": 3, "http": 2, "disk": 2, "kernel": 2, "app": 1, "security": 1}),
    ("memory", r"memory|\boom\b|\bram\b|heap|swap|leak", {"memory": 4, "process": 2, "resource": 2}),
    ("disk", r"disk|storage|space|\bfull\b|inode|volume|partition|drive|read-?only", {"disk": 4, "db": 1, "splunk": 1}),
    ("network", r"network|connect|\bdns\b|packet|firewall|vpn|unreachable|socket|\bport\b|proxy|load ?balancer|\blb\b",
     {"network": 4, "tls": 2, "http": 2, "security": 1}),
    ("auth", r"log ?in|logon|sign ?in|auth|password|credential|locked|access denied|\b401\b|\b403\b|\bsso\b|ldap|active directory|kerberos|permission|forbidden",
     {"auth": 4, "tls": 2, "network": 1, "security": 2, "db": 1}),
    ("database", r"\bdb\b|database|\bsql\b|oracle|mysql|postgres|mongo|query|deadlock|tablespace", {"db": 4, "network": 2, "resource": 1, "disk": 1}),
    ("tls", r"ssl|tls|cert|https|handshake", {"tls": 4, "network": 2, "auth": 1}),
    ("change", r"deploy|release|update|upgrade|patch|change|install|migrat|config", {"change": 4, "config": 4}),
    ("splunk", r"splunk|indexer|indexing|forwarder|ingest|search head|license|not receiving|missing (logs|data|events)|no (logs|data|events)|dashboard",
     {"splunk": 4, "network": 2, "disk": 2, "resource": 1}),
    ("security", r"attack|ddos|\bdos\b|hack|breach|brute|suspicious|malicious|scan|\bbot|flood|injection|exploit|intrusion",
     {"security": 4, "auth": 3, "http": 2, "network": 1}),
    ("errors", r"error|fail|exception|broken|issue|problem|not working", {"app": 2}),
]


def interpret_reason(reason):
    low = (reason or "").lower()
    weights, labels = {}, []
    for label, pat, w in REASON_RULES:
        if re.search(pat, low):
            labels.append(label)
            for k, v in w.items():
                weights[k] = max(weights.get(k, 0), v)
    if not weights:
        return None, []
    return weights, labels


# ============================================================================
# 3. LINE HELPERS (levels, hosts, http, templates, redaction)
# ============================================================================
_LEVEL_RX = re.compile(r"\b(EMERG(?:ENCY)?|ALERT|FATAL|CRIT(?:ICAL)?|SEVERE|ERROR|ERR|WARN(?:ING)?|NOTICE|INFO(?:RMATION(?:AL)?)?|DEBUG|TRACE|VERBOSE)\b")
_APACHE_LEVEL_RX = re.compile(r"\[(?:\w+:)?(emerg|alert|crit|error|warn|notice|info|debug)\]")
_KV_LEVEL_RX = re.compile(r"""\b(?:level|severity|log_level|loglevel|levelname|type|entrytype)["']?\s*[=:]\s*["']?([A-Za-z]+)""", re.I)
_LEVEL_MAP = {"EMERG": "CRITICAL", "EMERGENCY": "CRITICAL", "ALERT": "CRITICAL", "FATAL": "CRITICAL",
              "CRIT": "CRITICAL", "CRITICAL": "CRITICAL", "SEVERE": "CRITICAL", "ERROR": "ERROR", "ERR": "ERROR",
              "WARN": "WARN", "WARNING": "WARN", "NOTICE": "INFO", "INFO": "INFO", "INFORMATION": "INFO",
              "INFORMATIONAL": "INFO", "DEBUG": "DEBUG", "TRACE": "DEBUG", "VERBOSE": "DEBUG"}


def norm_level(v):
    if not v:
        return None
    return _LEVEL_MAP.get(str(v).strip().upper())


def detect_level(line):
    head = line[:250]
    m = _LEVEL_RX.search(head) or _APACHE_LEVEL_RX.search(head)
    if m:
        return _LEVEL_MAP.get(m.group(1).upper())
    m = _KV_LEVEL_RX.search(line[:600])
    if m:
        return _LEVEL_MAP.get(m.group(1).upper())
    return None


_SYSLOG_HOST = re.compile(r"^\s*(?P<host>[A-Za-z0-9][\w.-]{0,62})\s+[\w./-]+(?:\[\d+\])?:\s")
_KV_HOST = re.compile(r"\b(?:ComputerName|hostname|host_name|host)=\"?([A-Za-z0-9][\w.-]{0,62})")


def guess_host(line, span):
    if span is not None and span[0] <= 3:
        m = _SYSLOG_HOST.match(line[span[1]:])
        if m and m.group("host").upper() not in _LEVEL_MAP:
            return m.group("host")
    m = _KV_HOST.search(line)
    if m:
        return m.group(1)
    return None


_HTTP_RX = re.compile(r'"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) (?P<path>\S+)[^"]*" (?P<status>[1-5]\d{2})\b')
_IIS_RX = re.compile(r"\b(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?P<path>/\S*)\s+\S+\s+\d+\s+\S+\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+.*?\s(?P<status>[1-5]\d{2})\s+\d+\s+\d+\s+\d+\s*$")
_KV_STATUS_RX = re.compile(r"\b(?:status|sc_status|sc-status|status_code|http_status|response_code)\s*[=:]\s*\"?(?P<status>[1-5]\d{2})\b", re.I)
_IP_START_RX = re.compile(r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")
_KV_IP_RX = re.compile(r"\b(?:clientip|client_ip|c_ip|c-ip|src_ip|src|remote_addr|client|x_forwarded_for|xff)\s*[=:]\s*\"?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.I)


def parse_http(line):
    """Returns (status, method, path, client_ip) for web/access-log lines, else None."""
    m = _HTTP_RX.search(line)
    if m:
        ipm = _IP_START_RX.match(line) or _KV_IP_RX.search(line)
        return int(m.group("status")), m.group("method"), m.group("path"), ipm.group("ip") if ipm else None
    m = _IIS_RX.search(line)
    if m:
        return int(m.group("status")), m.group("method"), m.group("path"), m.group("ip")
    m = _KV_STATUS_RX.search(line)
    if m:
        ipm = _KV_IP_RX.search(line)
        return int(m.group("status")), None, None, ipm.group("ip") if ipm else None
    return None


_T_SUBS = [
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<id>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<hex>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hex>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "<email>"),
    (re.compile(r"\d+"), "#"),
    (re.compile(r"\s+"), " "),
]


def _mask(s):
    for rx, rep in _T_SUBS:
        s = rx.sub(rep, s)
    return s


def make_template(line, span, http):
    """Turns a log line into a pattern so repeats of the same error group together."""
    if http and http[0] >= 500:
        path = _mask((http[2] or "").split("?")[0])[:80]
        return ("HTTP %d on %s %s" % (http[0], http[1] or "", path)).replace("  ", " ").strip()
    s = (line[:span[0]] + " " + line[span[1]:]) if span else line
    s = _mask(s[:400]).strip(" -|:[],")
    return s[:180] or "(empty line)"


_SECRET_RX = [
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret)(\"?\s*[=:]\s*\"?)([^\s\"&,;]+)"), r"\1\2[hidden]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [hidden]"),
]
_PII_RX = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[email]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[ssn]"),
    (re.compile(r"\(?\b\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"), "[phone]"),
    (re.compile(r"(?<![\d.:#-])\d{9,}(?![\d.])"), "[number]"),
]


def clean_text(s, redact):
    for rx, rep in _SECRET_RX:
        s = rx.sub(rep, s)
    if redact:
        for rx, rep in _PII_RX:
            s = rx.sub(rep, s)
    return s


def evidence_text(text, max_lines=6, max_chars=900):
    lines = text.split("\n")
    out = lines[:max_lines]
    if len(lines) > max_lines:
        caused = [l for l in lines[max_lines:] if "Caused by" in l][:2]
        if caused:
            out += ["\t..."] + caused
        else:
            out.append("\t... (%d more lines)" % (len(lines) - max_lines))
    s = "\n".join(out)
    return s if len(s) <= max_chars else s[:max_chars] + " ..."


# ============================================================================
# 4. READING FILES (raw text, Splunk CSV, Splunk JSON / JSON lines, .gz)
# ============================================================================
def _encoding(path):
    opener = gzip.open if path.lower().endswith(".gz") else open
    with opener(path, "rb") as fh:
        head = fh.read(4)
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return "utf-16"
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def open_text(path, newline=None):
    enc = _encoding(path)
    if path.lower().endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding=enc, errors="replace", newline=newline)
    return open(path, "r", encoding=enc, errors="replace", newline=newline)


def sniff_format(path):
    with open_text(path) as fh:
        for _ in range(50):
            line = fh.readline()
            if not line:
                break
            s = line.strip().lstrip("\ufeff")
            if not s:
                continue
            if s[0] in "[{":
                return "json"
            low = s.lower()
            if ("_raw" in low or "_time" in low) and ("," in s or "\t" in s) and len(s) < 4000:
                return "csv"
            return "raw"
    return "raw"


def _raise_csv_limit():
    lim = sys.maxsize
    while True:
        try:
            csv.field_size_limit(lim)
            return
        except OverflowError:
            lim //= 10


def iter_raw(path):
    with open_text(path) as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\r\n")
            if line.strip():
                yield "line %d" % n, line, None, None, None, None


def iter_csv(path):
    _raise_csv_limit()
    with open_text(path, newline="") as fh:
        first = fh.readline()
        delim = "\t" if first.count("\t") > first.count(",") else ","
        header = [h.strip().lstrip("\ufeff") for h in next(csv.reader([first], delimiter=delim))]
        idx = {h.lower(): i for i, h in enumerate(header)}

        def pick(row, *names):
            for nm in names:
                i = idx.get(nm)
                if i is not None and i < len(row) and row[i] not in ("", None):
                    return row[i]
            return None

        for n, row in enumerate(csv.reader(fh, delimiter=delim), 1):
            if not row:
                continue
            raw = pick(row, "_raw", "message", "msg", "event")
            if raw is None:
                raw = " ".join("%s=%s" % (h, v) for h, v in zip(header, row) if v and not h.startswith("_"))
            yield ("row %d" % n, raw, pick(row, "_time", "timestamp", "time", "@timestamp"),
                   pick(row, "host", "hostname", "computername"),
                   pick(row, "source", "sourcetype"),
                   pick(row, "log_level", "level", "severity", "loglevel"))


_J_TIME = ("_time", "@timestamp", "timestamp", "time", "ts", "datetime", "date", "eventtime", "event_time")
_J_MSG = ("_raw", "message", "msg", "log", "event", "text", "description")
_J_LEVEL = ("log_level", "level", "severity", "loglevel", "levelname", "lvl")
_J_HOST = ("host", "hostname", "computer", "computername", "server")
_J_SRC = ("source", "sourcetype", "logger", "logger_name", "service", "app")


def _json_record(obj):
    if isinstance(obj, dict) and isinstance(obj.get("result"), dict):
        obj = obj["result"]
    elif isinstance(obj, dict) and "preview" in obj and "result" not in obj:
        return None
    if not isinstance(obj, dict):
        return str(obj), None, None, None, None
    low = {str(k).lower(): v for k, v in obj.items()}

    def pick(keys):
        for k in keys:
            v = low.get(k)
            if v in (None, "", []):
                continue
            if isinstance(v, list):
                v = " ".join(str(x) for x in v)
            return v
        return None

    msg = pick(_J_MSG)
    if isinstance(msg, (dict, list)):
        msg = json.dumps(msg, ensure_ascii=False)
    if msg is None:
        msg = json.dumps(obj, ensure_ascii=False)
    t = pick(_J_TIME)
    return (str(msg), str(t) if t is not None else None, pick(_J_HOST), pick(_J_SRC), pick(_J_LEVEL))


def iter_json(path):
    with open_text(path) as fh:
        first = ""
        while not first:
            first = fh.readline()
            if not first:
                return
            first = first.strip().lstrip("\ufeff")
        line_mode = True
        try:
            json.loads(first)
        except ValueError:
            line_mode = False
    if line_mode:
        with open_text(path) as fh:
            for n, line in enumerate(fh, 1):
                s = line.strip()
                if not s:
                    continue
                try:
                    rec = _json_record(json.loads(s))
                except ValueError:
                    rec = (s, None, None, None, None)
                if rec is not None:
                    yield ("line %d" % n,) + rec
        return
    with open_text(path) as fh:
        data = json.load(fh)
    rows = data
    if isinstance(data, dict):
        rows = data.get("results") or data.get("result") or data.get("events") or [data]
        if isinstance(rows, dict):
            rows = [rows]
    for n, obj in enumerate(rows, 1):
        rec = _json_record(obj)
        if rec is not None:
            yield ("record %d" % n,) + rec


def iter_records(path, fmt):
    if fmt == "csv":
        return iter_csv(path)
    if fmt == "json":
        return iter_json(path)
    return iter_raw(path)


_CONT_RX = re.compile(r"^(\s|at |Caused by|\.\.\. \d+ (more|common)|Suppressed:|Traceback|\}|\])")


# ============================================================================
# 5. ANALYSIS ENGINE
# ============================================================================
class Zone(object):
    """Counters for one period (baseline or incident window)."""

    def __init__(self):
        self.events = 0
        self.problems = 0
        self.levels = collections.Counter()
        self.sig = collections.Counter()
        self.tpl = collections.Counter()
        self.http = 0
        self.http5xx = 0
        self.ips = collections.Counter()
        self.status = collections.Counter()
        self.host_events = collections.Counter()
        self.host_problems = collections.Counter()


class Agg(object):
    """Occurrences of one pattern inside the incident window."""
    __slots__ = ("count", "before", "after", "first", "last", "hosts", "ex_first", "ex_last")

    def __init__(self):
        self.count = self.before = self.after = 0
        self.first = self.last = None
        self.hosts = collections.Counter()
        self.ex_first = []
        self.ex_last = None


class HostTrack(object):
    __slots__ = ("times", "ring", "last", "cands", "pending")

    def __init__(self):
        self.times = array.array("d")
        self.ring = collections.deque(maxlen=4)
        self.last = None
        self.cands = []
        self.pending = None


class Analyzer(object):
    def __init__(self, incident, reason, before_min=30, after_min=15, baseline_min=60, gap_seconds=60,
                 dayfirst=False, target_offset=None, redact=False, max_evidence=3):
        self.incident = incident
        self.reason = reason
        self.w_start = incident - dt.timedelta(minutes=before_min)
        self.w_end = incident + dt.timedelta(minutes=after_min)
        self.b_start = self.w_start - dt.timedelta(minutes=baseline_min)
        self.before_min, self.after_min, self.baseline_min = before_min, after_min, baseline_min
        self.gap_seconds = gap_seconds
        self.redact = redact
        self.max_evidence = max_evidence
        self.target_offset = target_offset
        self.tp = TimeParser(dayfirst=dayfirst, ref=incident, target_offset=target_offset)
        self.weights, self.reason_labels = interpret_reason(reason)
        self.files = []
        self.base, self.win = Zone(), Zone()
        self.minutes = {}
        self.sig_agg = {}
        self.tpl_agg = {}
        self.http5xx_agg = Agg()
        self.http5xx_min_ex = {}          # minute -> first 5xx example in that minute
        self.hosts = {}
        self.markers = []
        self.data_min = self.data_max = None
        self.cont_lines = 0
        self.no_ts_lines = 0
        self.total_events = 0
        self.tpl_overflow = 0

    # ---------------------------------------------------------------- input
    def feed(self, path):
        fmt = sniff_format(path)
        info = {"path": path, "name": os.path.basename(path), "format": fmt, "records": 0,
                "events": 0, "no_ts": 0, "first": None, "last": None}
        self.files.append(info)
        pend = None
        for ref, text, tstr, host, source, level in iter_records(path, fmt):
            info["records"] += 1
            if info["records"] % 250000 == 0:
                sys.stderr.write("  ... %s lines read\n" % "{:,}".format(info["records"]))
            if fmt == "raw":
                if pend is not None and _CONT_RX.match(text):
                    self._append(pend, text)
                    continue
                r = self.tp.parse(text)
                if r is None:
                    if pend is not None:
                        self._append(pend, text)
                    else:
                        info["no_ts"] += 1
                    continue
                if pend is not None:
                    self._emit(pend, info)
                pend = [r[0], r[1], ref, text, [text], host, source, level, len(text)]
            else:
                ts, span = None, None
                if tstr:
                    ts = self.tp.parse_field(tstr)
                if ts is None:
                    r = self.tp.parse(text or "")
                    if r:
                        ts, span = r
                if ts is None:
                    info["no_ts"] += 1
                    continue
                first = text.split("\n", 1)[0]
                self._emit([ts, span, ref, first, [text], host, source, level, len(text)], info)
        if pend is not None:
            self._emit(pend, info)
        self.no_ts_lines += info["no_ts"]

    def _append(self, pend, text):
        self.cont_lines += 1
        if len(pend[4]) < 60 and pend[8] < 8000:
            pend[4].append(text)
            pend[8] += len(text)

    def _emit(self, pend, info):
        ts, span, ref, first, lines, host, source, level, _ = pend
        info["events"] += 1
        self.total_events += 1
        if info["first"] is None or ts < info["first"]:
            info["first"] = ts
        if info["last"] is None or ts > info["last"]:
            info["last"] = ts
        if self.data_min is None or ts < self.data_min:
            self.data_min = ts
        if self.data_max is None or ts > self.data_max:
            self.data_max = ts
        if ts < self.b_start or ts > self.w_end:
            return
        full = "\n".join(lines)
        host = host or guess_host(first, span)
        if not host:
            host = os.path.basename(str(source)) if source else info["name"]
        self._consume(ts, span, ref, info["name"], host, first, full, level)

    def _consume(self, ts, span, ref, fname, host, first, full, level_field):
        in_win = ts >= self.w_start
        level = norm_level(level_field) or detect_level(first)
        hits = match_signatures(full[:6000])
        http = parse_http(first)
        causes = [s for s in hits if s.sev != "info" and s.cat != "lifecycle"]
        problem = (level in ("ERROR", "CRITICAL")
                   or any(SEV_WEIGHT[s.sev] >= 2 for s in causes)
                   or (http is not None and http[0] >= 500))
        minute = ts.replace(second=0, microsecond=0)
        b = self.minutes.get(minute)
        if b is None:
            b = self.minutes[minute] = [0, 0, 0, 0]
        b[0] += 1
        if problem:
            b[1] += 1
        if http:
            b[2] += 1
            if http[0] >= 500:
                b[3] += 1
        self._track_host(host, ts, ref, fname, first)

        z = self.win if in_win else self.base
        z.events += 1
        z.host_events[host] += 1
        z.levels[level or "-"] += 1
        if problem:
            z.problems += 1
            z.host_problems[host] += 1
        if http:
            z.http += 1
            z.status[http[0]] += 1
            if http[3]:
                z.ips[http[3]] += 1
            if http[0] >= 500:
                z.http5xx += 1
                if in_win:
                    self._record(self.http5xx_agg, ts, ref, fname, host, full)
                    prev = self.http5xx_min_ex.get(minute)
                    if prev is None or ts < prev[0]:
                        self.http5xx_min_ex[minute] = (ts, ref, fname, host, clean_text(evidence_text(full), self.redact))
        for s in hits:
            z.sig[s.key] += 1
            if in_win:
                agg = self.sig_agg.get(s.key)
                if agg is None:
                    agg = self.sig_agg[s.key] = Agg()
                self._record(agg, ts, ref, fname, host, full)
                if s.cat == "lifecycle" and len(self.markers) < 400:
                    self.markers.append((ts, host, s.key, clean_text(first[:300], self.redact), ref, fname))
        if problem and not causes:
            if span is None and not http:          # CSV/JSON rows: strip the timestamp inside the text too
                r = self.tp.parse_raw(first)
                span = r[3] if r else None
            tpl = make_template(first, span, http)
            if tpl not in z.tpl and len(z.tpl) > 20000:
                self.tpl_overflow += 1
                return
            z.tpl[tpl] += 1
            if in_win:
                agg = self.tpl_agg.get(tpl)
                if agg is None:
                    agg = self.tpl_agg[tpl] = Agg()
                self._record(agg, ts, ref, fname, host, full)

    def _record(self, agg, ts, ref, fname, host, full):
        agg.count += 1
        if ts <= self.incident:
            agg.before += 1
        else:
            agg.after += 1
        agg.hosts[host] += 1
        if agg.first is None or ts < agg.first:
            agg.first = ts
        if agg.last is None or ts >= agg.last:
            agg.last = ts
        need_first = len(agg.ex_first) < 2 or ts < agg.ex_first[-1][0]
        need_last = agg.ex_last is None or ts >= agg.ex_last[0]
        if need_first or need_last:
            ex = (ts, ref, fname, host, clean_text(evidence_text(full), self.redact))
            if need_first:
                agg.ex_first.append(ex)
                agg.ex_first.sort(key=lambda e: e[0])
                del agg.ex_first[2:]
            if need_last:
                agg.ex_last = ex

    def _track_host(self, host, ts, ref, fname, first):
        st = self.hosts.get(host)
        if st is None:
            st = self.hosts[host] = HostTrack()
        t = _secs(ts)
        st.times.append(t)
        item = (ts, ref, fname, first[:300])          # masked later, only if shown
        if st.pending is not None:
            st.pending["after"].append(item)
            if len(st.pending["after"]) >= 3:
                st.pending = None
        if st.last is not None and t - st.last >= self.gap_seconds:
            cand = {"start": st.last, "end": t, "before": list(st.ring), "after": [item]}
            st.cands.append(cand)
            st.pending = cand
        if st.last is None or t > st.last:
            st.last = t
        st.ring.append(item)

    # ---------------------------------------------------------------- analysis
    def _coverage(self):
        if self.data_min is None:
            return 0.0, 0.0
        ws = max(self.w_start, self.data_min)
        we = min(self.w_end, self.data_max)
        win_min = max(1.0, (we - ws).total_seconds() / 60.0) if we > ws else 1.0
        if self.data_min >= self.w_start:
            base_min = 0.0
        else:
            base_min = (self.w_start - max(self.b_start, self.data_min)).total_seconds() / 60.0
        return win_min, base_min

    @staticmethod
    def _status(win_count, base_count, win_min, base_min):
        if base_min < 5:
            return "UNKNOWN", None
        if base_count == 0:
            return "NEW", None
        ratio = (win_count / win_min) / (base_count / base_min)
        if ratio >= 3:
            return "SPIKE", ratio
        if ratio >= 1.5:
            return "ELEVATED", ratio
        return "NORMAL", ratio

    def _rel(self, cat):
        if self.weights is None:
            return 2.0
        return 1.0 + self.weights.get(cat, 0)

    def _evidence(self, agg):
        exs = list(agg.ex_first)
        if agg.ex_last is not None and all(agg.ex_last[1] != e[1] or agg.ex_last[2] != e[2] for e in exs):
            exs.append(agg.ex_last)
        out = []
        for ts, ref, fname, host, text in exs[:self.max_evidence]:
            out.append({"ts": ts, "ref": ref, "file": fname, "host": host, "text": text})
        return out

    def _finding(self, key, title, cat, sev, meaning, check, agg, base_count, win_min, base_min,
                 rel_cat=None, count_label=None):
        st, ratio = self._status(agg.count, base_count, win_min, base_min)
        f = {"key": key, "title": title, "cat": cat, "sev": sev, "meaning": meaning, "check": check,
             "count": agg.count, "before": agg.before, "after": agg.after, "first": agg.first,
             "last": agg.last, "hosts": agg.hosts.most_common(), "base_count": base_count,
             "status": st, "ratio": ratio, "symptom": key in SYMPTOMS, "also": [],
             "count_label": count_label, "rel_cat": rel_cat or cat, "evidence": self._evidence(agg)}
        self._score(f)
        return f

    def _score(self, f):
        """severity x relevance-to-complaint x timing x novelty x cause-vs-symptom x volume"""
        timing = 1.5 if f["first"] <= self.incident + TWO_MIN else 0.6
        role = 0.5 if f["symptom"] else 1.0
        vol = 1 + min(math.log10(max(f["count"], 1)), 3) * 0.15
        f["score"] = round(SEV_WEIGHT[f["sev"]] * self._rel(f["rel_cat"]) * timing * NOVELTY[f["status"]] * role * vol, 2)

    def _clean(self, items):
        return [(i[0], i[1], i[2], clean_text(i[3], self.redact)) for i in items]

    def _silences(self):
        out = []
        if self.data_max is None:
            return out
        w0, w1 = _secs(self.w_start), _secs(self.w_end)
        gmax = _secs(self.data_max)
        for host, st in self.hosts.items():
            ts = sorted(st.times)
            if len(ts) < 30:          # too sparse to judge silence (e.g. a quiet syslog)
                continue
            diffs = [b - a for a, b in zip(ts, ts[1:])]
            base_gaps = [b - a for a, b in zip(ts, ts[1:]) if b < w0]
            if len(base_gaps) >= 20:
                longest = max(base_gaps)
                thr = max(self.gap_seconds, 1.5 * longest)
                basis = "its longest quiet spell in the hour before was only %s" % fmt_dur(longest)
            else:
                med = statistics.median(diffs) if diffs else 0
                thr = max(self.gap_seconds, 10 * med)
                basis = "it usually logs every %s or so" % fmt_dur(max(med, 1))
            gaps = []
            for a, b in zip(ts, ts[1:]):
                if b - a >= thr and b >= w0 and a <= w1:
                    ctx = next((c for c in st.cands if c["start"] == a and c["end"] == b), None)
                    gaps.append({"kind": "gap", "host": host, "start": _from_secs(a), "end": _from_secs(b),
                                 "dur": b - a, "basis": basis,
                                 "before": self._clean(ctx["before"]) if ctx else [],
                                 "after": self._clean(ctx["after"]) if ctx else []})
            gaps.sort(key=lambda g: -g["dur"])
            out.extend(gaps[:5])
            last = ts[-1]
            end_ref = min(w1, gmax)
            if w0 - thr <= last < end_ref - thr:
                out.append({"kind": "tail", "host": host, "start": _from_secs(last), "end": _from_secs(end_ref),
                            "dur": end_ref - last, "basis": basis, "before": self._clean(st.ring), "after": []})
        # whole data set ends early inside the window
        if self.w_start <= self.data_max < self.w_end - dt.timedelta(seconds=self.gap_seconds):
            last_host = None
            for host, st in self.hosts.items():
                if st.last is not None and abs(st.last - gmax) < 1e-6:
                    last_host = host
            ring = self._clean(self.hosts[last_host].ring) if last_host else []
            out.append({"kind": "eod", "host": last_host or "all logs", "start": self.data_max,
                        "end": self.w_end, "dur": (self.w_end - self.data_max).total_seconds(),
                        "basis": "", "before": ring, "after": []})
        out.sort(key=lambda g: g["start"])
        return out

    def _traffic(self, win_min, base_min):
        W, B = self.win, self.base
        if W.http < 20:
            return None, []
        mins = []
        t = self.w_start.replace(second=0, microsecond=0)
        while t <= self.w_end:
            b = self.minutes.get(t)
            mins.append((t, b[2] if b else 0, b[3] if b else 0))
            t += dt.timedelta(minutes=1)
        peak = max(mins, key=lambda m: m[1])
        base_rate = (B.http / base_min) if base_min >= 5 and B.http else None
        tr = {"win_requests": W.http, "base_requests": B.http, "base_rate": base_rate,
              "peak_time": peak[0], "peak": peak[1],
              "err_win": W.http5xx / float(W.http),
              "err_base": (B.http5xx / float(B.http)) if B.http else None,
              "status": sorted(W.status.items()),
              "top_ips": [(ip, c, c / float(W.http), (B.ips.get(ip, 0) / float(B.http)) if B.http else None)
                          for ip, c in W.ips.most_common(5)]}
        pseudo = []
        # users getting 5xx
        eb = tr["err_base"]
        if W.http5xx >= 10 and tr["err_win"] >= 0.05 and (eb is None or tr["err_win"] >= 3 * max(eb, 0.002)):
            a = self.http5xx_agg
            sev = "high" if tr["err_win"] >= 0.25 else "medium"
            f = self._finding("http_5xx", "Users were getting server errors (HTTP 5xx)", "http", sev,
                              "%.0f%% of web requests failed on the server side in the window (vs %s before). This is what users experienced; the cause is usually the problem that started just before it."
                              % (tr["err_win"] * 100, ("%.1f%%" % (eb * 100)) if eb is not None else "unknown"),
                              "Look at the application/upstream errors that started just before the 5xx errors began.",
                              a, B.http5xx, win_min, base_min)
            # onset = first minute where 5xx clearly exceeds the normal background level
            base_per_min = (B.http5xx / base_min) if base_min >= 5 else 0
            onset = None
            for m in mins:
                if m[2] >= max(3, 3 * base_per_min) and m[1] and m[2] / float(m[1]) >= 0.05:
                    onset = m[0]
                    break
            if onset is not None and onset in self.http5xx_min_ex:
                ex_min = sorted(k for k in self.http5xx_min_ex if k >= onset)
                picks = [self.http5xx_min_ex[k] for k in ex_min[:2]]
                if a.ex_last and all(a.ex_last[1] != p[1] for p in picks):
                    picks.append(a.ex_last)
                f["first"] = picks[0][0]
                f["evidence"] = [{"ts": p[0], "ref": p[1], "file": p[2], "host": p[3], "text": p[4]}
                                 for p in picks[:self.max_evidence]]
                f["meaning"] += " Errors rose clearly above normal from %s." % fmt_hms(onset)
                self._score(f)
            f["count_label"] = "%s failed requests (%.0f%% of traffic)" % ("{:,}".format(W.http5xx), tr["err_win"] * 100)
            pseudo.append(f)
        # surge / flood
        if base_rate and peak[1] >= max(3 * base_rate, base_rate + 50):
            first = next(m for m in mins if m[1] >= max(3 * base_rate, base_rate + 50))
            top = tr["top_ips"][0] if tr["top_ips"] else None
            flood = top is not None and top[2] >= 0.3 and W.http >= 200 and (top[3] is None or top[3] < top[2] / 2)
            ag = Agg()
            ag.count, ag.first, ag.last = peak[1], first[0], peak[0]
            ag.before = 1 if first[0] <= self.incident else 0
            ag.hosts = collections.Counter()
            lines = ["%s  %s requests in that minute (normal is about %.0f per minute)"
                     % (fmt_hms(m[0]), "{:,}".format(m[1]), base_rate) for m in mins if m[1] >= 3 * base_rate][:6]
            if flood:
                lines.append("Top client %s sent %.0f%% of all requests in the window (%s before)"
                             % (top[0], top[2] * 100, ("%.0f%%" % (top[3] * 100)) if top[3] is not None else "n/a"))
            f = self._finding(
                "traffic_flood" if flood else "traffic_surge",
                "Traffic flood, mostly from a few clients (possible bot / DoS)" if flood else "Sudden surge in incoming requests",
                "security" if flood else "resource", "high",
                "Requests jumped to %s per minute against a normal ~%.0f. %s"
                % ("{:,}".format(peak[1]), base_rate,
                   "Most came from a small number of IP addresses, which looks like a bot, scraper or denial-of-service attempt."
                   if flood else "More traffic than usual can exhaust threads, connections or CPU."),
                "Check the top client IPs and URLs; apply rate-limiting / WAF rules if it is abusive, or scale up if it is real demand.",
                ag, 0, win_min, base_min, rel_cat="resource",
                count_label="peak %s requests/min vs normal ~%.0f" % ("{:,}".format(peak[1]), base_rate))
            f["status"], f["ratio"] = "SPIKE", peak[1] / base_rate
            if flood:
                f["title"] = "Traffic flood - %.0f%% of requests came from %s (possible bot / DoS)" % (top[2] * 100, top[0])
            f["evidence"] = [{"ts": first[0], "ref": "summary", "file": "", "host": "", "text": "\n".join(lines)}]
            self._score(f)
            pseudo.append(f)
        # drop
        if base_rate and base_rate >= 10:
            low = [m for m in mins if m[1] <= 0.2 * base_rate and m[0] < (self.data_max or self.w_end)]
            if len(low) >= 2:
                ag = Agg()
                ag.count, ag.first, ag.last = len(low), low[0][0], low[-1][0]
                f = self._finding("traffic_drop", "Incoming requests dropped sharply", "http", "medium",
                                  "For %d minute(s) the web logs saw less than 20%% of normal traffic - users may not have been able to reach the site at all (DNS, network, load balancer or upstream problem)." % len(low),
                                  "Check DNS, network, load balancer and firewall status at that time.",
                                  ag, 0, win_min, base_min,
                                  count_label="%d low-traffic minute(s)" % len(low))
                f["status"] = "NEW"
                self._score(f)
                f["evidence"] = [{"ts": low[0][0], "ref": "summary", "file": "", "host": "",
                                  "text": "\n".join("%s  %d requests (normal about %.0f per minute)" % (fmt_hms(m[0]), m[1], base_rate) for m in low[:6])}]
                pseudo.append(f)
        return tr, pseudo

    # ---------------------------------------------------------------- report
    def report(self):
        inc = self.incident
        win_min, base_min = self._coverage()
        self._base_min_eff = base_min
        R = collections.OrderedDict()
        R["tool"] = "Splunk Log Analyzer %s" % VERSION
        R["generated"] = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        R["reason"] = self.reason
        R["reason_labels"] = self.reason_labels
        R["incident"] = inc
        R["window"] = (self.w_start, self.w_end)
        R["baseline"] = (max(self.b_start, self.data_min), self.w_start) if base_min >= 5 else None
        R["base_min"] = base_min
        R["files"] = self.files
        R["data_range"] = (self.data_min, self.data_max)
        R["counts"] = {"window_events": self.win.events, "baseline_events": self.base.events,
                       "window_problems": self.win.problems, "baseline_problems": self.base.problems,
                       "total_events": self.total_events}

        findings = []
        for key, agg in self.sig_agg.items():
            s = SIG_BY_KEY[key]
            if s.sev == "info":
                continue
            findings.append(self._finding(key, s.title, s.cat, s.sev, s.meaning, s.check, agg,
                                          self.base.sig.get(key, 0), win_min, base_min))
        traffic, pseudo = self._traffic(win_min, base_min)
        findings.sort(key=lambda f: -f["score"])
        # one log line can match several patterns - merge findings built from the exact same lines
        merged, seen = [], {}
        for f in findings:
            ev = f["evidence"][0] if f["evidence"] else None
            sig = (f["count"], f["first"], ev["ref"], ev["file"]) if ev else None
            if sig is not None and sig in seen:
                seen[sig]["also"].append(f["title"])
                continue
            if sig is not None:
                seen[sig] = f
            merged.append(f)
        findings = merged + pseudo
        findings.sort(key=lambda f: -f["score"])
        noise = [f for f in findings if f["status"] == "NORMAL"]
        cands = [f for f in findings if f["status"] != "NORMAL"]

        unrec, recurring = [], []
        for tpl, agg in self.tpl_agg.items():
            bc = self.base.tpl.get(tpl, 0)
            st, ratio = self._status(agg.count, bc, win_min, base_min)
            timing = 1.5 if agg.first <= inc + TWO_MIN else 0.6
            vol = 1 + min(math.log10(max(agg.count, 1)), 3) * 0.2
            item = {"template": tpl, "count": agg.count, "base_count": bc, "status": st, "ratio": ratio,
                    "first": agg.first, "last": agg.last, "hosts": agg.hosts.most_common(),
                    "score": round(2 * timing * NOVELTY[st] * vol, 2), "evidence": self._evidence(agg)[:1]}
            (recurring if st == "NORMAL" else unrec).append(item)
        unrec.sort(key=lambda u: (STATUS_ORDER[u["status"]], -u["count"]))
        recurring.sort(key=lambda u: -u["count"])

        silences = self._silences()
        markers = self._dedupe_markers()

        R["findings"] = cands
        R["noise"] = noise
        R["unrecognized"] = unrec[:10]
        R["recurring"] = recurring[:6]
        R["silences"] = silences
        R["markers"] = markers
        R["traffic"] = traffic
        self._verdict(R, cands, unrec, silences, markers)
        R["timeline"] = self._timeline(R)
        R["hosts"] = self._host_table()
        R["series"] = self._series(base_min)
        R["data_gaps"] = self._data_gaps(R, win_min, base_min)
        return R

    def _dedupe_markers(self):
        out = []
        for m in sorted(self.markers, key=lambda x: x[0]):
            if out and out[-1][1] == m[1] and out[-1][2] == m[2] and (m[0] - out[-1][0]).total_seconds() < 120:
                continue
            out.append(m)
        return out[:40]

    def _where(self, hosts):
        names = [h for h, _ in hosts]
        if not names:
            return ""
        fnames = {f["name"] for f in self.files}
        prep = "in" if names[0] in fnames else "on"
        txt = ", ".join(names[:3])
        if len(names) > 3:
            txt += " (+%d more)" % (len(names) - 3)
        return "%s %s" % (prep, txt)

    def _name(self, f):
        w = self._where(f["hosts"])
        return "%s %s" % (f["title"].rstrip("."), w) if w else f["title"].rstrip(".")

    @staticmethod
    def _count_txt(f):
        if f.get("count_label"):
            return f["count_label"]
        return "%s time(s)" % "{:,}".format(f["count"])

    def _status_phrase(self, f):
        st = f["status"]
        mins = int(round(getattr(self, "_base_min_eff", self.baseline_min)))
        if st == "NEW":
            return "new - not seen in the %d min before" % mins
        if st == "SPIKE":
            return "%.0fx its normal rate" % f["ratio"] if f.get("ratio") else "far above normal"
        if st == "ELEVATED":
            return "somewhat above normal (%.1fx)" % f["ratio"]
        if st == "NORMAL":
            return "happens normally too"
        return "no earlier data to compare"

    def _verdict(self, R, cands, unrec, silences, markers):
        inc = self.incident
        story, steps, why = [], [], []
        win_lbl = "%s to %s" % (fmt_hms(self.w_start, self._multi()), fmt_hms(self.w_end, self._multi()))
        if R["baseline"]:
            story.append("Looked at %s log events between %s and compared them with %s events from the %d minutes before (what \"normal\" looks like)."
                         % ("{:,}".format(self.win.events), win_lbl, "{:,}".format(self.base.events), int(round(R["base_min"]))))
        else:
            story.append("Looked at %s log events between %s. There was no earlier data to compare with, so \"new vs normal\" could not be judged."
                         % ("{:,}".format(self.win.events), win_lbl))

        near = [s for s in silences if s["kind"] in ("gap", "tail")
                and s["start"] <= inc + dt.timedelta(minutes=10) and s["end"] >= inc - dt.timedelta(minutes=30)]
        restarts = [m for m in markers if m[2] in ("start", "boot")]
        stops = [m for m in markers if m[2] == "stop"]
        flood = [f for f in cands if f["key"] in ("traffic_flood", "traffic_surge")]
        corro = bool(near or restarts or flood or any(f["key"] == "http_5xx" for f in cands))

        conf, headline, top = "Low", "", None
        if self.win.events == 0:
            conf = "Inconclusive"
            if self.data_min is None:
                headline = "No readable log events were found in the file(s), so nothing can be concluded."
            else:
                headline = ("The logs contain nothing between %s - they cover %s to %s. Check the date, time and timezone you entered."
                            % (win_lbl, fmt_full(self.data_min), fmt_full(self.data_max)))
            steps.append("Re-run with the correct date/time, or use --tz if the logs are in a different timezone (e.g. UTC).")
        elif cands:
            top = cands[0]
            strong = top["sev"] in ("critical", "high") and top["status"] in ("NEW", "SPIKE") and top["first"] <= inc + TWO_MIN
            margin = len(cands) == 1 or top["score"] >= 1.5 * cands[1]["score"]
            conf = "High" if strong and (margin or corro) else "Medium"
            if top["status"] == "UNKNOWN" and conf == "High":
                conf = "Medium"
            if top["sev"] in ("medium", "low") and conf == "High":
                conf = "Medium"
            if top["first"] > inc + TWO_MIN:
                conf = "Low"
            headline = ("Most likely cause: %s. First seen at %s (%s); %s in the window - %s."
                        % (self._name(top), fmt_hms(top["first"], self._multi()),
                           rel_phrase(top["first"], inc), self._count_txt(top), self._status_phrase(top)))
            # an earlier, strong, new cause may have triggered the top one (e.g. traffic flood -> out of memory)
            trig = [f for f in cands[1:] if not f["symptom"] and f["first"] < top["first"] - dt.timedelta(seconds=30)
                    and f["sev"] in ("critical", "high") and f["status"] in ("NEW", "SPIKE")
                    and f["score"] >= 0.4 * top["score"]]
            if trig:
                t0 = min(trig, key=lambda f: f["first"])
                headline += " It was preceded by: %s at %s, which likely triggered it." % (t0["title"], fmt_hms(t0["first"], self._multi()))
            why.append("%s: %s." % (top["title"], self._status_phrase(top)))
            if top["first"] <= inc + TWO_MIN:
                why.append("It started before the problem was reported (%s)." % rel_phrase(top["first"], inc))
            else:
                why.append("It only appeared after the reported time, so it may be a consequence rather than the cause.")
            if near:
                s = near[0]
                why.append("Backed up by a logging silence on %s (%s with no logs)." % (s["host"], fmt_dur(s["dur"])))
            if restarts:
                why.append("Backed up by a restart at %s." % fmt_hms(restarts[0][0], self._multi()))
            after = [f for f in cands if f["symptom"] and top["first"] <= f["first"] <= top["first"] + dt.timedelta(minutes=10)]
            if after and not top["symptom"]:
                f2 = min(after, key=lambda x: x["first"])
                why.append("Consistent with what followed: %s at %s." % (f2["title"], fmt_hms(f2["first"], self._multi())))
            close = [f for f in cands[1:] if f["score"] >= 0.75 * top["score"] and not (trig and f is min(trig, key=lambda x: x["first"]))]
            if close:
                why.append("A close second candidate: %s." % close[0]["title"])
            if top.get("symptom"):
                why.append("Note: this is mainly a symptom (what users or other systems felt). The underlying reason may be in a system whose logs are not in this file.")
        elif unrec and unrec[0]["status"] in ("NEW", "SPIKE", "UNKNOWN"):
            u = unrec[0]
            top_u = u
            conf = "Low"
            headline = ("No known failure pattern matched. The clearest change is an error that %s at %s %s: \"%s\" (%s times)."
                        % ("started" if u["status"] == "NEW" else "spiked", fmt_hms(u["first"], self._multi()),
                           self._where(u["hosts"]), u["template"][:140], "{:,}".format(u["count"])))
            why.append("Unrecognised error, but it is %s and began %s." % (self._status_phrase(u), rel_phrase(u["first"], inc)))
        elif near:
            s = near[0]
            conf = "Medium"
            headline = ("%s stopped writing logs at %s for %s - the service/server was most likely down or frozen. The logs do not say why (no error before it)."
                        % (s["host"], fmt_hms(s["start"], self._multi()), fmt_dur(s["dur"])))
            why.append("A silence like this is unusual: %s." % s["basis"])
            steps.append("Check the operating-system/system logs (Linux /var/log/messages or journal, Windows System event log) and VM/hypervisor events for that exact time - the cause is outside this application log.")
        else:
            conf = "Low"
            headline = ("Nothing clearly abnormal was found around that time in these logs. The cause is probably in another system (database, load balancer, network, OS) or outside this time window.")
            steps.append("Widen the window (e.g. --before 120) or add logs from other tiers for the same time.")

        # ---- what happened, in time order
        mt = self._multi()
        events = []   # (time, text)
        chain = []
        if cands:
            cut = cands[0]["score"] * 0.2
            chain = [f for f in cands if f["score"] >= cut][:7]
            change = [f for f in cands if f["key"] == "change" and f["first"] <= inc and f not in chain]
            chain += change[:1]
            chain.sort(key=lambda f: f["first"])
            for f in chain:
                tag = " (symptom - what users/other systems felt)" if f.get("symptom") else ""
                events.append((f["first"], "%s - %s%s: %s, %s."
                               % (fmt_hms(f["first"], mt), self._name(f), tag, self._count_txt(f), self._status_phrase(f))))
        for s in silences:
            if s["kind"] == "gap":
                events.append((s["start"], "%s - %s wrote NO logs for %s (until %s). For comparison, %s. Silence like this usually means the application/server was down, frozen or restarting."
                               % (fmt_hms(s["start"], mt), s["host"], fmt_dur(s["dur"]), fmt_hms(s["end"], mt), s["basis"])))
            elif s["kind"] == "tail":
                events.append((s["start"], "%s - %s stopped logging and did not log again before %s, while other logs carried on. It most likely went down and stayed down."
                               % (fmt_hms(s["start"], mt), s["host"], fmt_hms(s["end"], mt))))
            elif s["kind"] == "eod":
                events.append((s["start"], "%s - The log data ends here, %s before the end of the window. If your export covered later times, the server stopped logging at this point (a strong sign it went down); otherwise, export a wider time range."
                               % (fmt_hms(s["start"], mt), fmt_dur(s["dur"]))))
        for m in restarts[:4]:
            events.append((m[0], "%s - %s %s (%s)."
                           % (fmt_hms(m[0], mt), "Server booted" if m[2] == "boot" else "Startup messages logged - the service was (re)started",
                              self._where([(m[1], 1)]), m[4])))
        if stops:
            crit_before = [f for f in cands if f["sev"] == "critical" and f["first"] <= stops[0][0]]
            if not crit_before:
                events.append((stops[0][0], "%s - A shutdown/stop was requested %s with no crash before it. This looks like a deliberate stop (deployment, admin action, patching or auto-scaling), not a crash."
                               % (fmt_hms(stops[0][0], mt), self._where([(stops[0][1], 1)]))))
        events.sort(key=lambda e: e[0])
        story.extend(e[1] for e in events)

        # ---- notes
        auth = [f for f in cands if f["key"] == "auth_fail" and f["count"] >= 30]
        if auth:
            a = auth[0]
            story.append("Note: %s failed logins in the window (%s). If they target few accounts or come from few IPs, treat it as a possible brute-force / credential-stuffing attempt."
                         % ("{:,}".format(a["count"]), self._status_phrase(a)))
        if cands and cands[0]["key"] in ("conn_refused", "timeout", "dns", "net_unreachable", "db_conn", "bad_gateway",
                                         "circuit_open", "unavailable_503", "http_5xx"):
            story.append("Note: the trail points to ANOTHER system this one depends on (see the host/URL in the evidence). Export that system's logs for the same time to find its own root cause.")
        if R["noise"]:
            story.append("Ignored as background noise (they happen at a similar rate before the problem too): %s."
                         % "; ".join("%s (%s now vs %s before)" % (f["title"], "{:,}".format(f["count"]), "{:,}".format(f["base_count"]))
                                     for f in R["noise"][:4]))

        # ---- next steps
        for f in chain[::-1] if not cands else sorted(chain, key=lambda f: -f["score"]):
            if f["check"] and f["check"] not in steps:
                steps.append(f["check"])
            if len(steps) >= 3:
                break
        if near and not any("operating-system" in s for s in steps):
            steps.append("For the silent period, check OS/system logs and monitoring (CPU, memory, disk) for that host at the same time.")
        if self.no_ts_lines and self.no_ts_lines > 0.2 * max(1, self.total_events):
            steps.append("Many lines had no recognisable timestamp - confirm the file format (see Data gaps).")
        if not steps:
            steps.append("Compare with logs from other layers (database, load balancer, OS) for the same time.")

        R["verdict"] = {"confidence": conf, "headline": headline, "why": why}
        R["story"] = story
        R["next_steps"] = steps[:5]
        R["chain_keys"] = [f["key"] for f in chain]

    def _multi(self):
        return self.w_start.date() != self.w_end.date()

    def _timeline(self, R):
        items = [{"ts": self.incident, "host": "", "kind": "reported", "text": "Problem reported: \"%s\"" % self.reason, "ref": ""}]
        chain = set(R["chain_keys"])
        for f in R["findings"]:
            if f["key"] in chain or f is (R["findings"][0] if R["findings"] else None):
                ev = f["evidence"][0] if f["evidence"] else None
                items.append({"ts": f["first"], "host": ev["host"] if ev else "", "kind": f["sev"],
                              "text": "First: %s" % f["title"],
                              "ref": ("%s (%s)" % (ev["ref"], ev["file"])) if ev and ev["file"] else ""})
        for s in R["silences"]:
            if s["kind"] == "gap":
                items.append({"ts": s["start"], "host": s["host"], "kind": "silence",
                              "text": "Logs go silent for %s" % fmt_dur(s["dur"]), "ref": ""})
                items.append({"ts": s["end"], "host": s["host"], "kind": "resume", "text": "Logging resumes", "ref": ""})
            elif s["kind"] == "tail":
                items.append({"ts": s["start"], "host": s["host"], "kind": "silence", "text": "Logs stop (never resume in window)", "ref": ""})
            else:
                items.append({"ts": s["start"], "host": s["host"] or "", "kind": "silence", "text": "End of log data", "ref": ""})
        for m in R["markers"][:15]:
            label = {"start": "Service started", "boot": "Server booted", "stop": "Stop/shutdown requested"}[m[2]]
            items.append({"ts": m[0], "host": m[1], "kind": m[2], "text": "%s - %s" % (label, m[3][:140]),
                          "ref": "%s (%s)" % (m[4], m[5])})
        tr = R["traffic"]
        if tr and tr["base_rate"] and tr["peak"] >= 3 * tr["base_rate"]:
            items.append({"ts": tr["peak_time"], "host": "", "kind": "traffic",
                          "text": "Traffic peak: %s requests/min (normal about %.0f)" % ("{:,}".format(tr["peak"]), tr["base_rate"]), "ref": ""})
        items.sort(key=lambda i: (i["ts"], i["kind"] != "reported"))
        return items[:40]

    def _host_table(self):
        hosts = set(self.win.host_events) | set(self.base.host_events)
        rows = []
        for h in hosts:
            st = self.hosts.get(h)
            rows.append({"host": h, "win_events": self.win.host_events.get(h, 0),
                         "win_problems": self.win.host_problems.get(h, 0),
                         "base_events": self.base.host_events.get(h, 0),
                         "base_problems": self.base.host_problems.get(h, 0),
                         "last_seen": _from_secs(st.last) if st and st.last else None})
        rows.sort(key=lambda r: (-r["win_problems"], -r["win_events"]))
        return rows[:15]

    def _series(self, base_min):
        start = self.w_start.replace(second=0, microsecond=0)
        end = self.w_end.replace(second=0, microsecond=0)
        n = int((end - start).total_seconds() // 60) + 1
        step = max(1, int(math.ceil(n / 90.0)))
        pts = []
        t = start
        while t <= end:
            tot = err = 0
            for k in range(step):
                b = self.minutes.get(t + dt.timedelta(minutes=k))
                if b:
                    tot += b[0]
                    err += b[1]
            pts.append((t, tot, err))
            t += dt.timedelta(minutes=step)
        base_avg = (self.base.events / base_min * step) if base_min >= 5 else None
        base_err = (self.base.problems / base_min * step) if base_min >= 5 else None
        return {"points": pts, "step": step, "base_avg": base_avg, "base_err": base_err}

    def _data_gaps(self, R, win_min, base_min):
        g = []
        if self.data_min is None:
            g.append("No timestamped events could be read. The file format may not be supported, or it is empty.")
            return g
        if self.data_min > self.w_start:
            g.append("Logs start at %s - after the start of the analysis window, so the lead-up to the problem is partly missing." % fmt_full(self.data_min))
        if self.data_max < self.w_end:
            g.append("Logs end at %s - before the end of the analysis window. What happened after that is not visible." % fmt_full(self.data_max))
        if base_min < 5:
            g.append("No (or too little) data before the window, so the tool cannot tell which errors are new and which are normal. Export at least an hour before the incident for a better answer.")
        elif base_min < self.baseline_min - 1:
            g.append("Only %d minutes of 'normal' data were available before the window (wanted %d)." % (int(round(base_min)), self.baseline_min))
        if self.no_ts_lines:
            pct = 100.0 * self.no_ts_lines / max(1, self.no_ts_lines + self.total_events + self.cont_lines)
            g.append("%s line(s) (%.1f%%) had no recognisable timestamp and could not be placed in time (ignored)." % ("{:,}".format(self.no_ts_lines), pct))
        if self.cont_lines and self.total_events and self.cont_lines > 20 * self.total_events:
            g.append("Most lines had no timestamp and were treated as continuation lines - the timestamp format may not be recognised.")
        offs = self.tp.offsets
        if offs and self.target_offset is None:
            zones = ", ".join(fmt_off(o) for o in sorted(offs))
            if len(offs) > 1:
                g.append("Log timestamps use different timezones (%s) and were compared as written. Re-run with --tz (e.g. --tz +05:30) to put everything on one clock." % zones)
            else:
                g.append("Log timestamps carry timezone %s. Your time was assumed to be on the same clock; if you meant another timezone, re-run with --tz." % zones)
        elif self.target_offset is not None and not offs:
            g.append("Logs have no timezone information; they were assumed to already be in %s." % fmt_off(self.target_offset))
        if self.tp.yearless:
            g.append("Some timestamps have no year (syslog style); year %d was assumed." % self.incident.year)
        for f in self.files:
            if f["format"] == "csv" and f["records"] in (10000, 50000, 100000, 500000):
                g.append("%s has exactly %s rows - a round number that often means the Splunk search/export was capped. Events may be missing." % (f["name"], "{:,}".format(f["records"])))
        n_hosts = len(set(self.win.host_events))
        if self.win.events:
            nolevel = self.win.levels.get("-", 0) / float(self.win.events)
            if nolevel > 0.8:
                g.append("Most lines have no severity level (ERROR/WARN...), so error detection relies on known patterns only.")
            g.append("Evidence comes only from %d host/source(s) in this export. Database, load balancer, network and OS logs are not visible unless included." % n_hosts)
        if self.tpl_overflow:
            g.append("Very many distinct error messages; some rare ones were not grouped.")
        return g


# ============================================================================
# 6. FORMATTING HELPERS
# ============================================================================
def fmt_dur(sec):
    sec = int(round(sec))
    if sec < 60:
        return "%ds" % sec
    m, s = divmod(sec, 60)
    if m < 60:
        return "%dm %02ds" % (m, s)
    h, m = divmod(m, 60)
    if h < 48:
        return "%dh %02dm" % (h, m)
    d, h = divmod(h, 24)
    return "%dd %02dh" % (d, h)


def fmt_hms(d, with_date=False):
    if d is None:
        return "-"
    return d.strftime("%d %b %H:%M:%S") if with_date else d.strftime("%H:%M:%S")


def fmt_full(d):
    return d.strftime("%Y-%m-%d %H:%M:%S") if d else "-"


def fmt_off(o):
    sign = "+" if o >= 0 else "-"
    return "%s%02d:%02d" % (sign, abs(o) // 60, abs(o) % 60)


def rel_phrase(ts, ref):
    d = (ts - ref).total_seconds()
    if abs(d) < 60:
        return "right at the reported time"
    return "%s %s the reported time" % (fmt_dur(abs(d)), "before" if d < 0 else "after")


# ============================================================================
# 7. TERMINAL OUTPUT
# ============================================================================
class Paint(object):
    def __init__(self, on):
        self.on = on

    def __call__(self, s, codes):
        return "\033[%sm%s\033[0m" % (codes, s) if self.on and codes else s


SEV_COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "2", "info": "2"}
CONF_COLOR = {"High": "1;32", "Medium": "1;33", "Low": "1;31", "Inconclusive": "1;31"}
SPARK = u"\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"


def render_text(R, paint, width):
    out = []
    W = max(60, min(width, 110))
    rule = "=" * W
    multi = R["window"][0].date() != R["window"][1].date()

    def wrap(text, indent="  ", sub=None):
        return textwrap.fill(text, W, initial_indent=indent, subsequent_indent=sub or indent + "  ",
                             break_long_words=False, break_on_hyphens=False)

    def head(t):
        out.append("")
        out.append(paint(t, "1;36"))
        out.append(paint("-" * len(t), "36"))

    out.append(rule)
    out.append(paint(" SPLUNK LOG ANALYZER - incident report", "1"))
    out.append(rule)
    out.append(" Reported : \"%s\" at %s" % (R["reason"], fmt_full(R["incident"])))
    out.append(" Window   : %s -> %s" % (fmt_full(R["window"][0]), fmt_full(R["window"][1])))
    out.append(" Baseline : %s" % (("%s -> %s" % (fmt_full(R["baseline"][0]), fmt_full(R["baseline"][1]))) if R["baseline"] else "none available"))
    out.append(" Files    : %s" % ", ".join("%s (%s, %s events)" % (f["name"], f["format"], "{:,}".format(f["events"])) for f in R["files"]))
    if R["reason_labels"]:
        out.append(" Read as  : %s" % ", ".join(R["reason_labels"]))

    v = R["verdict"]
    head("VERDICT")
    out.append("  " + paint("[%s confidence]" % v["confidence"].upper(), CONF_COLOR.get(v["confidence"], "1")))
    out.append(wrap(v["headline"]))
    for w in v["why"]:
        out.append(wrap("- " + w, "    "))

    head("WHAT HAPPENED (simple terms)")
    for s in R["story"]:
        out.append(wrap("* " + s))

    head("WHAT TO CHECK NEXT")
    for i, s in enumerate(R["next_steps"], 1):
        out.append(wrap("%d. %s" % (i, s)))

    pts = R["series"]["points"]
    if pts:
        mx = max(p[1] for p in pts) or 1
        spark = "".join(SPARK[min(7, int(7.0 * p[1] / mx))] if p[1] else " " for p in pts)
        errs = "".join(paint("!", "31") if p[2] else " " for p in pts)
        head("ACTIVITY (events per %d min, ! = errors)" % R["series"]["step"])
        inc_i = int((R["incident"] - pts[0][0]).total_seconds() // (60 * R["series"]["step"]))
        marker = " " * max(0, inc_i) + "^ reported"
        out.append("  " + spark)
        out.append("  " + errs)
        out.append("  " + paint(marker, "35"))
        out.append("  %s%s%s" % (fmt_hms(pts[0][0])[:5], " " * max(1, len(pts) - 10), fmt_hms(pts[-1][0])[:5]))

    head("TIMELINE")
    for it in R["timeline"]:
        col = {"reported": "1;35", "silence": "1;31", "resume": "32", "start": "32", "boot": "32",
               "stop": "33", "traffic": "33"}.get(it["kind"], SEV_COLOR.get(it["kind"], ""))
        line = "%s  %-14s %s" % (fmt_hms(it["ts"], multi), (it["host"] or "")[:14], it["text"])
        if it["ref"]:
            line += paint("  [%s]" % it["ref"], "2")
        out.append("  " + paint(line, col) if not it["ref"] else "  " + line)

    head("EVIDENCE")
    if not R["findings"]:
        out.append("  No known failure pattern was new or unusual in this window.")
    for i, f in enumerate(R["findings"][:8], 1):
        if f.get("count_label"):
            tag = "%s | %s | %s" % (f["sev"].upper(), f["status"], f["count_label"])
        else:
            tag = "%s | %s | %sx in window, %sx in the %d min before" % (
                f["sev"].upper(), f["status"], "{:,}".format(f["count"]), "{:,}".format(f["base_count"]), int(round(R["base_min"])))
        out.append("")
        out.append("  " + paint("[%d] %s" % (i, f["title"]), "1") + "  " + paint(tag, SEV_COLOR.get(f["sev"], "")))
        where = ", ".join(h for h, _ in f["hosts"][:3])
        out.append(paint("      first %s (%s) - last %s%s" % (fmt_hms(f["first"], multi), rel_phrase(f["first"], R["incident"]),
                                                           fmt_hms(f["last"], multi), (" - " + where) if where else ""), "2"))
        if f.get("also"):
            out.append(paint("      same lines also match: %s" % "; ".join(f["also"]), "2"))
        out.append(wrap("What it means: " + f["meaning"], "      ", "        "))
        out.append(wrap("Check next: " + f["check"], "      ", "        "))
        for ev in f["evidence"]:
            label = "%s %s" % (ev["ref"], ("(%s)" % ev["file"]) if ev["file"] else "")
            out.append(paint("      > %s  %s" % (label.strip(), fmt_hms(ev["ts"], multi)), "36"))
            for ln in ev["text"].split("\n")[:8]:
                out.append("        " + ln[:W - 8])

    if R["silences"]:
        head("LOG SILENCES (no logs = likely down/frozen)")
        for s in R["silences"]:
            out.append("  %s  %s -> %s  (%s)  %s" % (s["host"], fmt_hms(s["start"], multi), fmt_hms(s["end"], multi),
                                                    fmt_dur(s["dur"]), {"gap": "gap", "tail": "never resumed", "eod": "data ends"}[s["kind"]]))
            for b in s["before"][-3:]:
                out.append(paint("      last before: %s %s" % (b[1], b[3][:W - 30]), "2"))
            for a in s["after"][:2]:
                out.append(paint("      first after: %s %s" % (a[1], a[3][:W - 30]), "2"))

    if R["unrecognized"]:
        head("OTHER UNUSUAL ERRORS (no known pattern)")
        for u in R["unrecognized"][:6]:
            out.append(wrap("- %s x%s (%s) first %s: %s" % (u["status"], "{:,}".format(u["count"]), "{:,} before".format(u["base_count"]),
                                                          fmt_hms(u["first"], multi), u["template"][:150])))
            if u["evidence"]:
                out.append(paint("      e.g. %s (%s): %s" % (u["evidence"][0]["ref"], u["evidence"][0]["file"],
                                                         u["evidence"][0]["text"].split("\n")[0][:W - 30]), "2"))

    tr = R["traffic"]
    if tr:
        head("WEB TRAFFIC")
        out.append("  Requests in window: %s | peak %s/min at %s | normal %s/min" % (
            "{:,}".format(tr["win_requests"]), "{:,}".format(tr["peak"]), fmt_hms(tr["peak_time"], multi),
            ("%.0f" % tr["base_rate"]) if tr["base_rate"] else "n/a"))
        out.append("  Server errors (5xx): %.1f%% in window vs %s before" % (
            tr["err_win"] * 100, ("%.1f%%" % (tr["err_base"] * 100)) if tr["err_base"] is not None else "n/a"))
        for ip, c, share, bshare in tr["top_ips"][:3]:
            out.append("  Client %-15s %6s req  %5.1f%% of traffic (before: %s)" % (
                ip, "{:,}".format(c), share * 100, ("%.1f%%" % (bshare * 100)) if bshare is not None else "n/a"))

    if R["noise"] or R["recurring"]:
        head("BACKGROUND NOISE (also present before - probably NOT the cause)")
        for f in R["noise"][:5]:
            out.append("  - %s: %sx now vs %sx before" % (f["title"], "{:,}".format(f["count"]), "{:,}".format(f["base_count"])))
        for u in R["recurring"][:4]:
            out.append("  - %s: %sx now vs %sx before" % (u["template"][:90], "{:,}".format(u["count"]), "{:,}".format(u["base_count"])))

    head("DATA GAPS & LIMITS")
    for g in R["data_gaps"] or ["None noticed."]:
        out.append(wrap("- " + g))
    out.append("")
    return "\n".join(out)


# ============================================================================
# 8. HTML REPORT (self-contained, no external resources)
# ============================================================================
CSS = """
:root{--bg:#f5f6f8;--card:#fff;--ink:#1b2130;--muted:#5e6779;--line:#e2e5eb;--accent:#2952cc;
--crit:#c42b2b;--high:#d9480f;--med:#b7791f;--low:#64748b;--ok:#2f855a;--code:#f3f4f7;--bar:#c6d0e3;--barerr:#d64545;--pill:#eef1f6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0f1218;--card:#171b23;--ink:#e6e9ef;--muted:#9aa3b2;
--line:#2a303c;--accent:#7ea2ff;--crit:#ff6b6b;--high:#ff9a5c;--med:#f2c94c;--low:#a0aec0;--ok:#68d391;--code:#0c0f14;--bar:#39445a;--barerr:#ff6b6b;--pill:#222836}}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--ink)}
body{font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:28px 16px 56px}
.eyebrow{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:600}
h1{font-size:26px;line-height:1.25;margin:6px 0 4px}h2{font-size:17px;margin:0 0 12px}h3{font-size:15px;margin:0}
.sub{color:var(--muted);margin:0}
section,.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-top:16px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px 18px;margin-top:14px;font-size:13.5px}
.meta div span{display:block;color:var(--muted);font-size:12px}
.verdict{border-left:6px solid var(--low)}.verdict.c-High{border-left-color:var(--ok)}.verdict.c-Medium{border-left-color:var(--med)}
.verdict.c-Low,.verdict.c-Inconclusive{border-left-color:var(--crit)}
.badge{display:inline-block;font-size:12px;font-weight:700;padding:3px 10px;border-radius:99px;background:var(--pill);letter-spacing:.03em}
.c-High .badge{color:var(--ok)}.c-Medium .badge{color:var(--med)}.c-Low .badge,.c-Inconclusive .badge{color:var(--crit)}
.headline{font-size:17px;font-weight:600;margin:10px 0 8px}
ul,ol{margin:0;padding-left:20px}li{margin:4px 0}.why{color:var(--muted);font-size:14px}
.story li{margin:7px 0}
.pill{display:inline-block;font-size:11.5px;font-weight:700;padding:2px 8px;border-radius:99px;background:var(--pill);margin-left:6px;vertical-align:middle;text-transform:uppercase}
.s-critical{color:var(--crit)}.s-high{color:var(--high)}.s-medium{color:var(--med)}.s-low,.s-info{color:var(--low)}
.st-NEW,.st-SPIKE{color:var(--crit)}.st-ELEVATED{color:var(--med)}.st-NORMAL,.st-UNKNOWN{color:var(--low)}
.finding{border:1px solid var(--line);border-left:5px solid var(--low);border-radius:10px;padding:14px 16px;margin:12px 0}
.finding.f-critical{border-left-color:var(--crit)}.finding.f-high{border-left-color:var(--high)}.finding.f-medium{border-left-color:var(--med)}
.fhead{display:flex;flex-wrap:wrap;align-items:center;gap:4px}.rank{color:var(--muted);font-weight:700;margin-right:6px}
.facts{color:var(--muted);font-size:13px;margin:6px 0 8px}
.finding p{margin:6px 0;font-size:14px}
.ev{margin-top:10px}.evmeta{font-size:12px;color:var(--muted);margin-bottom:3px;font-family:ui-monospace,Menlo,Consolas,monospace}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:0;overflow-x:auto;
white-space:pre-wrap;word-break:break-word;font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
td.t{white-space:nowrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
tr.k-reported td{font-weight:700;color:var(--accent)}tr.k-silence td{color:var(--crit);font-weight:600}
tr.k-start td,tr.k-boot td,tr.k-resume td{color:var(--ok)}tr.k-stop td{color:var(--med)}
.ref{color:var(--muted);font-size:12px}
svg .tot{fill:var(--bar)}svg .err{fill:var(--barerr)}svg .ax{fill:var(--muted);font-size:11px}
svg .inc{stroke:var(--accent);stroke-width:2}svg .base{stroke:var(--muted);stroke-dasharray:4 4}
svg .inct{fill:var(--accent);font-size:11px;font-weight:700}
.chart{overflow-x:auto}.chart svg{min-width:600px;display:block}
.legend{font-size:12.5px;color:var(--muted);margin-top:6px}.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin:0 4px 0 12px;vertical-align:-1px}
.gaps li{color:var(--muted)}footer{color:var(--muted);font-size:12px;margin-top:22px;text-align:center}
details summary{cursor:pointer;color:var(--accent);font-size:13.5px;margin-top:6px}
"""


def _h(s):
    return html.escape("" if s is None else str(s), quote=True)


def svg_chart(R):
    S = R["series"]
    pts = S["points"]
    if not pts:
        return ""
    W, H, L, B, T = 900, 200, 44, 26, 16
    n = len(pts)
    cap = [p[1] for p in pts] + ([S["base_avg"]] if S["base_avg"] else [])
    mx = max(cap + [1])
    bw = (W - L - 8) / float(n)
    ph = H - B - T
    parts = ['<svg viewBox="0 0 %d %d" width="100%%" role="img" aria-label="Events per minute">' % (W, H)]
    for frac in (0, 0.5, 1):
        y = T + ph * (1 - frac)
        parts.append('<text class="ax" x="%d" y="%.1f" text-anchor="end">%s</text>' % (L - 6, y + 4, "{:,}".format(int(mx * frac))))
    for i, (t, tot, err) in enumerate(pts):
        x = L + i * bw
        ht, he = ph * tot / mx, ph * err / mx
        tip = "%s - %s events, %s errors" % (t.strftime("%H:%M"), "{:,}".format(tot), "{:,}".format(err))
        parts.append('<g><title>%s</title><rect class="tot" x="%.1f" y="%.1f" width="%.1f" height="%.1f"/>'
                     '<rect class="err" x="%.1f" y="%.1f" width="%.1f" height="%.1f"/></g>'
                     % (_h(tip), x, T + ph - ht, max(bw - 1, 1), ht, x, T + ph - he, max(bw - 1, 1), he))
    k = max(1, int(math.ceil(n / 8.0)))
    for i in range(0, n, k):
        parts.append('<text class="ax" x="%.1f" y="%d" text-anchor="middle">%s</text>' % (L + i * bw + bw / 2, H - 8, pts[i][0].strftime("%H:%M")))
    if S["base_avg"]:
        y = T + ph * (1 - S["base_avg"] / mx)
        parts.append('<line class="base" x1="%d" x2="%d" y1="%.1f" y2="%.1f"/>' % (L, W - 8, y, y))
    off = (R["incident"] - pts[0][0]).total_seconds() / 60.0 / S["step"]
    xi = L + off * bw
    parts.append('<line class="inc" x1="%.1f" x2="%.1f" y1="%d" y2="%d"/>' % (xi, xi, T - 4, T + ph))
    parts.append('<text class="inct" x="%.1f" y="%d" text-anchor="%s">reported</text>' % (xi + 4, T + 6, "start" if off < n * 0.8 else "end"))
    parts.append("</svg>")
    return "".join(parts)


def render_html(R):
    multi = R["window"][0].date() != R["window"][1].date()
    v = R["verdict"]
    P = []
    a = P.append
    a('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    a("<title>Incident Analysis Report</title><style>%s</style></head><body><div class=\"wrap\">" % CSS)
    a('<div class="eyebrow">Splunk Log Analyzer &middot; offline incident report</div>')
    a("<h1>What went wrong at %s?</h1>" % _h(R["incident"].strftime("%H:%M on %d %b %Y")))
    a('<p class="sub">Reported problem: &ldquo;%s&rdquo;</p>' % _h(R["reason"]))
    a('<div class="meta">')
    a("<div><span>Analysis window</span>%s &rarr; %s</div>" % (_h(fmt_hms(R["window"][0], True)), _h(fmt_hms(R["window"][1], True))))
    a("<div><span>Normal period compared</span>%s</div>" % (_h("%s -> %s" % (fmt_hms(R["baseline"][0], True), fmt_hms(R["baseline"][1], True))) if R["baseline"] else "none available"))
    a("<div><span>Events analysed</span>%s in window &middot; %s before</div>" % ("{:,}".format(R["counts"]["window_events"]), "{:,}".format(R["counts"]["baseline_events"])))
    a("<div><span>Files</span>%s</div>" % _h(", ".join(f["name"] for f in R["files"])))
    a("</div>")

    a('<section class="verdict c-%s"><span class="badge">%s confidence</span>' % (_h(v["confidence"]), _h(v["confidence"].upper())))
    a('<p class="headline">%s</p>' % _h(v["headline"]))
    if v["why"]:
        a('<ul class="why">%s</ul>' % "".join("<li>%s</li>" % _h(w) for w in v["why"]))
    a("</section>")

    a('<section><h2>What happened, in simple terms</h2><ol class="story">%s</ol></section>' % "".join("<li>%s</li>" % _h(s) for s in R["story"]))
    a('<section><h2>What to check next</h2><ol>%s</ol></section>' % "".join("<li>%s</li>" % _h(s) for s in R["next_steps"]))

    a('<section><h2>Activity around the incident</h2><div class="chart">%s</div><div class="legend"><span class="sw" style="background:var(--bar)"></span>all events'
      '<span class="sw" style="background:var(--barerr)"></span>errors<span class="sw" style="background:var(--accent)"></span>reported time'
      '%s &middot; one bar = %d min</div></section>'
      % (svg_chart(R), ' <span class="sw" style="border-top:2px dashed var(--muted);height:0"></span>normal level' if R["series"]["base_avg"] else "", R["series"]["step"]))

    a('<section><h2>Timeline</h2><div class="tw"><table><tr><th>Time</th><th>Host</th><th>Event</th></tr>')
    for it in R["timeline"]:
        a('<tr class="k-%s"><td class="t">%s</td><td>%s</td><td>%s%s</td></tr>' % (
            _h(it["kind"]), _h(fmt_hms(it["ts"], multi)), _h(it["host"]), _h(it["text"]),
            ('<div class="ref">%s</div>' % _h(it["ref"])) if it["ref"] else ""))
    a("</table></div></section>")

    a("<section><h2>Evidence</h2>")
    if not R["findings"]:
        a("<p>No known failure pattern was new or unusual in this window.</p>")
    for i, f in enumerate(R["findings"][:10], 1):
        a('<article class="finding f-%s"><div class="fhead"><span class="rank">#%d</span><h3>%s</h3>'
          '<span class="pill s-%s">%s</span><span class="pill st-%s">%s</span>%s</div>'
          % (_h(f["sev"]), i, _h(f["title"]), _h(f["sev"]), _h(f["sev"]), _h(f["status"]), _h(f["status"]),
             '<span class="pill">symptom</span>' if f.get("symptom") else ""))
        if f.get("count_label"):
            cnt = _h(f["count_label"])
        else:
            cnt = "%sx in window (%s before / %s after the reported time) &middot; %sx in the %d min before" % (
                "{:,}".format(f["count"]), "{:,}".format(f["before"]), "{:,}".format(f["after"]),
                "{:,}".format(f["base_count"]), int(round(R["base_min"])))
        hosts = ", ".join("%s (%s)" % (h, "{:,}".format(c)) for h, c in f["hosts"][:4])
        a('<div class="facts">%s &middot; first %s (%s) &middot; last %s%s</div>'
          % (cnt, _h(fmt_hms(f["first"], multi)), _h(rel_phrase(f["first"], R["incident"])),
             _h(fmt_hms(f["last"], multi)), (" &middot; " + _h(hosts)) if hosts else ""))
        if f.get("also"):
            a('<div class="facts">Same lines also match: %s</div>' % _h("; ".join(f["also"])))
        a("<p><b>What it means:</b> %s</p><p><b>What to check:</b> %s</p>" % (_h(f["meaning"]), _h(f["check"])))
        for ev in f["evidence"]:
            meta = " &middot; ".join(x for x in (_h(ev["ref"]), _h(ev["file"]), _h(fmt_hms(ev["ts"], multi)), _h(ev["host"])) if x)
            a('<div class="ev"><div class="evmeta">%s</div><pre>%s</pre></div>' % (meta, _h(ev["text"])))
        a("</article>")
    a("</section>")

    if R["silences"]:
        a("<section><h2>Log silences</h2><p class=\"sub\">When a server stops writing logs, it was usually down, frozen or restarting.</p>")
        for s in R["silences"]:
            kind = {"gap": "No logs", "tail": "Stopped logging (never resumed in window)", "eod": "Log data ends"}[s["kind"]]
            a('<article class="finding f-high"><div class="fhead"><h3>%s on %s: %s &rarr; %s (%s)</h3></div>'
              % (_h(kind), _h(s["host"]), _h(fmt_hms(s["start"], multi)), _h(fmt_hms(s["end"], multi)), _h(fmt_dur(s["dur"]))))
            if s["basis"]:
                a('<div class="facts">Normally %s.</div>' % _h(s["basis"]))
            if s["before"]:
                a('<div class="ev"><div class="evmeta">last lines before the silence</div><pre>%s</pre></div>'
                  % _h("\n".join("[%s] %s" % (b[1], b[3]) for b in s["before"])))
            if s["after"]:
                a('<div class="ev"><div class="evmeta">first lines after</div><pre>%s</pre></div>'
                  % _h("\n".join("[%s] %s" % (x[1], x[3]) for x in s["after"])))
            a("</article>")
        a("</section>")

    if R["unrecognized"]:
        a('<section><h2>Other unusual errors</h2><p class="sub">New or spiking errors that did not match a known pattern.</p><div class="tw"><table>'
          "<tr><th>Status</th><th>Count</th><th>Before</th><th>First</th><th>Error pattern / example</th></tr>")
        for u in R["unrecognized"]:
            ex = u["evidence"][0] if u["evidence"] else None
            a('<tr><td class="st-%s"><b>%s</b></td><td>%s</td><td>%s</td><td class="t">%s</td><td>%s%s</td></tr>' % (
                _h(u["status"]), _h(u["status"]), "{:,}".format(u["count"]), "{:,}".format(u["base_count"]),
                _h(fmt_hms(u["first"], multi)), _h(u["template"]),
                ('<details><summary>%s (%s)</summary><pre>%s</pre></details>' % (_h(ex["ref"]), _h(ex["file"]), _h(ex["text"]))) if ex else ""))
        a("</table></div></section>")

    tr = R["traffic"]
    if tr:
        a("<section><h2>Web traffic</h2><div class=\"meta\">")
        a("<div><span>Requests in window</span>%s</div>" % "{:,}".format(tr["win_requests"]))
        a("<div><span>Peak</span>%s/min at %s</div>" % ("{:,}".format(tr["peak"]), _h(fmt_hms(tr["peak_time"], multi))))
        a("<div><span>Normal rate</span>%s</div>" % (("%.0f/min" % tr["base_rate"]) if tr["base_rate"] else "n/a"))
        a("<div><span>Server errors (5xx)</span>%.1f%% now vs %s before</div>" % (tr["err_win"] * 100, ("%.1f%%" % (tr["err_base"] * 100)) if tr["err_base"] is not None else "n/a"))
        a("</div>")
        if tr["top_ips"]:
            a('<div class="tw" style="margin-top:12px"><table><tr><th>Client IP</th><th>Requests</th><th>Share now</th><th>Share before</th></tr>')
            for ip, c, sh, bsh in tr["top_ips"]:
                a("<tr><td class=\"t\">%s</td><td>%s</td><td>%.1f%%</td><td>%s</td></tr>" % (_h(ip), "{:,}".format(c), sh * 100, ("%.1f%%" % (bsh * 100)) if bsh is not None else "n/a"))
            a("</table></div>")
        a('<div class="facts" style="margin-top:10px">Status codes in window: %s</div></section>' % _h(", ".join("%d: %s" % (k, "{:,}".format(c)) for k, c in tr["status"])))

    if R["noise"] or R["recurring"]:
        a('<section><h2>Background noise</h2><p class="sub">These also happen at a similar rate before the problem, so they are probably not the cause.</p><div class="tw"><table>'
          "<tr><th>Error</th><th>In window</th><th>Before</th></tr>")
        for f in R["noise"][:8]:
            a("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (_h(f["title"]), "{:,}".format(f["count"]), "{:,}".format(f["base_count"])))
        for u in R["recurring"]:
            a("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (_h(u["template"]), "{:,}".format(u["count"]), "{:,}".format(u["base_count"])))
        a("</table></div></section>")

    if R["hosts"]:
        a('<section><h2>Hosts / sources</h2><div class="tw"><table><tr><th>Host</th><th>Events (window)</th><th>Errors (window)</th><th>Events (before)</th><th>Errors (before)</th><th>Last log seen</th></tr>')
        for h in R["hosts"]:
            a("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"t\">%s</td></tr>" % (
                _h(h["host"]), "{:,}".format(h["win_events"]), "{:,}".format(h["win_problems"]),
                "{:,}".format(h["base_events"]), "{:,}".format(h["base_problems"]), _h(fmt_hms(h["last_seen"], True))))
        a("</table></div></section>")

    a('<section><h2>Data gaps &amp; limits</h2><ul class="gaps">%s</ul></section>' % "".join("<li>%s</li>" % _h(g) for g in (R["data_gaps"] or ["None noticed."])))

    a('<section><h2>Files analysed</h2><div class="tw"><table><tr><th>File</th><th>Format</th><th>Events</th><th>No timestamp</th><th>Covers</th></tr>')
    for f in R["files"]:
        a("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"t\">%s &rarr; %s</td></tr>" % (
            _h(f["name"]), _h(f["format"]), "{:,}".format(f["events"]), "{:,}".format(f["no_ts"]),
            _h(fmt_full(f["first"])), _h(fmt_full(f["last"]))))
    a("</table></div></section>")
    a("<footer>Generated %s by %s on this machine &middot; no data was sent anywhere &middot; secrets in evidence are masked</footer>" % (_h(R["generated"]), _h(R["tool"])))
    a("</div></body></html>")
    return "".join(P)


# ============================================================================
# 9. COMMAND LINE
# ============================================================================
def expand_paths(items):
    found, missing = [], []
    for it in items:
        p = os.path.expanduser(it.strip().strip('"').strip("'"))
        if any(c in p for c in "*?["):
            hits = sorted(x for x in glob.glob(p) if os.path.isfile(x))
            (found.extend(hits) if hits else missing.append(it))
        elif os.path.isdir(p):
            found.extend(sorted(os.path.join(p, n) for n in os.listdir(p) if os.path.isfile(os.path.join(p, n))))
        elif os.path.isfile(p):
            found.append(p)
        else:
            missing.append(it)
    return found, missing


def _ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        print("\nNo input - exiting. Run with -h for options.")
        sys.exit(2)


def interactive_fill(args):
    print("Splunk Log Analyzer - answer 3 quick questions (Ctrl+C to quit)\n")
    if not args.file:
        while True:
            p = _ask("1) Log file path (drag & drop the file here; several files separated by spaces): ")
            parts = re.findall(r'"[^"]+"|\'[^\']+\'|\S+', p)
            found, missing = expand_paths(parts)
            if found and not missing:
                args.file = parts
                break
            print("   Not found: %s - try again." % ", ".join(missing or [p]))
    if not args.time:
        while True:
            t = _ask('2) When did the problem happen? e.g. "2026-10-09 14:30" or "today 2:30 PM": ')
            if parse_user_time(t, args.dayfirst):
                args.time = t
                break
            print("   Could not understand that date/time - please include the date, e.g. 2026-10-09 14:30")
    if not args.reason:
        args.reason = _ask("3) What went wrong, in your words? (e.g. server crashed, site down, very slow, logins failing): ") or "unspecified problem"
    b = _ask("   Minutes to look back before that time [%d]: " % args.before)
    if b:
        try:
            args.before = float(b)
        except ValueError:
            pass
    print("")


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except Exception:
            pass
    if os.name == "nt":
        os.system("")  # enables ANSI colours on Windows 10+

    ap = argparse.ArgumentParser(
        prog="splunk_log_analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Offline incident analyzer for Splunk exports and server logs. Explains what went wrong, with evidence.",
        epilog='Example:\n  python splunk_log_analyzer.py -f export.csv -t "2026-10-09 14:30" -r "server went down"\n'
               "Run with no arguments to be asked questions interactively.")
    ap.add_argument("-f", "--file", nargs="+", help="log file(s), folder or wildcard (.log .txt .csv .json .gz)")
    ap.add_argument("-t", "--time", help='when the problem happened, e.g. "2026-10-09 14:30"')
    ap.add_argument("-r", "--reason", help='what went wrong in plain words, e.g. "server crashed"')
    ap.add_argument("--before", type=float, default=30, help="minutes before the time to analyse (default 30)")
    ap.add_argument("--after", type=float, default=15, help="minutes after the time to analyse (default 15)")
    ap.add_argument("--baseline", type=float, default=60, help="minutes of 'normal' data before the window to compare with (default 60)")
    ap.add_argument("--gap", type=float, default=60, help="minimum seconds of no logs to call a silence (default 60)")
    ap.add_argument("--tz", help="timezone of the time you typed, e.g. +05:30, UTC, IST, local. Logs with offsets are converted to it")
    ap.add_argument("--dayfirst", action="store_true", help="read 09/10/2026 as 9 Oct (default: month first, Splunk style)")
    ap.add_argument("-o", "--out", help="HTML report path (default: incident_report_<date>_<time>.html)")
    ap.add_argument("--no-html", action="store_true", help="terminal output only")
    ap.add_argument("--json", help="also save the findings as JSON to this path")
    ap.add_argument("--redact", action="store_true", help="mask emails, phone/SSN-like numbers and long IDs in evidence")
    ap.add_argument("--max-evidence", type=int, default=3, help="evidence lines shown per finding (default 3)")
    ap.add_argument("--open", action="store_true", help="open the HTML report in your browser when done")
    ap.add_argument("--no-color", action="store_true", help="disable coloured terminal output")
    ap.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = ap.parse_args(argv)

    asked = False
    if not (args.file and args.time and args.reason):
        asked = True
        try:
            interactive_fill(args)
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 130

    files, missing = expand_paths(args.file)
    for m in missing:
        print("! File not found: %s" % m, file=sys.stderr)
    if not files:
        print("No readable log files given.", file=sys.stderr)
        return 2
    ut = parse_user_time(args.time, args.dayfirst)
    if ut is None:
        print('Could not understand the time "%s". Use e.g. "2026-10-09 14:30".' % args.time, file=sys.stderr)
        return 2
    incident, typed_off = ut
    try:
        target = parse_tz(args.tz) if args.tz else typed_off
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    an = Analyzer(incident, args.reason, args.before, args.after, args.baseline, args.gap,
                  args.dayfirst, target, args.redact, max(1, args.max_evidence))
    t0 = time.time()
    for f in files:
        sys.stderr.write("Reading %s ...\n" % f)
        try:
            an.feed(f)
        except (IOError, OSError) as e:
            print("! Could not read %s: %s" % (f, e), file=sys.stderr)
        except Exception as e:  # keep going with other files
            print("! Problem parsing %s (%s): %s - continuing" % (f, type(e).__name__, e), file=sys.stderr)
    R = an.report()
    R["elapsed"] = round(time.time() - t0, 2)

    paint = Paint(sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR"))
    width = shutil.get_terminal_size((100, 20)).columns
    print(render_text(R, paint, width))

    if not args.no_html:
        out = args.out or "incident_report_%s.html" % incident.strftime("%Y%m%d_%H%M")
        try:
            with io.open(out, "w", encoding="utf-8") as fh:
                fh.write(render_html(R))
            print("HTML report : %s" % os.path.abspath(out))
            if args.open:
                webbrowser.open("file://" + os.path.abspath(out))
        except (IOError, OSError) as e:
            print("! Could not write HTML report: %s" % e, file=sys.stderr)
    if args.json:
        with io.open(args.json, "w", encoding="utf-8") as fh:
            json.dump(R, fh, default=str, indent=2, ensure_ascii=False)
        print("JSON        : %s" % os.path.abspath(args.json))
    print("Done in %.1fs - nothing left this machine." % R["elapsed"])
    if asked and os.name == "nt" and sys.stdin.isatty():
        _ask("\nPress Enter to close...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
