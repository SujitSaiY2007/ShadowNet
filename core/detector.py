"""Threat analysis engine.

Three complementary detection techniques run over every parsed log line:

1. **Signature matching** - compiled regular expressions for SQL injection,
   directory traversal and reconnaissance probes.
2. **Shannon entropy** - long, high-entropy query strings indicate encoded or
   obfuscated payloads that signatures cannot see.
3. **Sliding time windows** - per-IP ``collections.deque`` counters catch
   brute-force login storms and DDoS request floods by *rate*, not content.

Both web access logs (Common/Combined Log Format) and sshd authentication logs
(``auth.log`` / ``secure``) are supported, simulated or real.

The result is a JSON-serialisable report consumed by the dashboard.
"""

import math
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import unquote_plus

# --- Tunable thresholds -------------------------------------------------------
BRUTE_WINDOW, BRUTE_LIMIT = 60, 10    # failed logins per IP per 60 s
DDOS_WINDOW, DDOS_LIMIT = 5, 30       # requests per IP per 5 s
SSH_WINDOW, SSH_LIMIT = 60, 8         # failed SSH logins per IP per 60 s
MAX_LINES = 200_000                   # only the newest lines of each file are analysed
TIMELINE_POINTS = 180                 # timeline buckets widen to cover long real logs
ENTROPY_MIN_LEN, ENTROPY_LIMIT = 40, 4.5
BUCKET_SECONDS = 10                   # minimum timeline resolution

SEVERITY = {
    "SQL Injection": "critical",
    "SSH Compromise": "critical",
    "SSH Brute Force": "high",
    "DDoS Burst": "critical",
    "Brute Force": "high",
    "Directory Traversal": "high",
    "Obfuscated Payload": "medium",
    "Recon Probe": "low",
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

CLF_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\d+|-)'
)
# Signatures are evaluated in order against the URL-decoded request path.
SIGNATURES = [
    ("SQL Injection", re.compile(
        r"union\s+select|\bor\s+1\s*=\s*1|'\s*or\s*'|sleep\s*\(|benchmark\s*\(|drop\s+table"
        r"|information_schema|xp_cmdshell|'\s*--", re.I)),
    ("Directory Traversal", re.compile(
        r"\.\.[/\\]|\.\.\.\.//|/etc/(passwd|shadow)|win\.ini|boot\.ini|/bin/sh", re.I)),
    ("Recon Probe", re.compile(
        r"/\.env|/\.git/|/wp-admin|/wp-login\.php|/phpmyadmin|/\.aws/|/server-status"
        r"|\.php\.bak|/admin\.php|/backup\.sql", re.I)),
]
# sshd lines from auth.log / secure, classic ("Nov  6 10:00:00") or ISO timestamps.
SSH_RE = re.compile(
    r'^(?P<ts>[A-Z][a-z]{2}\s+\d+\s[\d:]{8}|\d{4}-\S+)\s+\S+\s+sshd(?:\[\d+\])?:\s+'
    r'(?P<result>Failed|Accepted)\s+\S+\s+for\s+(?P<invalid>invalid user\s+)?(?P<user>\S+)'
    r'\s+from\s+(?P<ip>\S+)'
)
LOGIN_RE = re.compile(r"^/(login|signin|wp-login\.php|admin/login)", re.I)


def shannon_entropy(text):
    """Return the Shannon entropy of *text* in bits per character."""
    if not text:
        return 0.0
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in Counter(text).values())


def parse_line(line):
    """Parse one CLF line into a dict, or ``None`` if it is malformed."""
    match = CLF_RE.match(line)
    if not match:
        return None
    rec = match.groupdict()
    try:
        rec["epoch"] = int(datetime.strptime(rec["ts"], "%d/%b/%Y:%H:%M:%S %z").timestamp())
    except ValueError:
        return None
    rec["status"] = int(rec["status"])
    rec["source"] = "web"
    return rec


def parse_ssh_line(line):
    """Parse one sshd authentication line into the common record shape."""
    match = SSH_RE.match(line)
    if not match:
        return None
    stamp = match["ts"]
    try:
        if stamp[0].isdigit():
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        else:  # classic syslog has no year: assume the current one, in local time
            now = datetime.now()
            when = datetime.strptime(f"{now.year} {stamp}", "%Y %b %d %H:%M:%S")
            if (when - now).days >= 1:
                when = when.replace(year=now.year - 1)
        epoch = int(when.timestamp())
    except ValueError:
        return None
    failed = match["result"] == "Failed"
    return {"ip": match["ip"], "user": match["user"], "epoch": epoch, "method": "SSH",
            "path": f'{match["result"]} login for {match["invalid"] or ""}{match["user"]}',
            "status": 401 if failed else 200, "source": "ssh"}


def _signature(rec):
    """Content-based classification: returns ``(attack_type, detail)`` or ``None``."""
    decoded = unquote_plus(unquote_plus(rec["path"]))  # twice: defeats double-encoding
    for name, pattern in SIGNATURES:
        hit = pattern.search(decoded)
        if hit:
            return name, f"Signature match: “{hit.group(0)}”"
    query = decoded.partition("?")[2]
    if len(query) >= ENTROPY_MIN_LEN:
        entropy = shannon_entropy(query)
        if entropy >= ENTROPY_LIMIT:
            return "Obfuscated Payload", f"Query entropy {entropy:.2f} bits/char ({len(query)} chars)"
    return None


def analyze(lines=(), ssh_lines=()):
    """Analyse raw web access lines and sshd lines; return the threat report dict."""
    records = [rec for rec in map(parse_line, lines) if rec]
    records += [rec for rec in map(parse_ssh_line, ssh_lines) if rec]
    records.sort(key=lambda rec: rec["epoch"])
    flags = [None] * len(records)                 # attack type per record, if any
    details = {}                                  # (ip, type) -> human readable evidence
    login_fail = defaultdict(deque)               # ip -> deque[(epoch, index)]
    ssh_fail = defaultdict(deque)                 # ip -> deque[(epoch, index)]
    recent = defaultdict(deque)                   # ip -> deque[(epoch, index)]
    per_second = Counter()

    def rate_check(window, idx, rec, span, limit, name, what):
        """Slide the per-IP window; when it overflows, flag every request in it."""
        window.append((rec["epoch"], idx))
        while window[0][0] <= rec["epoch"] - span:
            window.popleft()
        if len(window) >= limit:
            for _, i in window:
                flags[i] = flags[i] or name
            key = (rec["ip"], name)
            peak = max(len(window), details.get(key, (0, ""))[0])
            details[key] = (peak, f"Rate anomaly: {peak} {what} in {span}s (limit {limit})")

    for idx, rec in enumerate(records):
        per_second[rec["epoch"]] += 1
        if rec["source"] == "ssh":
            brute = (rec["ip"], "SSH Brute Force")
            if rec["status"] == 401:
                rate_check(ssh_fail[rec["ip"]], idx, rec, SSH_WINDOW, SSH_LIMIT,
                           "SSH Brute Force", "failed SSH logins")
            elif brute in details:  # a success right after a storm = likely breach
                flags[idx] = "SSH Compromise"
                details[(rec["ip"], "SSH Compromise")] = (
                    0, f"Successful login as “{rec['user']}” after a brute-force attack")
            continue
        sig = _signature(rec)
        if sig:
            flags[idx] = sig[0]
            details.setdefault((rec["ip"], sig[0]), (0, sig[1]))
        if LOGIN_RE.match(rec["path"]) and rec["status"] in (401, 403):
            rate_check(login_fail[rec["ip"]], idx, rec, BRUTE_WINDOW, BRUTE_LIMIT,
                       "Brute Force", "failed logins")
        rate_check(recent[rec["ip"]], idx, rec, DDOS_WINDOW, DDOS_LIMIT,
                   "DDoS Burst", "requests")

    # --- Aggregate flagged requests into one alert per (source IP, attack type) --
    alerts, buckets = {}, defaultdict(lambda: [0, 0])
    start = records[0]["epoch"] if records else 0
    end = records[-1]["epoch"] if records else 0
    bucket = max(BUCKET_SECONDS, -(-(end - start) // TIMELINE_POINTS))
    for rec, kind in zip(records, flags):
        buckets[(rec["epoch"] - start) // bucket][1 if kind else 0] += 1
        if not kind:
            continue
        alert = alerts.setdefault((rec["ip"], kind), {
            "ip": rec["ip"], "type": kind, "severity": SEVERITY[kind], "count": 0,
            "first_seen": rec["epoch"], "sample": f'{rec["method"]} {rec["path"]}'[:160],
            "detail": details.get((rec["ip"], kind), (0, "Flagged by engine"))[1],
        })
        alert["count"] += 1
        alert["last_seen"] = rec["epoch"]

    alert_list = sorted(alerts.values(),
                        key=lambda a: (SEVERITY_RANK[a["severity"]], -a["count"]))
    for number, alert in enumerate(alert_list, 1):
        alert["id"] = f"SN-{number:04d}"

    attackers = defaultdict(lambda: {"hits": 0, "types": []})
    for alert in alert_list:
        entry = attackers[alert["ip"]]
        entry["hits"] += alert["count"]
        entry["types"].append(alert["type"])
    top = sorted(({"ip": ip, **data} for ip, data in attackers.items()),
                 key=lambda a: -a["hits"])[:8]

    blocked = sum(1 for kind in flags if kind)
    n_buckets = (end - start) // bucket + 1 if records else 0
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "total_requests": len(records),
            "ssh_events": sum(1 for rec in records if rec["source"] == "ssh"),
            "blocked_threats": blocked,
            "critical_ips": len({a["ip"] for a in alert_list if a["severity"] == "critical"}),
            "peak_rps": max(per_second.values(), default=0),
            "unique_ips": len({rec["ip"] for rec in records}),
            "threat_ratio": round(blocked / len(records) * 100, 1) if records else 0.0,
            "alert_count": len(alert_list),
            "window_start": start,
            "window_end": end,
        },
        "by_type": dict(Counter(kind for kind in flags if kind).most_common()),
        "by_severity": dict(Counter(a["severity"] for a in alert_list)),
        "timeline": {
            "bucket_seconds": bucket,
            "start": start,
            "normal": [buckets[i][0] for i in range(n_buckets)],
            "malicious": [buckets[i][1] for i in range(n_buckets)],
        },
        "top_attackers": top,
        "alerts": alert_list,
    }


def _tail(path):
    """Return the newest ``MAX_LINES`` lines of *path* (empty if no path given)."""
    if not path:
        return ()
    with open(path, encoding="utf-8", errors="replace") as handle:
        return deque(handle, maxlen=MAX_LINES)


def analyze_file(path=None, auth_path=None):
    """Analyse a web access log and/or an sshd auth log; return the threat report."""
    return analyze(_tail(path), _tail(auth_path))
