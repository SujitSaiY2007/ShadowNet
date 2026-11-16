"""Traffic & attack generator.

Produces realistic web-server access logs in Common Log Format (CLF) and
injects six hostile behaviours into the benign background traffic:

* Brute-force login spikes        (rapid ``POST /login`` -> 401)
* SQL injection payloads          (``UNION SELECT``, ``' OR 1=1`` ...)
* Directory traversal attempts    (``../../etc/passwd`` ...)
* High-frequency DDoS bursts      (hundreds of requests in a few seconds)
* Obfuscated (high-entropy) query strings
* Reconnaissance probes           (``/.env``, ``/wp-admin`` ...)

It also writes an sshd ``auth.log`` containing SSH brute-force storms.

Only the Python standard library is used.
"""

import base64
import math
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

WINDOW_SECONDS = 30 * 60   # every generated log covers the last 30 minutes
NORMAL_REQUESTS = 2300     # benign background volume

NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/pricing", "/blog", "/blog/zero-trust-101",
    "/blog/log-forensics", "/products", "/products/42", "/products/7", "/cart", "/checkout",
    "/api/v1/items", "/api/v1/items?page=2", "/api/v1/users/me", "/search?q=firewall",
    "/search?q=vpn+router&sort=price", "/static/app.js", "/static/site.css",
    "/static/logo.png", "/favicon.ico", "/docs/getting-started", "/login", "/dashboard",
]
SQLI_PAYLOADS = [
    "' OR 1=1--", "' OR '1'='1", "1 UNION SELECT username,password FROM users--",
    "1; DROP TABLE sessions--", "admin'--", "1' AND SLEEP(5)--",
    "-1 UNION SELECT table_name,2 FROM information_schema.tables",
    "1' AND BENCHMARK(5000000,MD5(1))--", "'; EXEC xp_cmdshell('whoami')--",
]
TRAVERSAL_PATHS = [
    "/download?file=../../../../etc/passwd", "/static/../../../etc/shadow",
    "/view?page=..%2F..%2F..%2Fetc%2Fpasswd", "/img?src=....//....//etc/passwd",
    "/files/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/download?file=..\\..\\..\\windows\\win.ini",
    "/logs?name=../../../../var/log/auth.log", "/cgi-bin/.%2e/.%2e/.%2e/bin/sh",
]
RECON_PATHS = [
    "/.env", "/.git/config", "/wp-admin/", "/wp-login.php", "/phpmyadmin/index.php",
    "/.aws/credentials", "/server-status", "/config.php.bak", "/admin.php", "/backup.sql",
]


def _ip(rng, internal=False):
    """Return a random IPv4 address (private range when *internal*)."""
    if internal:
        return f"10.{rng.randint(0, 20)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
    first = rng.choice([23, 45, 62, 77, 91, 103, 141, 176, 185, 193, 198, 203, 212])
    return f"{first}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def _line(ts, ip, method, path, status, size, user="-"):
    """Format one Common Log Format line."""
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - {user} [{stamp}] "{method} {path} HTTP/1.1" {status} {size}'


def generate_events(seed=None):
    """Build a chronologically sorted list of ``(datetime, log_line)`` tuples."""
    rng = random.Random(seed)
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(seconds=WINDOW_SECONDS)
    at = lambda offset: start + timedelta(seconds=offset)
    events = []
    add = lambda ts, *fields, **kw: events.append((ts, _line(ts, *fields, **kw)))

    # --- Benign background traffic with a gentle sinusoidal rhythm -------------
    clients = [_ip(rng, internal=rng.random() < 0.25) for _ in range(160)]
    phase = rng.uniform(0, math.tau)
    made = 0
    while made < NORMAL_REQUESTS:
        offset = rng.uniform(0, WINDOW_SECONDS)
        if rng.random() > 0.65 + 0.35 * math.sin(phase + offset / WINDOW_SECONDS * math.tau * 2):
            continue  # rejection sampling shapes the traffic curve
        path = rng.choice(NORMAL_PATHS)
        if path == "/login":
            method, status = "POST", rng.choices([302, 401], [9, 1])[0]
        else:
            method = "GET"
            status = rng.choices([200, 304, 404, 500], [84, 10, 5, 1])[0]
        add(at(offset), rng.choice(clients), method, path, status, rng.randint(180, 48000))
        made += 1

    # --- Brute-force login spikes --------------------------------------------
    for _ in range(3):
        ip, t0 = _ip(rng), rng.uniform(60, WINDOW_SECONDS - 150)
        for i in range(rng.randint(90, 140)):
            user = rng.choice(["admin", "root", "test", "guest", "oracle", "deploy"])
            add(at(t0 + i * rng.uniform(0.4, 0.9)), ip, "POST", "/login", 401, 512, user=user)

    # --- High-frequency DDoS bursts ------------------------------------------
    for _ in range(3):
        ip, t0 = _ip(rng), rng.uniform(60, WINDOW_SECONDS - 60)
        target = rng.choice(["/", "/api/v1/items", "/search?q=a"])
        for _ in range(rng.randint(150, 240)):
            add(at(t0 + rng.uniform(0, 9)), ip, "GET", target, rng.choice([200, 200, 503]), 320)

    # --- Signature-based attacks, scattered across the window -----------------
    def scatter(n_ips, per_ip, make):
        for _ in range(n_ips):
            ip = _ip(rng)
            for _ in range(rng.randint(*per_ip)):
                method, path, status = make()
                add(at(rng.uniform(0, WINDOW_SECONDS)), ip, method, path, status,
                    rng.randint(200, 2400))

    scatter(8, (3, 8), lambda: ("GET", rng.choice(["/products?id=", "/search?q=", "/api/v1/users?id="])
                                + quote(rng.choice(SQLI_PAYLOADS)), rng.choice([200, 500, 403])))
    scatter(7, (3, 7), lambda: ("GET", rng.choice(TRAVERSAL_PATHS), rng.choice([400, 403, 404])))
    scatter(8, (2, 6), lambda: ("GET", rng.choice(RECON_PATHS), rng.choice([403, 404])))

    def obfuscated():
        blob = base64.b64encode(rng.randbytes(rng.randint(45, 90))).decode()
        return "GET", f"/api/v1/track?d={quote(blob, safe='')}", 200
    scatter(5, (2, 5), obfuscated)

    events.sort(key=lambda event: event[0])
    return events


def generate_ssh_events(seed=None):
    """Build sorted ``(datetime, line)`` tuples in sshd syslog format (ISO timestamps).

    Contains routine logins, stray typos, and brute-force storms - one of which
    ends in a *successful* login to exercise the compromise detector.
    """
    rng = random.Random(seed)
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(seconds=WINDOW_SECONDS)
    events = []

    def add(offset, ok, user, ip, invalid=False):
        ts = start + timedelta(seconds=offset)
        verb = "Accepted" if ok else "Failed"
        who = f"invalid user {user}" if invalid else user
        events.append((ts, f"{ts.isoformat()} web-01 sshd[{rng.randint(900, 32000)}]: "
                           f"{verb} password for {who} from {ip} port {rng.randint(1024, 65000)} ssh2"))

    staff = ["alice", "bob", "deploy", "carol"]
    for _ in range(40):  # routine activity, with the occasional typo
        add(rng.uniform(0, WINDOW_SECONDS), rng.random() > 0.12, rng.choice(staff), _ip(rng, True))
    for n in range(3):   # brute-force storms
        ip, t0 = _ip(rng), rng.uniform(60, WINDOW_SECONDS - 200)
        for _ in range(rng.randint(70, 120)):
            t0 += rng.uniform(0.3, 1.2)
            user = rng.choice(["root", "admin", "ubuntu", "pi", "oracle", "git", "test"])
            add(t0, False, user, ip, invalid=user not in ("root", "git"))
        if n == 0:       # ... the first one eventually guesses the password
            add(t0 + 2, True, "root", ip)
    events.sort(key=lambda event: event[0])
    return events


def _write(path, events):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(line for _, line in events) + "\n", encoding="utf-8")
    return len(events)


def generate_logs(path, auth_path=None, seed=None):
    """Write a simulated access log (and optional SSH auth log); return line count."""
    total = _write(path, generate_events(seed))
    if auth_path:
        total += _write(auth_path, generate_ssh_events(seed))
    return total
