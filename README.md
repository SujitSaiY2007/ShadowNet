# ShadowNet

**Zero-dependency Network Intrusion & Log Forensics Engine** with a browser-based
Security Operations Center (SOC) dashboard.

ShadowNet generates realistic web-server access logs with injected attacks, runs a
threat-detection engine over them, and visualises the result — using nothing but the
Python standard library and vanilla HTML/CSS/JavaScript. No `pip`, no `npm`, no CDNs.

## Quick start

```bash
python run.py
```

That single command:

1. generates ~3,000 web access log lines (`data/access.log`) and an sshd log
   (`data/auth.log`) with injected attacks,
2. runs the detection engine and builds a JSON threat report,
3. starts a local server at <http://localhost:8080>,
4. opens the dashboard in your default browser.

Requires **Python 3.9+**.

### Live mode — monitor real logs

```bash
python run.py --log /var/log/nginx/access.log --auth-log /var/log/auth.log
```

Pass either flag or both. ShadowNet only *reads* these files, re-analyses them whenever
they change, and the dashboard refreshes itself every 3 seconds. Web logs may be in
Common or Combined Log Format (Apache/Nginx defaults); SSH logs are standard sshd
`auth.log` / `secure` lines with classic or ISO timestamps. Only the newest 200,000
lines of each file are analysed, and the timeline widens its buckets to fit long logs.
 Options: `--port 9000` to change the port, `--no-browser` to
skip opening a tab. Stop with `Ctrl+C`.

## Architecture

```
                 ┌──────────────────────── run.py ────────────────────────┐
                 │                  (orchestrator)                        │
                 └───────────────────────────┬────────────────────────────┘
                                             ▼
┌───────────────────┐  access.log  ┌───────────────────┐  report   ┌──────────────────┐
│ core/simulator.py │ ───────────▶ │ core/detector.py  │ ────────▶ │  core/server.py  │
│ traffic + attacks │              │ regex · entropy · │   (JSON)  │ ThreadingHTTP-   │
│ (CLF log lines)   │              │ sliding windows   │           │ Server :8080     │
└───────────────────┘              └───────────────────┘           └────────┬─────────┘
          ▲                                                                 │
          │        POST /api/simulate                  GET /api/report      ▼
          └──────────────────────────────────────────────────────  web/ (index.html,
                                                                   styles.css, app.js)
```

```
ShadowNet/
├── run.py              # single-command launcher
├── core/
│   ├── simulator.py    # traffic & attack generator
│   ├── detector.py     # threat analysis engine
│   └── server.py       # static file server + JSON API
└── web/
    ├── index.html      # SOC dashboard layout
    ├── styles.css      # dark theme (CSS Grid / Flexbox)
    └── app.js          # fetch client, filters, HTML5 Canvas chart
```

## Detection techniques

| Attack type         | Severity | How it is detected                                                        |
|---------------------|----------|---------------------------------------------------------------------------|
| SQL Injection       | critical | Compiled regex signatures on the URL-decoded request (`UNION SELECT`, `OR 1=1`, …) |
| DDoS Burst          | critical | Sliding window (`collections.deque`): ≥ 30 requests from one IP in 5 s    |
| SSH Compromise      | critical | A *successful* SSH login from an IP that was just brute-forcing            |
| SSH Brute Force     | high     | Sliding window: ≥ 8 failed sshd logins from one IP in 60 s                |
| Brute Force         | high     | Sliding window: ≥ 10 failed logins (401/403) from one IP in 60 s          |
| Directory Traversal | high     | Regex signatures (`../`, `%2e%2e`, `/etc/passwd`, …), double-decoded      |
| Obfuscated Payload  | medium   | Shannon entropy ≥ 4.5 bits/char on query strings of 40+ characters        |
| Recon Probe         | low      | Regex signatures for sensitive paths (`/.env`, `/.git/`, `/wp-admin`, …)  |

Flagged requests are aggregated into one alert per *(source IP, attack type)*.
Thresholds are constants at the top of `core/detector.py`.

## Dashboard

- **KPI cards** — Total Requests, Blocked Threats, Critical IPs, Peak RPS.
- **Traffic timeline** — HTML5 Canvas chart of normal vs. malicious requests per
  10-second bucket, with hover crosshair and a linear/sqrt scale toggle.
- **Attack vectors & top attackers** — click a vector or IP to filter the table.
- **Threat alerts table** — filter by severity chips, attack type, or free-text search.
- **Simulate Attack Wave** — regenerates logs, re-runs detection, updates the UI live.

## API

| Method | Route           | Description                                             |
|--------|-----------------|---------------------------------------------------------|
| GET    | `/api/report`   | Latest threat report (summary, timeline, alerts) as JSON |
| POST   | `/api/simulate` | Generate a new attack wave, re-analyse, return the report |

## Notes

- Without `--log` / `--auth-log`, all data is **simulated**. In live mode the
  "Simulate" button becomes "Re-scan Logs" and nothing is ever written to your logs.
- The server binds to `127.0.0.1` only, and the dashboard renders log-derived strings as
  text (never HTML), so attack payloads cannot execute in the browser.

## License

See [LICENSE](LICENSE).
