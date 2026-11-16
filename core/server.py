"""Zero-dependency web server for the ShadowNet dashboard.

Routes
------
``GET  /``              static dashboard files from ``web/``
``GET  /api/report``    latest threat report as JSON
``POST /api/simulate``  generate a new attack wave, re-analyse, return the report
                        (in live mode: just re-analyse the real logs)
"""

import json
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import detector, simulator

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "web"
LOG_FILE = ROOT / "data" / "access.log"
AUTH_FILE = ROOT / "data" / "auth.log"


class Engine:
    """Thread-safe pipeline holder.

    * **Simulated mode** (default): ``refresh()`` regenerates sample logs.
    * **Live mode** (real log paths given): files are never written; they are
      re-analysed whenever they change on disk, so the dashboard tracks them.
    """

    def __init__(self, access_log=None, auth_log=None):
        self.live = bool(access_log or auth_log)
        self.access_log = Path(access_log) if access_log else (None if self.live else LOG_FILE)
        self.auth_log = Path(auth_log) if auth_log else (None if self.live else AUTH_FILE)
        self._lock = threading.Lock()
        self._stamp = None
        self.report = {}

    def _fingerprint(self):
        """(mtime, size) of every source file - changes when new lines arrive."""
        stats = [p.stat() for p in (self.access_log, self.auth_log) if p and p.exists()]
        return [(s.st_mtime_ns, s.st_size) for s in stats]

    def _analyze(self):
        self.report = detector.analyze_file(self.access_log, self.auth_log)
        self.report["mode"] = "live" if self.live else "simulated"
        self.report["sources"] = [str(p) for p in (self.access_log, self.auth_log) if p]
        self._stamp = self._fingerprint()
        return self.report

    def refresh(self, seed=None):
        """Simulated mode: generate a new attack wave. Then (re)run detection."""
        with self._lock:
            if not self.live:
                simulator.generate_logs(self.access_log, self.auth_log, seed)
            return self._analyze()

    def current(self):
        """Latest report; in live mode, re-analyse first if the logs changed."""
        with self._lock:
            if self.live and self._fingerprint() != self._stamp:
                self._analyze()
            return self.report


class Handler(SimpleHTTPRequestHandler):
    """Serves static assets plus the small JSON API."""

    def __init__(self, *args, engine, **kwargs):
        self.engine = engine
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def _json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")  # always serve fresh data/assets
        super().end_headers()

    def do_GET(self):
        route = self.path.split("?")[0]
        if route == "/api/report":
            self._json(self.engine.current())
        elif route.startswith("/api/"):
            self._json({"error": "not found"}, 404)
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.split("?")[0] == "/api/simulate":
            self._json(self.engine.refresh())
        else:
            self._json({"error": "not found"}, 404)

    def log_message(self, *args):
        """Keep the console quiet; ShadowNet prints its own status lines."""


def create_server(engine, host="127.0.0.1", port=8080):
    """Build (but do not start) the threaded HTTP server."""
    return ThreadingHTTPServer((host, port), partial(Handler, engine=engine))
