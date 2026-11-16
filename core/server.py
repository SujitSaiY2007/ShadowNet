"""Zero-dependency web server for the ShadowNet dashboard.

Routes
------
``GET  /``              static dashboard files from ``web/``
``GET  /api/report``    latest threat report as JSON
``POST /api/simulate``  generate a new attack wave, re-analyse, return the report
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


class Engine:
    """Thread-safe holder of the simulate -> detect pipeline and its last report."""

    def __init__(self, log_file=LOG_FILE):
        self.log_file = Path(log_file)
        self._lock = threading.Lock()
        self.report = {}

    def refresh(self, seed=None):
        """Regenerate the log file, run detection and cache the new report."""
        with self._lock:
            simulator.generate_logs(self.log_file, seed)
            self.report = detector.analyze_file(self.log_file)
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
            self._json(self.engine.report)
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
