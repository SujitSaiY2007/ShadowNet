#!/usr/bin/env python3
"""ShadowNet launcher.

    python run.py              # simulate, analyse, serve and open the dashboard
    python run.py --no-browser # same, without opening a browser tab
    python run.py --port 9000  # use a different port
"""

import argparse
import sys
import threading
import webbrowser

from core.server import Engine, create_server

BANNER = r"""
  ____  _               _               _   _      _
 / ___|| |__   __ _  __| | _____      _| \ | | ___| |_
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /  \| |/ _ \ __|
  ___) | | | | (_| | (_| | (_) \ V  V /| |\  |  __/ |_
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_| \_|\___|\__|
        Network Intrusion & Log Forensics Engine
"""


def main():
    parser = argparse.ArgumentParser(description="ShadowNet SOC dashboard")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    args = parser.parse_args()
    if sys.version_info < (3, 9):
        sys.exit("ShadowNet requires Python 3.9 or newer.")

    print(BANNER)
    engine = Engine()
    print("[1/3] Generating simulated traffic and attack logs ...")
    summary = engine.refresh()["summary"]
    print(f"      {summary['total_requests']} log lines -> {engine.log_file}")
    print("[2/3] Threat analysis complete:")
    print(f"      {summary['blocked_threats']} malicious requests, {summary['alert_count']} alerts, "
          f"{summary['critical_ips']} critical IPs, peak {summary['peak_rps']} req/s")

    try:
        server = create_server(engine, port=args.port)
    except OSError as error:
        sys.exit(f"Could not bind port {args.port}: {error}. Try --port <other>.")
    url = f"http://localhost:{args.port}"
    print(f"[3/3] Dashboard live at {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(0.6, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShadowNet stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
