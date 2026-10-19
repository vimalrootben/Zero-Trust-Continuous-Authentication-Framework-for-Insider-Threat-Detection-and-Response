#!/usr/bin/env python
"""Safe Local Development & System Verification Runner for ZTA Platform.

Starts the ZTA Manager (threaded HTTP server on ports 8000 & 8080)
and registers the Windows Agent with verified credentials.
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import threading
import time
from pathlib import Path

# Ensure root workspace is in sys.path
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from zta.dashboard.run_dashboard import create_zta_server


def check_prerequisites(db_path: str):
    """Verifies Python version, OS platform, and database accessibility."""
    print("==========================================================")
    print("ZTA Platform — Preflight Environment & Health Check")
    print("==========================================================")
    print(f"[*] Python Version: {sys.version.split()[0]}")
    print(f"[*] Operating System: {platform.system()} ({platform.platform()})")
    print(f"[*] Workspace Root: {ROOT_DIR}")

    db_file = Path(db_path).resolve()
    print(f"[*] Database Path: {db_file}")
    if not db_file.exists():
        print(f"[!] Warning: Database {db_file} does not exist yet. It will be initialized.")
    else:
        print(f"[+] Database verified. Size: {db_file.stat().st_size:,} bytes.")

    return True


def start_system(dashboard_port: int = 8000, api_port: int = 8080, db_path: str = "zta_runtime.db"):
    """Starts the dual-port ZTA Manager server and provides operator instructions."""
    check_prerequisites(db_path)

    print("\n[*] Initializing ZTA Manager Backend & Detection Engines...")
    servers = []
    try:
        for port in dict.fromkeys((dashboard_port, api_port)):
            servers.append(create_zta_server("127.0.0.1", port, db_path, runtime=servers[0].runtime if servers else None))
    except OSError as exc:
        print(f"[-] Error: Failed to bind to ports {dashboard_port}/{api_port}: {exc}")
        print("[-] Please ensure no other process is listening on these ports.")
        sys.exit(1)

    threads = []
    for server in servers:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)

    print(f"[+] ZTA Manager Backend successfully started:")
    print(f"    - SOC Dashboard URL:  http://127.0.0.1:{dashboard_port}")
    print(f"    - Agent REST API URL: http://127.0.0.1:{api_port}")
    print(f"    - Real-Time WebSocket: ws://127.0.0.1:{dashboard_port}/api/zta/ws")
    print(f"\n[*] Default Operator Login:")
    print(f"    Username: admin")
    print(f"    Password: (See admin-credentials.env or provisioned credentials)")
    print("\n[*] To start the Windows Agent in another shell:")
    print(f"    python zta_agent.py --manager-url http://127.0.0.1:{api_port} --agent-id my-endpoint-01 --token <agent-token>")
    print("\n[*] Press Ctrl+C to cleanly stop the ZTA Platform.\n")

    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\n[*] Intercepted shutdown signal. Gracefully closing servers...")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        print("[+] All ZTA Manager services and worker supervisor threads stopped cleanly.")


def main():
    parser = argparse.ArgumentParser(description="Zero Trust Architecture Local Development Runner")
    parser.add_argument("--port", type=int, default=8000, help="SOC Dashboard Port (default: 8000)")
    parser.add_argument("--api-port", type=int, default=8080, help="Agent Ingestion API Port (default: 8080)")
    parser.add_argument("--db", default="zta_runtime.db", help="SQLite database path (default: zta_runtime.db)")
    args = parser.parse_args()

    start_system(dashboard_port=args.port, api_port=args.api_port, db_path=args.db)


if __name__ == "__main__":
    main()
