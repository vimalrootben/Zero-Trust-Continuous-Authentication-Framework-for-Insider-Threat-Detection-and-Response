"""Start ZTA's dashboard and API without changing the working directory."""
import argparse
from pathlib import Path
import sys
import threading

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zta.api.server import create_zta_server


def main():
    parser = argparse.ArgumentParser(description="ZTA Platform dashboard and API")
    parser.add_argument("--port", type=int, default=8000, help="Dashboard port")
    parser.add_argument("--api-port", type=int, default=8080, help="Agent API port")
    parser.add_argument("--db", help="SQLite database path (also ZTA_DB_PATH)")
    args = parser.parse_args()
    servers = []
    try:
        for port in dict.fromkeys((args.port, args.api_port)):
            servers.append(create_zta_server("127.0.0.1", port, args.db, runtime=servers[0].runtime if servers else None))
    except OSError as exc:
        for server in servers:
            server.server_close()
        parser.exit(1, f"Unable to start ZTA: {exc}\n")
    threads = []
    for server in servers:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    print(f"ZTA Platform: http://127.0.0.1:{args.port}\nAgent API: http://127.0.0.1:{args.api_port}", flush=True)
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
