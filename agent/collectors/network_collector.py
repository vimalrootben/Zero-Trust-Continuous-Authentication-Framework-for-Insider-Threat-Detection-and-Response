"""
NetworkCollector (A9) — Monitors active network connections and detects new socket activity.

Design:
  - Delta polling via psutil.net_connections() every poll_interval seconds (5-10s).
  - Enriches connections with local PID and process name.
  - Exposes NetworkConnectionProvider seam for test injection.
  - Emits TelemetryEventDTO with collector_type='network'.
"""
import logging
import socket
import threading
from typing import Callable, Dict, List, Optional, Set, Tuple

from agent.collectors.base_collector import BaseCollector
from agent.storage.models import EventSeverity, TelemetryEventDTO

logger = logging.getLogger(__name__)

COLLECTOR_TYPE = "network"

# (fd, laddr, lport, raddr, rport, status, pid)
_ConnTuple = Tuple[str, int, str, int, str, int]


class NetworkConnectionProvider:
    """
    Wraps psutil.net_connections() for network socket enumeration.
    """

    def get_connections(self) -> List[dict]:
        results: List[dict] = []
        try:
            import psutil  # type: ignore[import]
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                laddr = c.laddr.ip if c.laddr else ""
                lport = c.laddr.port if c.laddr else 0
                raddr = c.raddr.ip if c.raddr else ""
                rport = c.raddr.port if c.raddr else 0
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                status = getattr(c, "status", "")

                proc_name = ""
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except Exception:
                        pass

                results.append({
                    "local_addr": laddr,
                    "local_port": lport,
                    "remote_addr": raddr,
                    "remote_port": rport,
                    "protocol": proto,
                    "status": status,
                    "pid": c.pid or 0,
                    "process_name": proc_name,
                    "direction": "outbound" if raddr and not raddr.startswith("127.") else "inbound",
                    "dns_query": None,
                })
        except Exception as e:
            logger.debug(f"NetworkConnectionProvider error: {e}")
        return results


class NetworkCollector(BaseCollector):
    """
    A9 — Network Collector.
    Monitors active network connections and detects connection deltas.
    """

    COLLECTOR_TYPE = COLLECTOR_TYPE

    def __init__(
        self,
        event_sink: Callable[[TelemetryEventDTO], None],
        provider: Optional[NetworkConnectionProvider] = None,
        poll_interval: int = 5,
    ) -> None:
        super().__init__(event_sink)
        self._provider = provider or NetworkConnectionProvider()
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._known_connections: Set[_ConnTuple] = set()

    def collector_type(self) -> str:
        return self.COLLECTOR_TYPE

    def start(self) -> None:
        """Start network polling thread. Idempotent."""
        if self._running:
            return
        self._stop_event.clear()
        self._known_connections.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="NetworkCollector-Thread",
            daemon=True,
        )
        self._running = True
        self._thread.start()
        logger.info("NetworkCollector started.")

    def stop(self) -> None:
        """Stop network polling thread. Idempotent."""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._running = False
        logger.info("NetworkCollector stopped.")

    def _run(self) -> None:
        # Initial snapshot to populate baseline connections
        try:
            initial = self._provider.get_connections()
            for c in initial:
                tup = self._make_tuple(c)
                self._known_connections.add(tup)
        except Exception as e:
            logger.error(f"Error populating initial network snapshot: {e}")

        while not self._stop_event.is_set():
            if self._stop_event.wait(timeout=self._poll_interval):
                break
            try:
                current_conns = self._provider.get_connections()
                current_tuples: Set[_ConnTuple] = set()

                for conn in current_conns:
                    tup = self._make_tuple(conn)
                    current_tuples.add(tup)

                    # New connection established
                    if tup not in self._known_connections:
                        self._on_new_connection(conn)

                self._known_connections = current_tuples
            except Exception as exc:
                logger.error(f"Error in NetworkCollector polling loop: {exc}", exc_info=True)

        self._running = False

    def _on_new_connection(self, conn: dict) -> None:
        raddr = conn.get("remote_addr", "")
        rport = conn.get("remote_port", 0)
        proc = conn.get("process_name", "").lower()

        severity = EventSeverity.LOW.value
        # Connections to unusual remote ports or by cmd/powershell get higher severity
        if rport in (4444, 1337, 6667, 3389) or "powershell" in proc or "cmd" in proc:
            severity = EventSeverity.HIGH.value
        elif raddr and not (raddr.startswith("127.") or raddr.startswith("10.") or raddr.startswith("192.168.")):
            severity = EventSeverity.MEDIUM.value

        event = TelemetryEventDTO(
            collector_type=self.COLLECTOR_TYPE,
            event_type="network_connection",
            severity=severity,
            data=conn,
        )
        self._emit(event)

    @staticmethod
    def _make_tuple(c: dict) -> _ConnTuple:
        return (
            c.get("local_addr", ""),
            c.get("local_port", 0),
            c.get("remote_addr", ""),
            c.get("remote_port", 0),
            c.get("protocol", ""),
            c.get("pid", 0),
        )
