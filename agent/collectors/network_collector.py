"""
NetworkCollector (A9) — Monitors active network connections and listening sockets.

Design:
  - Delta polling via psutil.net_connections() every poll_interval seconds (5-10s).
  - Enriches sockets with PID, process name, process exe path, and process username.
  - Detects both active connection transitions (CONNECTION_OPENED, CONNECTION_CLOSED)
    and listening port transitions (LISTEN_STARTED, LISTEN_STOPPED).
  - Emits TelemetryEventDTO with collector_type='network'.
"""
import logging
import socket
import threading
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set, Tuple

from agent.collectors.base_collector import BaseCollector
from agent.storage.models import EventSeverity, TelemetryEventDTO

logger = logging.getLogger(__name__)

COLLECTOR_TYPE = "network"

# (protocol, local_addr, local_port, remote_addr, remote_port, status, pid)
_SocketTuple = Tuple[str, str, int, str, int, str, int]


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
                status = getattr(c, "status", "NONE")
                if not status:
                    status = "LISTENING" if proto == "UDP" and lport else "NONE"

                proc_name = ""
                proc_path = ""
                proc_user = ""
                if c.pid:
                    try:
                        p = psutil.Process(c.pid)
                        proc_name = p.name()
                        try:
                            proc_path = p.exe()
                        except Exception:
                            proc_path = ""
                        try:
                            proc_user = p.username()
                        except Exception:
                            proc_user = ""
                    except Exception:
                        pass

                is_listen = (status == "LISTEN" or status == "LISTENING") or (proto == "UDP" and not raddr)
                direction = "listen" if is_listen else ("outbound" if raddr and not raddr.startswith("127.") else "inbound")

                results.append({
                    "local_addr": laddr,
                    "local_ip": laddr,
                    "local_port": lport,
                    "remote_addr": raddr,
                    "remote_ip": raddr,
                    "remote_port": rport,
                    "protocol": proto,
                    "status": "LISTENING" if is_listen else status,
                    "state": "LISTENING" if is_listen else status,
                    "is_listening": is_listen,
                    "pid": c.pid or 0,
                    "process_name": proc_name,
                    "process_path": proc_path,
                    "process_user": proc_user,
                    "username": proc_user,
                    "direction": direction,
                    "dns_query": None,
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                })
        except Exception as e:
            logger.debug(f"NetworkConnectionProvider error: {e}")
        return results


class NetworkCollector(BaseCollector):
    """
    A9 — Network Collector.
    Monitors active network connections and listening sockets, detecting state deltas.
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
        self._known_sockets: Dict[_SocketTuple, dict] = {}

    def collector_type(self) -> str:
        return self.COLLECTOR_TYPE

    def start(self) -> None:
        """Start network polling thread. Idempotent."""
        if self._running:
            return
        self._stop_event.clear()
        self._known_sockets.clear()
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
        # Initial snapshot to populate baseline connections and emit initial listening ports
        try:
            initial = self._provider.get_connections()
            for c in initial:
                tup = self._make_tuple(c)
                self._known_sockets[tup] = c
                if c.get("is_listening"):
                    self._emit_listening_port_event(c, "listen_baseline")
        except Exception as e:
            logger.error(f"Error populating initial network snapshot: {e}")

        while not self._stop_event.is_set():
            if self._stop_event.wait(timeout=self._poll_interval):
                break
            try:
                current_conns = self._provider.get_connections()
                current_map: Dict[_SocketTuple, dict] = {}

                for conn in current_conns:
                    tup = self._make_tuple(conn)
                    current_map[tup] = conn

                    # New socket / connection established
                    if tup not in self._known_sockets:
                        if conn.get("is_listening"):
                            self._emit_listening_port_event(conn, "LISTEN_STARTED")
                        else:
                            self._on_new_connection(conn)

                # Sockets closed / terminated
                for old_tup, old_conn in self._known_sockets.items():
                    if old_tup not in current_map:
                        if old_conn.get("is_listening"):
                            self._emit_listening_port_event(old_conn, "LISTEN_STOPPED")
                        else:
                            self._on_closed_connection(old_conn)

                self._known_sockets = current_map
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
            event_type="CONNECTION_OPENED",
            severity=severity,
            data=conn,
        )
        self._emit(event)

    def _on_closed_connection(self, conn: dict) -> None:
        event = TelemetryEventDTO(
            collector_type=self.COLLECTOR_TYPE,
            event_type="CONNECTION_CLOSED",
            severity=EventSeverity.LOW.value,
            data=conn,
        )
        self._emit(event)

    def _emit_listening_port_event(self, conn: dict, event_type: str) -> None:
        severity = EventSeverity.LOW.value
        lport = conn.get("local_port", 0)
        proc = conn.get("process_name", "").lower()

        if lport in (4444, 1337, 6667, 3389, 8080) and ("powershell" in proc or "cmd" in proc or "netcat" in proc):
            severity = EventSeverity.HIGH.value

        event = TelemetryEventDTO(
            collector_type=self.COLLECTOR_TYPE,
            event_type=event_type,
            severity=severity,
            data=conn,
        )
        self._emit(event)

    @staticmethod
    def _make_tuple(c: dict) -> _SocketTuple:
        return (
            c.get("protocol", ""),
            c.get("local_addr", ""),
            c.get("local_port", 0),
            c.get("remote_addr", ""),
            c.get("remote_port", 0),
            c.get("status", ""),
            c.get("pid", 0),
        )
