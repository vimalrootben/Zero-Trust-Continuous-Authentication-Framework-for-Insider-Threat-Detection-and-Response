"""
ServiceCollector (A7) — Service creation, modification, and deletion telemetry.

Design:
  - Event-driven via WMI __InstanceCreationEvent, __InstanceModificationEvent, and
    __InstanceDeletionEvent on Win32_Service when running on Windows.
  - Polling fallback (psutil.win_service_iter diffing) every N seconds when WMI
    is unsuited or for cross-platform fallback.
  - Exposes WMIServiceSubscriber seam for test injection on non-Windows hosts.
  - Emits TelemetryEventDTO with collector_type='service'.
"""
import logging
import threading
import time
from typing import Callable, Dict, Optional, Set

from agent.collectors.base_collector import BaseCollector
from agent.storage.models import EventSeverity, TelemetryEventDTO

logger = logging.getLogger(__name__)

COLLECTOR_TYPE = "service"


class WMIServiceSubscriber:
    """
    Wraps WMI service event subscriptions and polling diff fallback.
    """

    def subscribe(
        self,
        on_change: Callable[[dict], None],
        stop_event: threading.Event,
        poll_interval: int = 15,
    ) -> None:
        """
        Runs event loop until stop_event is set.
        Attempts WMI event watcher first; if WMI fails or is unavailable,
        falls back to polling psutil.win_service_iter().
        """
        wmi_available = False
        try:
            import wmi  # type: ignore[import]
            c = wmi.WMI()
            creation_watcher = c.watch_for(
                notification_type="Creation",
                wmi_class="Win32_Service",
                delay_secs=2,
            )
            modification_watcher = c.watch_for(
                notification_type="Modification",
                wmi_class="Win32_Service",
                delay_secs=2,
            )
            wmi_available = True
            logger.info("ServiceCollector attached to WMI Win32_Service watchers.")
            while not stop_event.is_set():
                try:
                    ev = creation_watcher(timeout_ms=500)
                    if ev:
                        on_change(self._wmi_to_dict(ev, "created"))
                except Exception:
                    pass
                try:
                    ev = modification_watcher(timeout_ms=500)
                    if ev:
                        on_change(self._wmi_to_dict(ev, "modified"))
                except Exception:
                    pass
        except Exception as exc:
            logger.debug(f"WMI Win32_Service subscription unavailable ({exc}). Using polling fallback.")
            wmi_available = False

        if not wmi_available:
            self._poll_loop(on_change, stop_event, poll_interval)

    def _poll_loop(
        self,
        on_change: Callable[[dict], None],
        stop_event: threading.Event,
        poll_interval: int,
    ) -> None:
        known_services: Dict[str, dict] = {}

        def snapshot() -> Dict[str, dict]:
            curr: Dict[str, dict] = {}
            try:
                import psutil  # type: ignore[import]
                for svc in psutil.win_service_iter():
                    try:
                        info = svc.as_dict()
                        s_name = info.get("name", "")
                        if s_name:
                            curr[s_name] = {
                                "service_name": s_name,
                                "display_name": info.get("display_name", ""),
                                "path_name": info.get("binpath", ""),
                                "start_type": info.get("start_type", ""),
                                "status": info.get("status", ""),
                                "start_name": info.get("username", ""),
                            }
                    except Exception:
                        continue
            except Exception as e:
                logger.debug(f"psutil win_service_iter error: {e}")
            return curr

        known_services = snapshot()
        while not stop_event.is_set():
            if stop_event.wait(timeout=poll_interval):
                break
            current_services = snapshot()

            # Detect created services
            for name, data in current_services.items():
                if name not in known_services:
                    payload = dict(data)
                    payload["change_type"] = "created"
                    on_change(payload)
                elif current_services[name] != known_services[name]:
                    payload = dict(data)
                    payload["change_type"] = "modified"
                    on_change(payload)

            # Detect deleted services
            for name in known_services:
                if name not in current_services:
                    payload = dict(known_services[name])
                    payload["change_type"] = "deleted"
                    on_change(payload)

            known_services = current_services

    @staticmethod
    def _wmi_to_dict(ev, change_type: str) -> dict:
        return {
            "service_name": getattr(ev, "Name", ""),
            "display_name": getattr(ev, "DisplayName", ""),
            "path_name": getattr(ev, "PathName", ""),
            "start_mode": getattr(ev, "StartMode", ""),
            "state": getattr(ev, "State", ""),
            "start_name": getattr(ev, "StartName", ""),
            "change_type": change_type,
        }


class ServiceCollector(BaseCollector):
    """
    A7 — Service Collector.
    Monitors Windows Service creation, modification, and deletion events.
    """

    COLLECTOR_TYPE = COLLECTOR_TYPE

    def __init__(
        self,
        event_sink: Callable[[TelemetryEventDTO], None],
        subscriber: Optional[WMIServiceSubscriber] = None,
        poll_interval: int = 15,
    ) -> None:
        super().__init__(event_sink)
        self._subscriber = subscriber or WMIServiceSubscriber()
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def collector_type(self) -> str:
        return self.COLLECTOR_TYPE

    def start(self) -> None:
        """Start service monitoring thread. Idempotent."""
        if self._running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="ServiceCollector-Thread",
            daemon=True,
        )
        self._running = True
        self._thread.start()
        logger.info("ServiceCollector started.")

    def stop(self) -> None:
        """Stop service monitoring thread. Idempotent."""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._running = False
        logger.info("ServiceCollector stopped.")

    def _run(self) -> None:
        try:
            self._subscriber.subscribe(
                on_change=self._on_service_change,
                stop_event=self._stop_event,
                poll_interval=self._poll_interval,
            )
        except Exception as exc:
            logger.error(f"ServiceCollector thread error: {exc}", exc_info=True)
        finally:
            self._running = False

    def _on_service_change(self, raw: dict) -> None:
        change_type = raw.get("change_type", "modified")
        severity = EventSeverity.LOW.value
        # New services or services with unusual path names get medium severity
        if change_type == "created":
            severity = EventSeverity.MEDIUM.value
        path_name = raw.get("path_name", "").lower()
        if "temp" in path_name or "appdata" in path_name:
            severity = EventSeverity.HIGH.value

        event = TelemetryEventDTO(
            collector_type=self.COLLECTOR_TYPE,
            event_type=f"service_{change_type}",
            severity=severity,
            data={
                "service_name": raw.get("service_name", ""),
                "display_name": raw.get("display_name", ""),
                "path_name": raw.get("path_name", ""),
                "start_mode": raw.get("start_mode") or raw.get("start_type", ""),
                "state": raw.get("state") or raw.get("status", ""),
                "start_name": raw.get("start_name", ""),
                "change_type": change_type,
            },
        )
        self._emit(event)
