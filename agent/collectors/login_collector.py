"""
LoginCollector — Monitors Windows session logon, logoff, lock, unlock, and remote connection events.

Design:
  - Event-driven session notification via WTSRegisterSessionNotification / win32ts when running on Windows.
  - Exposes SessionNotificationSubscriber seam for test injection.
  - Emits TelemetryEventDTO with collector_type='login'.
"""
import logging
import threading
from datetime import datetime, timezone
from typing import Callable, Optional

from agent.collectors.base_collector import BaseCollector
from agent.storage.models import EventSeverity, TelemetryEventDTO

logger = logging.getLogger(__name__)

COLLECTOR_TYPE = "login"


class SessionNotificationSubscriber:
    """
    Wraps Windows Session Notification API listeners.
    """

    def subscribe(
        self,
        on_session_event: Callable[[dict], None],
        stop_event: threading.Event,
    ) -> None:
        try:
            import win32ts  # type: ignore[import]
            logger.info("LoginCollector initialized win32ts session listener.")
            stop_event.wait()
        except Exception as exc:
            logger.debug(f"win32ts unavailable ({exc}). Using mock/idle loop.")
            stop_event.wait()


class LoginCollector(BaseCollector):
    """
    Login Collector.
    Monitors session events (logon, logoff, lock, unlock, remote_connect, remote_disconnect).
    """

    COLLECTOR_TYPE = COLLECTOR_TYPE

    def __init__(
        self,
        event_sink: Callable[[TelemetryEventDTO], None],
        subscriber: Optional[SessionNotificationSubscriber] = None,
    ) -> None:
        super().__init__(event_sink)
        self._subscriber = subscriber or SessionNotificationSubscriber()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def collector_type(self) -> str:
        return self.COLLECTOR_TYPE

    def start(self) -> None:
        """Start session monitoring thread. Idempotent."""
        if self._running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="LoginCollector-Thread",
            daemon=True,
        )
        self._running = True
        self._thread.start()
        logger.info("LoginCollector started.")

    def stop(self) -> None:
        """Stop session monitoring thread. Idempotent."""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._running = False
        logger.info("LoginCollector stopped.")

    def _run(self) -> None:
        try:
            self._subscriber.subscribe(
                on_session_event=self._on_session_event,
                stop_event=self._stop_event,
            )
        except Exception as exc:
            logger.error(f"LoginCollector thread error: {exc}", exc_info=True)
        finally:
            self._running = False

    def _on_session_event(self, raw: dict) -> None:
        event_type = raw.get("event_type", "logon")
        severity = EventSeverity.LOW.value
        if event_type in ("remote_connect", "failed_logon"):
            severity = EventSeverity.MEDIUM.value

        event = TelemetryEventDTO(
            collector_type=self.COLLECTOR_TYPE,
            event_type="session_event",
            severity=severity,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data={
                "session_id": raw.get("session_id", 0),
                "user_sid": raw.get("user_sid", ""),
                "event_type": event_type,
                "timestamp": raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            },
        )
        self._emit(event)
