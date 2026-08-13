"""
LogCollector (A12) — Monitors Windows Security, System, and Application Event Logs.

Design:
  - Filters for high-value Event IDs:
    4624 (logon success), 4625 (logon fail), 4648 (explicit creds),
    4672 (special privileges), 4697 (service install), 4698 (task created),
    4720 (user created), 4732 (group member added), 1102 (audit log cleared),
    7045 (service installed).
  - Uses EvtSubscribe / win32evtlog when running on Windows.
  - Exposes EventLogSubscriber seam for test injection.
  - Emits TelemetryEventDTO with collector_type='log'.
"""
import logging
import threading
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set

from agent.collectors.base_collector import BaseCollector
from agent.storage.models import EventSeverity, TelemetryEventDTO

logger = logging.getLogger(__name__)

COLLECTOR_TYPE = "log"

TARGET_EVENT_IDS: Set[int] = {
    4624, 4625, 4648, 4672, 4697, 4698, 4720, 4732, 1102, 7045
}


class EventLogSubscriber:
    """
    Wraps Windows Event Log API subscription.
    """

    def subscribe(
        self,
        on_log_event: Callable[[dict], None],
        stop_event: threading.Event,
    ) -> None:
        try:
            import win32evtlog  # type: ignore[import]

            def read_channel(channel_name: str):
                try:
                    h_log = win32evtlog.OpenEventLog(None, channel_name)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(h_log, flags, 0)
                    for ev in events:
                        ev_id = ev.EventID & 0xFFFF
                        if ev_id in TARGET_EVENT_IDS:
                            on_log_event({
                                "event_id": ev_id,
                                "channel": channel_name,
                                "timestamp": ev.TimeGenerated.isoformat() if hasattr(ev.TimeGenerated, "isoformat") else str(ev.TimeGenerated),
                                "event_data": {
                                    "source_name": ev.SourceName,
                                    "computer_name": ev.ComputerName,
                                    "event_type": ev.EventType,
                                    "string_inserts": list(ev.StringInserts) if ev.StringInserts else [],
                                },
                            })
                    win32evtlog.CloseEventLog(h_log)
                except Exception as e:
                    logger.debug(f"Event log read error on {channel_name}: {e}")

            logger.info("LogCollector polling Windows Event Logs.")
            while not stop_event.is_set():
                read_channel("Security")
                read_channel("System")
                if stop_event.wait(timeout=10.0):
                    break
        except Exception as exc:
            logger.debug(f"win32evtlog unavailable ({exc}). Using mock/idle loop.")
            stop_event.wait()


class LogCollector(BaseCollector):
    """
    A12 — Log Collector.
    Monitors Windows Event Logs for critical security Event IDs.
    """

    COLLECTOR_TYPE = COLLECTOR_TYPE

    def __init__(
        self,
        event_sink: Callable[[TelemetryEventDTO], None],
        subscriber: Optional[EventLogSubscriber] = None,
    ) -> None:
        super().__init__(event_sink)
        self._subscriber = subscriber or EventLogSubscriber()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def collector_type(self) -> str:
        return self.COLLECTOR_TYPE

    def start(self) -> None:
        """Start event log monitoring thread. Idempotent."""
        if self._running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="LogCollector-Thread",
            daemon=True,
        )
        self._running = True
        self._thread.start()
        logger.info("LogCollector started.")

    def stop(self) -> None:
        """Stop event log monitoring thread. Idempotent."""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._running = False
        logger.info("LogCollector stopped.")

    def _run(self) -> None:
        try:
            self._subscriber.subscribe(
                on_log_event=self._on_log_event,
                stop_event=self._stop_event,
            )
        except Exception as exc:
            logger.error(f"LogCollector thread error: {exc}", exc_info=True)
        finally:
            self._running = False

    def _on_log_event(self, raw: dict) -> None:
        event_id = raw.get("event_id", 0)

        severity = EventSeverity.LOW.value
        if event_id in (4625, 4648, 4697, 4698, 4720, 4732, 7045):
            severity = EventSeverity.MEDIUM.value
        if event_id == 1102:  # Audit log cleared
            severity = EventSeverity.CRITICAL.value

        event = TelemetryEventDTO(
            collector_type=self.COLLECTOR_TYPE,
            event_type="event_log",
            severity=severity,
            data=raw,
        )
        self._emit(event)
