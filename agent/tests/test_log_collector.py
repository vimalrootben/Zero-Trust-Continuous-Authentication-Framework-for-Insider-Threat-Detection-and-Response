"""
Unit tests for LogCollector (A12).
"""
import time
from agent.collectors.log_collector import EventLogSubscriber, LogCollector
from agent.storage.models import TelemetryEventDTO


class MockEventLogSubscriber(EventLogSubscriber):
    """Mock subscriber emitting log events."""

    def __init__(self, sample_logs=None):
        self.sample_logs = sample_logs or []

    def subscribe(self, on_log_event, stop_event):
        for log in self.sample_logs:
            if stop_event.is_set():
                break
            on_log_event(log)
        stop_event.wait(timeout=0.1)


def test_log_collector_critical_event():
    events = []
    subscriber = MockEventLogSubscriber([
        {
            "event_id": 1102,
            "channel": "Security",
            "timestamp": "2026-08-07T12:00:00Z",
            "event_data": {
                "source_name": "Microsoft-Windows-Eventlog",
                "computer_name": "DESKTOP-TEST",
                "event_type": 4,
                "string_inserts": ["System", "Administrator"],
            },
        }
    ])

    collector = LogCollector(
        event_sink=events.append,
        subscriber=subscriber,
    )
    assert collector.collector_type() == "log"

    collector.start()
    time.sleep(0.2)
    collector.stop()

    assert len(events) == 1
    ev = events[0]
    assert ev.collector_type == "log"
    assert ev.event_type == "event_log"
    assert ev.data["event_id"] == 1102
    assert ev.severity == "critical"  # Event ID 1102 (audit log cleared) triggers critical
