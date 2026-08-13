"""
Unit tests for LoginCollector.
"""
import time
from agent.collectors.login_collector import LoginCollector, SessionNotificationSubscriber
from agent.storage.models import TelemetryEventDTO


class MockSessionNotificationSubscriber(SessionNotificationSubscriber):
    """Mock subscriber emitting session notification events."""

    def __init__(self, sample_events=None):
        self.sample_events = sample_events or []

    def subscribe(self, on_session_event, stop_event):
        for ev in self.sample_events:
            if stop_event.is_set():
                break
            on_session_event(ev)
        stop_event.wait(timeout=0.1)


def test_login_collector_events():
    events = []
    subscriber = MockSessionNotificationSubscriber([
        {
            "session_id": 1,
            "user_sid": "S-1-5-21-123456789-987654321-1001",
            "event_type": "remote_connect",
            "timestamp": "2026-08-07T12:00:00Z",
        }
    ])

    collector = LoginCollector(
        event_sink=events.append,
        subscriber=subscriber,
    )
    assert collector.collector_type() == "login"

    collector.start()
    time.sleep(0.2)
    collector.stop()

    assert len(events) == 1
    ev = events[0]
    assert ev.collector_type == "login"
    assert ev.event_type == "session_event"
    assert ev.data["event_type"] == "remote_connect"
    assert ev.severity == "medium"
