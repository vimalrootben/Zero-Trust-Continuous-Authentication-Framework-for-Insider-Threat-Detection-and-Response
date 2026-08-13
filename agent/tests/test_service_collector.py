"""
Unit tests for ServiceCollector (A7).
"""
import threading
import time
from agent.collectors.service_collector import ServiceCollector, WMIServiceSubscriber
from agent.storage.models import TelemetryEventDTO


class MockWMIServiceSubscriber(WMIServiceSubscriber):
    """Mock subscriber that emits controlled service change dicts."""

    def __init__(self, sample_changes=None):
        self.sample_changes = sample_changes or []

    def subscribe(self, on_change, stop_event, poll_interval=15):
        for change in self.sample_changes:
            if stop_event.is_set():
                break
            on_change(change)
        stop_event.wait(timeout=0.1)


def test_service_collector_lifecycle():
    events = []
    subscriber = MockWMIServiceSubscriber([
        {
            "service_name": "TestSvc",
            "display_name": "Test Service",
            "path_name": "C:\\Windows\\system32\\test.exe",
            "start_mode": "Auto",
            "state": "Running",
            "start_name": "LocalSystem",
            "change_type": "created",
        }
    ])

    collector = ServiceCollector(
        event_sink=events.append,
        subscriber=subscriber,
        poll_interval=1,
    )
    assert collector.collector_type() == "service"

    collector.start()
    time.sleep(0.2)
    collector.stop()

    assert len(events) == 1
    ev = events[0]
    assert isinstance(ev, TelemetryEventDTO)
    assert ev.collector_type == "service"
    assert ev.event_type == "service_created"
    assert ev.data["service_name"] == "TestSvc"


def test_service_collector_idempotent_start_stop():
    collector = ServiceCollector(event_sink=lambda x: None, subscriber=MockWMIServiceSubscriber())
    collector.start()
    collector.start()  # Duplicate start
    collector.stop()
    collector.stop()   # Duplicate stop
