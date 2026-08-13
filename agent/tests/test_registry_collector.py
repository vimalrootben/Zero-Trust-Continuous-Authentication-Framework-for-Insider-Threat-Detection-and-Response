"""
Unit tests for RegistryCollector (A8).
"""
import time
from agent.collectors.registry_collector import RegistryCollector, WinRegistryWatcher
from agent.storage.models import TelemetryEventDTO


class MockWinRegistryWatcher(WinRegistryWatcher):
    """Mock watcher emitting synthetic registry changes."""

    def __init__(self, sample_changes=None):
        super().__init__()
        self.sample_changes = sample_changes or []

    def subscribe(self, on_change, stop_event, poll_interval=15):
        for change in self.sample_changes:
            if stop_event.is_set():
                break
            on_change(change)
        stop_event.wait(timeout=0.1)


def test_registry_collector_events():
    events = []
    watcher = MockWinRegistryWatcher([
        {
            "key_path": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            "value_name": "PersistenceKey",
            "old_value": None,
            "new_value": "powershell.exe -enc AAAAA==",
            "change_type": "created",
        }
    ])

    collector = RegistryCollector(
        event_sink=events.append,
        watcher=watcher,
        poll_interval=1,
    )
    assert collector.collector_type() == "registry"

    collector.start()
    time.sleep(0.2)
    collector.stop()

    assert len(events) == 1
    ev = events[0]
    assert ev.collector_type == "registry"
    assert ev.event_type == "registry_change"
    assert ev.data["value_name"] == "PersistenceKey"
    assert ev.severity == "critical"  # Powershell in run key triggers critical
