"""
Unit tests for FileCollector (A11).
"""
import time
from agent.collectors.file_collector import FileCollector, FileWatcher
from agent.storage.models import TelemetryEventDTO


class MockFileWatcher(FileWatcher):
    """Mock file watcher emitting synthetic events."""

    def __init__(self, sample_events=None):
        super().__init__([])
        self.sample_events = sample_events or []

    def subscribe(self, on_file_event, stop_event):
        for ev in self.sample_events:
            if stop_event.is_set():
                break
            on_file_event(ev)
        stop_event.wait(timeout=0.1)


def test_file_collector_event_enrichment():
    events = []
    watcher = MockFileWatcher([
        {
            "file_path": "C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe",
            "change_type": "created",
        }
    ])

    collector = FileCollector(
        event_sink=events.append,
        watched_paths=["C:\\Users\\User\\AppData\\Local\\Temp"],
        watcher=watcher,
    )
    assert collector.collector_type() == "file"

    collector.start()
    time.sleep(0.3)
    collector.stop()

    assert len(events) == 1
    ev = events[0]
    assert ev.collector_type == "file"
    assert ev.event_type == "file_created"
    assert ev.data["file_path"] == "C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe"
    assert ev.severity == "high"  # exe in Temp gets high severity
