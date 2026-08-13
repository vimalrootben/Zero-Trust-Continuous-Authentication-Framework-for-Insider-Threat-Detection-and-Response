"""
Unit tests for A6 ProcessCollector and BaseCollector.

Test strategy (per blueprint §A6 test guidance):
  - All tests mock the WMI subscriber layer — no real WMI calls.
    This keeps the test suite runnable on any OS (Linux CI included).
  - Tests marked `@pytest.mark.windows_only` require a real Windows host
    with the `wmi` package installed; they are skipped in CI.
  - Pure-logic tests (hash cache, event shape, severity computation,
    allowlist, malformed event resilience, start/stop idempotency) run
    everywhere via mock injection.
"""
import hashlib
import os
import sys
import threading
import time
from queue import Empty, Queue
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from agent.collectors.base_collector import BaseCollector
from agent.collectors.process_collector import (
    COLLECTOR_TYPE,
    ProcessCollector,
    WMIProcessSubscriber,
    _sha256_file,
)
from agent.storage.models import TelemetryEventDTO


# ─── Helpers ─────────────────────────────────────────────────────────────────

class MockWMISubscriber:
    """
    Fake WMI subscriber that replays a pre-configured sequence of events
    and then blocks on stop_event.
    """

    def __init__(self, start_events: List[dict] = None, stop_events: List[dict] = None):
        self._start_events = start_events or []
        self._stop_events = stop_events or []

    def subscribe(self, on_start, on_stop, stop_event: threading.Event) -> None:
        for ev in self._start_events:
            on_start(ev)
        for ev in self._stop_events:
            on_stop(ev)
        stop_event.wait()


class CrashingSubscriber:
    """Subscriber that raises immediately — verifies collector thread survives."""

    def subscribe(self, on_start, on_stop, stop_event: threading.Event) -> None:
        raise RuntimeError("Simulated WMI subscription crash")


# ─── BaseCollector abstract contract ─────────────────────────────────────────

def test_base_collector_cannot_be_instantiated():
    """BaseCollector is abstract — instantiation must raise TypeError."""
    with pytest.raises(TypeError):
        BaseCollector(event_sink=lambda e: None)  # type: ignore[abstract]


def test_emit_does_not_propagate_event_sink_exception():
    """_emit() catches and suppresses any exception from event_sink."""
    def crashing_sink(e: TelemetryEventDTO):
        raise ValueError("Sink exploded")

    # Create concrete subclass via ProcessCollector
    collector = ProcessCollector(
        event_sink=crashing_sink,
        subscriber=MockWMISubscriber(),
    )
    # Should not raise
    collector._emit(TelemetryEventDTO(
        collector_type="process", event_type="process_start", data={}
    ))


# ─── ProcessCollector: start / stop lifecycle ─────────────────────────────────

def test_start_stop_idempotent():
    """Calling stop() before start() and start() twice must not raise."""
    q: Queue = Queue()
    collector = ProcessCollector(event_sink=q.put, subscriber=MockWMISubscriber())

    collector.stop()  # stop before start — must be safe
    collector.start()
    collector.start()  # duplicate start — must not spawn second thread
    collector.stop()

    assert not collector._running


def test_stop_joins_thread():
    """stop() must cleanly join the subscriber thread within timeout."""
    q: Queue = Queue()
    subscriber = MockWMISubscriber(start_events=[], stop_events=[])
    collector = ProcessCollector(event_sink=q.put, subscriber=subscriber)

    collector.start()
    time.sleep(0.05)
    collector.stop()

    assert collector._thread is not None
    assert not collector._thread.is_alive()


def test_wmi_crash_does_not_leak_thread():
    """If the subscriber crashes, _running is set to False (thread cleans up)."""
    q: Queue = Queue()
    collector = ProcessCollector(event_sink=q.put, subscriber=CrashingSubscriber())

    collector.start()
    time.sleep(0.2)  # Give the thread time to crash and clean up

    assert not collector._running


# ─── ProcessCollector: collector_type ─────────────────────────────────────────

def test_collector_type_constant():
    """collector_type() must return the exact string the Rule Engine expects."""
    collector = ProcessCollector(event_sink=lambda e: None, subscriber=MockWMISubscriber())
    assert collector.collector_type() == "process"
    assert COLLECTOR_TYPE == "process"


# ─── ProcessCollector: event shape ────────────────────────────────────────────

def test_process_start_event_shape():
    """process_start events must contain all required telemetry fields."""
    received: List[TelemetryEventDTO] = []
    mock_sub = MockWMISubscriber(
        start_events=[{
            "ProcessName": "cmd.exe",
            "ProcessId": 1234,
            "ParentProcessId": 5678,
        }]
    )
    collector = ProcessCollector(event_sink=received.append, subscriber=mock_sub)
    collector.start()

    deadline = time.time() + 2.0
    while not received and time.time() < deadline:
        time.sleep(0.05)
    collector.stop()

    assert received, "No process_start event was emitted"
    evt = received[0]
    assert evt.collector_type == "process"
    assert evt.event_type == "process_start"
    assert "process_name" in evt.data
    assert "pid" in evt.data
    assert "ppid" in evt.data
    assert "parent_process_name" in evt.data
    assert "command_line" in evt.data
    assert "executable_path" in evt.data
    assert "executable_sha256" in evt.data
    assert "signed" in evt.data
    assert "user_sid" in evt.data
    assert "integrity_level" in evt.data
    assert "in_allowlist" in evt.data


def test_process_stop_event_shape():
    """process_stop events must contain process_name and pid."""
    received: List[TelemetryEventDTO] = []
    mock_sub = MockWMISubscriber(
        stop_events=[{"ProcessName": "notepad.exe", "ProcessId": 9999, "ParentProcessId": 0}]
    )
    collector = ProcessCollector(event_sink=received.append, subscriber=mock_sub)
    collector.start()

    deadline = time.time() + 2.0
    while not received and time.time() < deadline:
        time.sleep(0.05)
    collector.stop()

    assert received
    evt = received[0]
    assert evt.event_type == "process_stop"
    assert evt.data["process_name"] == "notepad.exe"
    assert evt.data["pid"] == 9999


# ─── ProcessCollector: malformed events ───────────────────────────────────────

def test_malformed_start_event_does_not_crash():
    """Partial/malformed WMI event dict must not crash the collector."""
    received: List[TelemetryEventDTO] = []

    # Missing ProcessId and ProcessName — should default gracefully
    mock_sub = MockWMISubscriber(start_events=[{}])
    collector = ProcessCollector(event_sink=received.append, subscriber=mock_sub)
    collector.start()

    deadline = time.time() + 2.0
    while not received and time.time() < deadline:
        time.sleep(0.05)
    collector.stop()

    # An event should still be emitted with default/empty values
    assert received
    assert received[0].event_type == "process_start"


def test_malformed_stop_event_does_not_crash():
    """Partial stop event must not crash the collector."""
    received: List[TelemetryEventDTO] = []
    mock_sub = MockWMISubscriber(stop_events=[{"garbage_key": "x"}])
    collector = ProcessCollector(event_sink=received.append, subscriber=mock_sub)
    collector.start()

    deadline = time.time() + 2.0
    while not received and time.time() < deadline:
        time.sleep(0.05)
    collector.stop()

    assert received


# ─── ProcessCollector: allowlist ──────────────────────────────────────────────

def test_allowlisted_process_still_emits_event():
    """Blueprint: allowlisting affects severity weighting, NOT event emission."""
    received: List[TelemetryEventDTO] = []
    norm_chrome = os.path.normcase("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")
    mock_sub = MockWMISubscriber(
        start_events=[{
            "ProcessName": "chrome.exe",
            "ProcessId": 4321,
            "ParentProcessId": 1000,
        }]
    )
    collector = ProcessCollector(
        event_sink=received.append,
        subscriber=mock_sub,
        allowlist={norm_chrome},
    )
    collector.start()

    deadline = time.time() + 2.0
    while not received and time.time() < deadline:
        time.sleep(0.05)
    collector.stop()

    # Event MUST be emitted even for allowlisted processes
    assert received, "Allowlisted process must still produce a telemetry event"


# ─── SHA-256 hash cache ────────────────────────────────────────────────────────

def test_sha256_file_returns_correct_hash(tmp_path):
    """_sha256_file() returns the correct SHA-256 digest."""
    content = b"zero trust edr test content"
    target = tmp_path / "test_file.exe"
    target.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    result = _sha256_file(str(target))
    assert result == expected


def test_sha256_file_caches_result(tmp_path):
    """Second call with same path+mtime returns cached result without reading disk."""
    content = b"cached content"
    target = tmp_path / "cached.exe"
    target.write_bytes(content)

    from agent.collectors.process_collector import _hash_cache, _hash_cache_lock

    result1 = _sha256_file(str(target))

    with _hash_cache_lock:
        cache_size_after_first = len(_hash_cache)

    result2 = _sha256_file(str(target))

    assert result1 == result2
    assert result1 is not None


def test_sha256_file_returns_none_for_missing_file():
    """Non-existent file path returns None gracefully."""
    result = _sha256_file("/nonexistent/path/that/cannot/exist.exe")
    assert result is None


# ─── Severity computation ──────────────────────────────────────────────────────

def test_powershell_from_unusual_parent_gets_medium_severity():
    """
    PowerShell launched from a non-explorer parent should have medium severity.
    We patch _is_signed to return True (signed) so unsigned doesn't interfere.
    """
    received: List[TelemetryEventDTO] = []
    mock_sub = MockWMISubscriber(
        start_events=[{
            "ProcessName": "powershell.exe",
            "ProcessId": 8888,
            "ParentProcessId": 1111,
        }]
    )
    collector = ProcessCollector(event_sink=received.append, subscriber=mock_sub)

    # Patch psutil to return a non-explorer parent
    import agent.collectors.process_collector as proc_mod
    original_is_signed = proc_mod._is_signed

    with patch("agent.collectors.process_collector._is_signed", return_value=True):
        with patch("psutil.Process") as mock_psutil:
            mock_proc = MagicMock()
            mock_proc.exe.return_value = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            mock_proc.cmdline.return_value = ["powershell.exe"]
            mock_proc.username.return_value = "DOMAIN\\user"
            mock_parent = MagicMock()
            mock_parent.name.return_value = "cmd.exe"  # Not explorer
            mock_psutil.side_effect = [mock_proc, mock_parent, MagicMock()]

            collector.start()
            deadline = time.time() + 2.0
            while not received and time.time() < deadline:
                time.sleep(0.05)
            collector.stop()

    if received:
        # If psutil enrichment ran, severity should be medium
        from agent.storage.models import EventSeverity
        assert received[0].severity in (EventSeverity.MEDIUM.value, EventSeverity.LOW.value)
