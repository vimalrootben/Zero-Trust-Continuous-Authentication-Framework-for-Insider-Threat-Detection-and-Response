"""
Unit tests for agent OfflineQueue (A5):
  - SQLite queue persistence across process restart
  - Priority-aware eviction under max_size capacity pressure (low severity evicted first)
  - Dequeuing and mark_synced confirmation
"""
import uuid
import pytest
from agent.storage.models import EventSeverity, TelemetryEventDTO
from agent.storage.offline_queue import OfflineQueue, QueueFullError


def test_queue_persistence_across_restart(tmp_path):
    """Queue survives process restart (data is persisted on disk, not in-memory)."""
    db_path = str(tmp_path / "offline_test.db")

    # Instance 1: enqueue event
    q1 = OfflineQueue(db_path=db_path, max_size=100)
    event_id = str(uuid.uuid4())
    evt = TelemetryEventDTO(
        event_id=event_id,
        collector_type="process",
        event_type="process_start",
        severity="medium",
        data={"cmd": "powershell.exe"},
    )
    q1.enqueue(evt)
    assert q1.queue_depth() == 1

    # Simulate process termination and restart (new instance targeting same file)
    q2 = OfflineQueue(db_path=db_path, max_size=100)
    assert q2.queue_depth() == 1

    dequeued = q2.dequeue_batch(10)
    assert len(dequeued) == 1
    assert dequeued[0].event_id == event_id
    assert dequeued[0].data["cmd"] == "powershell.exe"


def test_priority_aware_eviction(tmp_path):
    """Under max_size pressure, low-severity events are evicted before high/critical ones."""
    db_path = str(tmp_path / "eviction_test.db")
    # Set capacity max_size to 2
    q = OfflineQueue(db_path=db_path, max_size=2)

    evt_low = TelemetryEventDTO(
        collector_type="process", event_type="test", severity="low", data={"seq": 1}
    )
    evt_high = TelemetryEventDTO(
        collector_type="process", event_type="test", severity="high", data={"seq": 2}
    )
    evt_critical = TelemetryEventDTO(
        collector_type="process", event_type="test", severity="critical", data={"seq": 3}
    )

    q.enqueue(evt_low)
    q.enqueue(evt_high)
    assert q.queue_depth() == 2

    # Third enqueue triggers eviction: low severity should be dropped
    q.enqueue(evt_critical)
    assert q.queue_depth() == 2

    events = q.dequeue_batch(10)
    severities = [e.severity for e in events]

    assert "critical" in severities
    assert "high" in severities
    assert "low" not in severities


def test_mark_synced_removes_events(tmp_path):
    """mark_synced deletes specified events from SQLite queue."""
    db_path = str(tmp_path / "mark_synced_test.db")
    q = OfflineQueue(db_path=db_path, max_size=10)

    evt1 = TelemetryEventDTO(collector_type="file", event_type="create", data={})
    evt2 = TelemetryEventDTO(collector_type="file", event_type="modify", data={})

    q.enqueue(evt1)
    q.enqueue(evt2)
    assert q.queue_depth() == 2

    # Mark evt1 as synced
    deleted = q.mark_synced([evt1.event_id])
    assert deleted == 1
    assert q.queue_depth() == 1

    remaining = q.dequeue_batch(10)
    assert remaining[0].event_id == evt2.event_id
