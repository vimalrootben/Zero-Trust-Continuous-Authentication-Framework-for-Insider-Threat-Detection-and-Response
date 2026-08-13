"""
Unit tests for OfflineSyncManager (A5):
  - Reconnect flush sends batches in sequence and marks confirmed events synced.
  - Mid-batch network error halts flushing without deleting unacknowledged events.
"""
import uuid
from unittest.mock import AsyncMock, MagicMock
import pytest

from agent.communication.transport import TransportError
from agent.storage.models import TelemetryEventDTO
from agent.storage.offline_queue import OfflineQueue
from agent.storage.offline_sync_manager import OfflineSyncManager


@pytest.mark.asyncio
async def test_flush_on_reconnect_success(tmp_path):
    """Flushes queued events and removes them from SQLite upon manager confirmation."""
    db_path = str(tmp_path / "sync_success.db")
    queue = OfflineQueue(db_path=db_path, max_size=100)

    # Queue 3 events
    for i in range(3):
        queue.enqueue(
            TelemetryEventDTO(collector_type="network", event_type="connect", data={"i": i})
        )
    assert queue.queue_depth() == 3

    mock_transport = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_transport.post = AsyncMock(return_value=mock_response)

    sync_mgr = OfflineSyncManager(
        queue=queue,
        transport=mock_transport,
        agent_id=str(uuid.uuid4()),
        batch_size=2,
    )

    result = await sync_mgr.flush_on_reconnect()

    assert result.success is True
    assert result.synced_count == 3
    assert queue.queue_depth() == 0


@pytest.mark.asyncio
async def test_flush_on_reconnect_stops_on_network_failure(tmp_path):
    """Network failure during flush halts flushing without losing queued events."""
    db_path = str(tmp_path / "sync_failure.db")
    queue = OfflineQueue(db_path=db_path, max_size=100)

    for i in range(5):
        queue.enqueue(
            TelemetryEventDTO(collector_type="process", event_type="start", data={"i": i})
        )
    assert queue.queue_depth() == 5

    mock_transport = MagicMock()
    mock_transport.post = AsyncMock(side_effect=TransportError("Connection reset by peer"))

    sync_mgr = OfflineSyncManager(
        queue=queue,
        transport=mock_transport,
        agent_id=str(uuid.uuid4()),
        batch_size=2,
    )

    result = await sync_mgr.flush_on_reconnect()

    assert result.success is False
    # Queue depth must remain 5 — no data loss!
    assert queue.queue_depth() == 5
