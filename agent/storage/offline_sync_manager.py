"""
OfflineSyncManager — Handles flushing persistent offline telemetry queues upon reconnection.
"""
import logging
import uuid
from typing import Optional

from agent.communication.transport import AuthenticationError, SecureTransport, TransportError
from agent.storage.models import SyncResult, TelemetryBatchDTO
from agent.storage.offline_queue import OfflineQueue

logger = logging.getLogger(__name__)


class OfflineSyncManager:
    """
    Orchestrates batch flushing of offline telemetry events upon manager connection restoration.
    """

    def __init__(
        self,
        queue: OfflineQueue,
        transport: SecureTransport,
        agent_id: str,
        batch_size: int = 100,
    ) -> None:
        self.queue = queue
        self.transport = transport
        self.agent_id = agent_id
        self.batch_size = batch_size

    async def flush_on_reconnect(self) -> SyncResult:
        """
        Flush all queued events to the manager in batches of `batch_size`.

        Stops cleanly if a batch submission encounters a network failure or error,
        leaving unsynced events in the local SQLite queue for subsequent retries.

        Returns:
            SyncResult: Summary of synced events, failures, and remaining queue depth.
        """
        initial_depth = self.queue.queue_depth()
        if initial_depth == 0:
            return SyncResult(synced_count=0, failed_count=0, remaining_depth=0, success=True)

        logger.info(f"Initiating offline telemetry flush: {initial_depth} events queued.")

        total_synced = 0
        total_failed = 0

        while True:
            batch_events = self.queue.dequeue_batch(self.batch_size)
            if not batch_events:
                break

            batch_id = str(uuid.uuid4())
            batch_dto = TelemetryBatchDTO(
                agent_id=self.agent_id,
                batch_id=batch_id,
                events=batch_events,
            )

            try:
                response = await self.transport.post(
                    "/agent/telemetry", json=batch_dto.to_dict()
                )

                if response.status_code in (200, 202):
                    event_ids = [e.event_id for e in batch_events]
                    self.queue.mark_synced(event_ids)
                    total_synced += len(event_ids)
                    logger.debug(f"Flushed batch {batch_id}: {len(event_ids)} events synced.")
                else:
                    logger.warning(
                        f"Telemetry batch {batch_id} rejected with status {response.status_code}."
                    )
                    total_failed += len(batch_events)
                    # Stop flushing on server error to avoid spinning
                    break

            except AuthenticationError as e:
                logger.critical(f"Certificate authentication error during flush: {e}")
                return SyncResult(
                    synced_count=total_synced,
                    failed_count=total_failed + len(batch_events),
                    remaining_depth=self.queue.queue_depth(),
                    success=False,
                    error_message=str(e),
                )

            except TransportError as e:
                logger.warning(f"Network transport error during telemetry flush: {e}")
                return SyncResult(
                    synced_count=total_synced,
                    failed_count=total_failed + len(batch_events),
                    remaining_depth=self.queue.queue_depth(),
                    success=False,
                    error_message=str(e),
                )

        remaining = self.queue.queue_depth()
        logger.info(f"Offline telemetry flush complete: synced={total_synced}, remaining={remaining}.")
        return SyncResult(
            synced_count=total_synced,
            failed_count=total_failed,
            remaining_depth=remaining,
            success=(total_failed == 0),
        )
