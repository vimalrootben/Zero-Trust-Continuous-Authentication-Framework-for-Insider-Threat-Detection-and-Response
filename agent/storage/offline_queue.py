"""
OfflineQueue — Persistent, priority-aware offline queue backed by SQLite.

Eviction Policy:
  - Drops lowest priority events first (`low` -> `medium` -> `high`).
  - `critical` events are strictly protected and never dropped unless the queue
    is 100% full of critical events.
  - Data is disk-persisted — survives agent process restarts.
"""
import json
import logging
import sqlite3
from typing import List, Optional

from agent.storage.local_db import LocalDatabase
from agent.storage.models import EventSeverity, TelemetryEventDTO

logger = logging.getLogger(__name__)


class QueueFullError(Exception):
    """Raised when the queue reaches max_size and no evictable events can be dropped."""


class OfflineQueue:
    """
    Disk-backed offline queue for agent telemetry events.
    """

    def __init__(self, db_path: str, max_size: int = 100000) -> None:
        self.db_path = db_path
        self.max_size = max_size
        self.db = LocalDatabase(db_path)

    def queue_depth(self) -> int:
        """Return total count of queued events."""
        with self.db.get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM offline_events;")
            return cursor.fetchone()[0]

    def enqueue(self, event: TelemetryEventDTO) -> None:
        """
        Enqueue a telemetry event.

        If current depth >= max_size, attempts priority-aware eviction first:
        drops the oldest lowest-severity event.
        Raises QueueFullError if no event can be dropped.
        """
        depth = self.queue_depth()
        if depth >= self.max_size:
            evicted = self._evict_one()
            if not evicted:
                raise QueueFullError(
                    f"Offline queue reached maximum capacity ({self.max_size}) "
                    "and no evictable lower-priority events were available."
                )

        priority_rank = EventSeverity.priority_rank(event.severity)
        data_json = json.dumps(event.data)

        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO offline_events 
                (event_id, collector_type, event_type, severity, priority_rank, timestamp, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event.event_id,
                    event.collector_type,
                    event.event_type,
                    event.severity,
                    priority_rank,
                    event.timestamp,
                    data_json,
                ),
            )
            conn.commit()

        logger.debug(f"Queued offline event: {event.event_id} ({event.collector_type}:{event.event_type})")

    def _evict_one(self) -> bool:
        """
        Evict the oldest lowest-priority event.
        Returns True if an event was evicted, False otherwise.
        """
        with self.db.get_connection() as conn:
            # Find the oldest event with the minimum priority rank currently in DB
            cursor = conn.execute(
                """
                SELECT event_id, severity, priority_rank 
                FROM offline_events 
                ORDER BY priority_rank ASC, timestamp ASC 
                LIMIT 1;
                """
            )
            row = cursor.fetchone()
            if not row:
                return False

            event_id = row["event_id"]
            severity = row["severity"]

            conn.execute("DELETE FROM offline_events WHERE event_id = ?;", (event_id,))
            conn.commit()

            logger.warning(
                f"Offline queue full: evicted oldest event {event_id} (severity={severity})"
            )
            return True

    def dequeue_batch(self, batch_size: int) -> List[TelemetryEventDTO]:
        """
        Fetch up to `batch_size` events ordered by highest priority first, then oldest timestamp.
        Does NOT delete events from DB — events remain until mark_synced() is called.
        """
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT event_id, collector_type, event_type, severity, timestamp, data_json
                FROM offline_events
                ORDER BY priority_rank DESC, timestamp ASC
                LIMIT ?;
                """,
                (batch_size,),
            )
            rows = cursor.fetchall()

        events: List[TelemetryEventDTO] = []
        for row in rows:
            try:
                data = json.loads(row["data_json"])
            except Exception:
                data = {}
            events.append(
                TelemetryEventDTO(
                    event_id=row["event_id"],
                    collector_type=row["collector_type"],
                    event_type=row["event_type"],
                    severity=row["severity"],
                    timestamp=row["timestamp"],
                    data=data,
                )
            )
        return events

    def mark_synced(self, event_ids: List[str]) -> int:
        """
        Delete rows for confirmed synced events from SQLite.
        Returns number of deleted rows.
        """
        if not event_ids:
            return 0

        placeholders = ",".join("?" for _ in event_ids)
        with self.db.get_connection() as conn:
            cursor = conn.execute(
                f"DELETE FROM offline_events WHERE event_id IN ({placeholders});",
                event_ids,
            )
            deleted_count = cursor.rowcount
            conn.commit()

        logger.debug(f"Marked {deleted_count} events as synced and removed from local queue.")
        return deleted_count

    def clear(self) -> None:
        """Utility to wipe local queue (useful for test resets)."""
        with self.db.get_connection() as conn:
            conn.execute("DELETE FROM offline_events;")
            conn.commit()
