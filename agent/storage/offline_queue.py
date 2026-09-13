"""Durable Agent queue; capacity warnings never discard unsynchronized data."""

import json
import logging
import sqlite3
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union


class OfflineQueueError(Exception):
    """Raised when offline queue storage encounters a fatal database error."""
    pass


class QueueFullError(OfflineQueueError):
    """Raised when the offline queue reaches capacity and priority eviction fails."""
    pass


class OfflineQueue:
    """Manages offline telemetry events in a local SQLite database when manager is unreachable."""

    def __init__(self, db_path: str = "zta_agent_offline.db", max_size: int = 10000):
        Path(db_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self.db_path = str(Path(db_path).expanduser().resolve())
        self.max_size = max_size
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a connection to local SQLite database."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            raise OfflineQueueError(f"Database connection failed: {str(e)}")

    def _init_db(self):
        """Initializes offline events table schema."""
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS offline_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE NOT NULL,
                        collector_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        timestamp TEXT NOT NULL
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            raise OfflineQueueError(f"Failed to initialize offline queue table: {str(e)}")

    def queue_depth(self) -> int:
        """Returns current count of queued offline events."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM offline_events")
                return cursor.fetchone()[0]
        except sqlite3.Error as e:
            raise OfflineQueueError(f"Failed to fetch queue depth: {str(e)}")

    def enqueue(
        self,
        event_id: Union[str, Dict[str, Any]],
        collector_type: str = "PROCESS",
        severity: str = "MEDIUM",
        payload: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ):
        """Enqueues a telemetry event for offline storage."""
        if isinstance(event_id, dict):
            payload = event_id
            evt_id = payload.get("id") or payload.get("event_id") or f"evt-{uuid.uuid4().hex[:8]}"
            collector_type = payload.get("collector_type") or payload.get("event_type") or "PROCESS"
            severity = payload.get("severity", "MEDIUM")
            timestamp = payload.get("timestamp")
            event_id = str(evt_id)
        elif payload is None:
            payload = {"event_id": event_id}

        ts = timestamp or datetime.now(timezone.utc).isoformat()
        try:
            with self._get_connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    "SELECT collector_type, severity, payload_json FROM offline_events WHERE event_id=?",
                    (event_id,),
                ).fetchone()
                encoded = json.dumps(payload, sort_keys=True)
                if existing:
                    if (existing["collector_type"] != collector_type or existing["severity"] != severity
                            or json.loads(existing["payload_json"]) != payload):
                        raise OfflineQueueError("Conflicting payload for existing event ID")
                    return
                # The configured capacity is a warning threshold, never permission to discard data.
                if conn.execute("SELECT COUNT(*) FROM offline_events").fetchone()[0] >= self.max_size:
                    logging.getLogger(__name__).warning("offline_queue.capacity_exceeded", extra={"max_size": self.max_size})
                conn.execute(
                    "INSERT INTO offline_events (event_id, collector_type, severity, payload_json, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (event_id, collector_type, severity, encoded, ts),
                )
        except sqlite3.Error as e:
            raise OfflineQueueError(f"Failed to enqueue event {event_id}: {str(e)}")

    def get_pending_batch(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Alias for dequeue_batch."""
        return self.dequeue_batch(batch_size=limit)

    def dequeue_batch(self, batch_size: int = 50) -> List[Dict[str, Any]]:
        """Dequeues up to batch_size oldest offline events for sync."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT event_id, collector_type, severity, payload_json, timestamp FROM offline_events ORDER BY id ASC LIMIT ?",
                    (batch_size,),
                )
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    item = dict(row)
                    item["payload"] = json.loads(item.pop("payload_json"))
                    results.append(item)
                return results
        except sqlite3.Error as e:
            raise OfflineQueueError(f"Failed to dequeue batch: {str(e)}")


    def mark_synced(self, event_ids: List[str]):
        """Deletes synced event IDs from local SQLite queue post-acknowledgement."""
        if not event_ids:
            return
        try:
            with self._get_connection() as conn:
                placeholders = ",".join("?" for _ in event_ids)
                conn.execute(f"DELETE FROM offline_events WHERE event_id IN ({placeholders})", event_ids)
                conn.commit()
        except sqlite3.Error as e:
            raise OfflineQueueError(f"Failed to mark events synced: {str(e)}")
