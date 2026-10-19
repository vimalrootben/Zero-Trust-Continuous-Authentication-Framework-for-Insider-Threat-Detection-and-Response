"""Durable Agent queue; capacity warnings never discard unsynchronized data."""

import json
import logging
import sqlite3
import uuid
import time
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
        self._last_capacity_warning = 0.0
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a connection to local SQLite database."""
        try:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA synchronous=NORMAL")
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
                        timestamp TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'PENDING',
                        attempt_count INTEGER NOT NULL DEFAULT 0,
                        last_attempt_at TEXT,
                        next_attempt_at TEXT,
                        last_error TEXT,
                        error_class TEXT
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS command_journal (
                        command_id TEXT PRIMARY KEY,
                        correlation_id TEXT,
                        action TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        result TEXT,
                        verification TEXT,
                        timestamp TEXT NOT NULL,
                        failure_reason TEXT,
                        report TEXT,
                        reported INTEGER NOT NULL DEFAULT 0
                    )
                """)
                columns = {row[1] for row in conn.execute("PRAGMA table_info(command_journal)")}
                for name, definition in (
                    ("correlation_id", "TEXT"), ("action", "TEXT NOT NULL DEFAULT ''"),
                    ("result", "TEXT"), ("verification", "TEXT"),
                    ("timestamp", "TEXT NOT NULL DEFAULT ''"), ("failure_reason", "TEXT"),
                    ("reported", "INTEGER NOT NULL DEFAULT 0"),
                    ("target_identity", "TEXT"), ("received_at", "TEXT"),
                    ("validated_at", "TEXT"), ("execution_started_at", "TEXT"),
                    ("execution_finished_at", "TEXT"), ("verification_status", "TEXT"),
                    ("result_status", "TEXT"), ("error_code", "TEXT"),
                    ("error_message", "TEXT"), ("result_uploaded_at", "TEXT"),
                    ("state", "TEXT NOT NULL DEFAULT 'RECEIVED'"),
                ):
                    if name not in columns:
                        conn.execute(f"ALTER TABLE command_journal ADD COLUMN {name} {definition}")
                event_columns = {row[1] for row in conn.execute("PRAGMA table_info(offline_events)")}
                for name, definition in (
                    ("status", "TEXT NOT NULL DEFAULT 'PENDING'"),
                    ("attempt_count", "INTEGER NOT NULL DEFAULT 0"),
                    ("last_attempt_at", "TEXT"), ("next_attempt_at", "TEXT"),
                    ("last_error", "TEXT"), ("error_class", "TEXT"),
                ):
                    if name not in event_columns:
                        conn.execute(f"ALTER TABLE offline_events ADD COLUMN {name} {definition}")
                conn.execute("UPDATE offline_events SET status='RETRY_PENDING' WHERE status='IN_FLIGHT'")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_events_pending ON offline_events(status,next_attempt_at,id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_command_journal_upload ON command_journal(reported,state,timestamp)")
                conn.commit()
        except sqlite3.Error as e:
            raise OfflineQueueError(f"Failed to initialize offline queue table: {str(e)}")

    def recover_interrupted_commands(self, agent_id: str) -> int:
        """Make ambiguous pre-crash claims uploadable without re-executing them."""
        now = datetime.now(timezone.utc).isoformat()
        recovered = 0
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute("""SELECT * FROM command_journal
                WHERE report IS NULL AND state IN ('RECEIVED','VALIDATED','EXECUTING','VERIFYING')""").fetchall()
            for row in rows:
                payload = json.loads(row['payload'])
                report = {
                    'result_id': 'result-' + uuid.uuid5(uuid.NAMESPACE_URL, row['command_id'] + ':UNKNOWN').hex,
                    'command_id': row['command_id'], 'agent_id': agent_id,
                    'action_type': row['action'], 'status': 'UNKNOWN', 'output': '',
                    'error': 'Agent restarted with an unfinished execution claim; action was not repeated',
                    'error_code': 'INTERRUPTED_UNKNOWN', 'failure_reason': 'INTERRUPTED_UNKNOWN',
                    'verification': 'UNKNOWN', 'verification_status': 'UNKNOWN',
                    'executed_at': row['execution_started_at'] or '', 'completed_at': now,
                    'correlation_id': row['correlation_id'] or '',
                }
                conn.execute("""UPDATE command_journal SET state='UNKNOWN',result='UNKNOWN',
                    result_status='UNKNOWN',verification=?,verification_status='UNKNOWN',
                    failure_reason=?,error_code='INTERRUPTED_UNKNOWN',error_message=?,
                    execution_finished_at=?,timestamp=?,report=? WHERE command_id=?""",
                    (json.dumps('UNKNOWN'), report['failure_reason'], report['error'], now, now,
                     json.dumps(report), row['command_id']))
                recovered += 1
        return recovered

    def queue_depth(self) -> int:
        """Returns current count of queued offline events."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM offline_events")
                return cursor.fetchone()[0]
        except sqlite3.Error as e:
            raise OfflineQueueError(f"Failed to fetch queue depth: {str(e)}")

    def pending_depth(self) -> int:
        with self._get_connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM offline_events WHERE status IN ('PENDING','RETRY_PENDING','IN_FLIGHT')").fetchone()[0]

    def permanent_error_count(self) -> int:
        with self._get_connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM offline_events WHERE status='PERMANENT_ERROR'").fetchone()[0]

    def recover_legacy_batch_rejections(self) -> int:
        """Retry rows blanket-quarantined by the old whole-batch HTTP 400 behavior."""
        with self._get_connection() as conn:
            cursor = conn.execute("""UPDATE offline_events
                SET status='RETRY_PENDING',next_attempt_at=NULL,
                    last_error='Re-evaluating legacy batch rejection',error_class='TRANSIENT'
                WHERE status='PERMANENT_ERROR' AND error_class='VALIDATION' AND last_error='HTTP 400'""")
            return cursor.rowcount

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
                if (conn.execute("SELECT COUNT(*) FROM offline_events WHERE status IN ('PENDING','RETRY_PENDING','IN_FLIGHT')").fetchone()[0] >= self.max_size
                        and time.monotonic() - self._last_capacity_warning >= 300):
                    logging.getLogger(__name__).warning("offline_queue.capacity_exceeded", extra={"max_size": self.max_size})
                    self._last_capacity_warning = time.monotonic()
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

    def claim_batch(self, batch_size: int = 50) -> List[Dict[str, Any]]:
        """Atomically marks eligible rows in-flight and returns a bounded batch.

        Stale IN_FLIGHT rows (older than ZTA_INFLIGHT_TIMEOUT_SECONDS, default 60s)
        are recovered to RETRY_PENDING before the new batch is selected.  This
        prevents events from staying stuck in-flight after a transport timeout
        without requiring a process restart.
        """
        import os
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        inflight_timeout = max(30, int(os.environ.get('ZTA_INFLIGHT_TIMEOUT_SECONDS', '60')))
        stale_threshold = (now - timedelta(seconds=inflight_timeout)).isoformat()
        now_iso = now.isoformat()
        try:
            with self._get_connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                # Recover stale IN_FLIGHT events from a previous timed-out upload.
                conn.execute(
                    "UPDATE offline_events SET status='RETRY_PENDING', next_attempt_at=NULL,"
                    " last_error='Recovered from stale IN_FLIGHT state (upload timeout)', error_class='TRANSIENT'"
                    " WHERE status='IN_FLIGHT' AND last_attempt_at<=?",
                    (stale_threshold,),
                )
                rows = conn.execute(
                    "SELECT event_id,collector_type,severity,payload_json,timestamp FROM offline_events "
                    "WHERE status IN ('PENDING','RETRY_PENDING') AND (next_attempt_at IS NULL OR next_attempt_at<=?) "
                    "ORDER BY id LIMIT ?", (now_iso, max(1, int(batch_size))),
                ).fetchall()
                ids = [row['event_id'] for row in rows]
                if ids:
                    marks = ','.join('?' for _ in ids)
                    conn.execute(f"UPDATE offline_events SET status='IN_FLIGHT',attempt_count=attempt_count+1,last_attempt_at=? "
                                 f"WHERE event_id IN ({marks})", [now_iso, *ids])
                return [{**dict(row), 'payload': json.loads(row['payload_json'])} for row in rows]
        except sqlite3.Error as e:
            raise OfflineQueueError(f"Failed to claim telemetry batch: {str(e)}")


    def mark_retry(self, event_ids, error, error_class='TRANSIENT', delay_seconds=None):
        if not event_ids:
            return
        from datetime import timedelta
        with self._get_connection() as conn:
            marks = ','.join('?' for _ in event_ids)
            rows = conn.execute(f"SELECT event_id,attempt_count FROM offline_events WHERE event_id IN ({marks})", event_ids).fetchall()
            attempts = {row['event_id']: row['attempt_count'] for row in rows}
            for event_id in event_ids:
                delay = delay_seconds
                if delay is None:
                    attempt = attempts.get(event_id, 1)
                    delay = 0 if attempt <= 1 else min(300, 2 ** min(attempt - 1, 8))
                next_attempt = (datetime.now(timezone.utc) + timedelta(seconds=max(0, delay))).isoformat()
                permanent = error_class in ('PERMANENT', 'VALIDATION', 'SECURITY') or (
                    error_class == 'AUTHENTICATION' and attempts.get(event_id, 0) >= 3)
                conn.execute("UPDATE offline_events SET status=?,next_attempt_at=?,last_error=?,error_class=? WHERE event_id=?",
                             ('PERMANENT_ERROR' if permanent else 'RETRY_PENDING', next_attempt,
                              str(error)[:2000], error_class, event_id))

    def oldest_pending_age_seconds(self):
        with self._get_connection() as conn:
            row = conn.execute("SELECT timestamp FROM offline_events WHERE status IN ('PENDING','RETRY_PENDING','IN_FLIGHT') ORDER BY id LIMIT 1").fetchone()
        if not row:
            return 0
        try:
            stamp = datetime.fromisoformat(row[0].replace('Z', '+00:00'))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            return max(0, int((datetime.now(timezone.utc) - stamp).total_seconds()))
        except Exception:
            return 0


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
