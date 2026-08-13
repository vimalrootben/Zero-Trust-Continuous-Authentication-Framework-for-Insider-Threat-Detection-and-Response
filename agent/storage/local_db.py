"""
LocalDatabase — SQLite database manager for the agent's disk-persisted offline storage.
"""
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class LocalDatabase:
    """
    Manages the local SQLite database for offline telemetry queuing.
    Ensures schema creation and provides thread-safe connection context.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._ensure_db_dir()
        self._init_schema()

    def _ensure_db_dir(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Returns a connection with WAL mode enabled for concurrent performance."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_schema(self) -> None:
        """Initialize the local database tables if they do not exist."""
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS offline_events (
                    event_id TEXT PRIMARY KEY,
                    collector_type TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'low',
                    priority_rank INTEGER NOT NULL DEFAULT 1,
                    timestamp TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_offline_events_priority_timestamp
                ON offline_events (priority_rank DESC, timestamp ASC);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_offline_events_severity
                ON offline_events (severity);
            """)
            conn.commit()
        logger.debug(f"Local SQLite schema initialized at {self.db_path}")
