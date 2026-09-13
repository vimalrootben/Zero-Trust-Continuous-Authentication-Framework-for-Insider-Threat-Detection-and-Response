"""Durable cache, collection checkpoints and command execution journal."""
import json


class AgentState:
    def __init__(self, queue):
        self.queue = queue
        with queue._get_connection() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS agent_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS command_journal (command_id TEXT PRIMARY KEY, payload TEXT NOT NULL, report TEXT, reported INTEGER NOT NULL DEFAULT 0)')

    def get(self, key, default=None):
        with self.queue._get_connection() as conn:
            row = conn.execute('SELECT value FROM agent_state WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        with self.queue._get_connection() as conn:
            conn.execute('INSERT INTO agent_state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, json.dumps(value)))
