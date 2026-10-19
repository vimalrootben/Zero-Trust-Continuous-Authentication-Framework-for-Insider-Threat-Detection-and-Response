import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from zta.agent.agent_daemon import ZTAAgentDaemon
from zta.agent.storage.offline_queue import OfflineQueue
from zta.api.server import create_zta_server
from zta.storage.database import ZTADatabase, ZTARepository


def test_manager_and_agent_sqlite_are_wal_bounded_and_enforce_relations(tmp_path):
    db = ZTADatabase(str(tmp_path / "manager.db"), seed_defaults=False)
    with db.get_connection() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("""INSERT INTO command_results(result_id,command_id,agent_id,status,evidence_json,received_at)
                VALUES('result','missing','agent','FAILED','{}','2026-10-15T00:00:00+00:00')""")
    queue = OfflineQueue(str(tmp_path / "agent.db"))
    with queue._get_connection() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 30000


def test_clean_manager_start_stop_and_migration_restart(tmp_path):
    path = tmp_path / "nested" / "manager.db"
    server = create_zta_server(port=0, db_path=path)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    assert thread.is_alive()
    server.shutdown(); thread.join(timeout=5); server.server_close()
    assert not thread.is_alive()
    reopened = ZTADatabase(str(path), seed_defaults=False)
    with reopened.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] >= 1


def test_concurrent_manager_writes_recover_without_loss(tmp_path):
    repo = ZTARepository(ZTADatabase(str(tmp_path / "concurrent.db"), seed_defaults=False))
    def write(number):
        repo.save_audit("LOAD_TEST", "bounded concurrent write", details={"correlation_id": f"load-{number}"})
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(write, range(100)))
    assert len(repo.get_audit_logs(limit=200, event_type="LOAD_TEST")) == 100


def test_remote_cleartext_and_incomplete_mtls_are_refused(tmp_path, monkeypatch):
    agent = ZTAAgentDaemon(manager_url="http://192.0.2.10:8080", db_path=str(tmp_path / "agent.db"),
                           agent_id="agent-secure", token="secret")
    with pytest.raises(ValueError, match="requires HTTPS"):
        agent.post("/api/v1/agents/heartbeat", {})
    agent.manager_url = "https://manager.example"
    monkeypatch.setenv("ZTA_CLIENT_CERT", "client.pem"); monkeypatch.delenv("ZTA_CLIENT_KEY", raising=False)
    with pytest.raises(ValueError, match="Both ZTA_CLIENT_CERT"):
        agent.post("/api/v1/agents/heartbeat", {})


def test_multi_agent_command_delivery_is_identity_isolated(tmp_path):
    repo = ZTARepository(ZTADatabase(str(tmp_path / "isolation.db"), seed_defaults=False))
    now = "2026-10-15T00:00:00+00:00"
    with repo.db.get_connection() as conn:
        for command_id, agent_id in (("cmd-a", "agent-a"), ("cmd-b", "agent-b")):
            conn.execute("""INSERT INTO commands(command_id,agent_id,action_type,params_json,status,created_at)
                VALUES(?,?,?,'{}','QUEUED',?)""", (command_id, agent_id, "DEMO_SCRIPT", now))
    assert [row["command_id"] for row in repo.get_pending_commands("agent-a")] == ["cmd-a"]
    assert [row["command_id"] for row in repo.get_pending_commands("agent-b")] == ["cmd-b"]
