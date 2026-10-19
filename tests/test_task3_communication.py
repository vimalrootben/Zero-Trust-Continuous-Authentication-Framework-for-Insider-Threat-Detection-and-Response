"""Focused Task 3 communication and durable synchronization tests."""
import json
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

from zta.agent.agent_daemon import ZTAAgentDaemon
from zta.agent.connection import ConnectionStateMachine, InvalidConnectionTransition
from zta.agent.storage.offline_queue import OfflineQueue
from zta.agent.workers import BackgroundWorkerSupervisor
from zta.api.server import create_zta_server
from zta.storage.database import ZTADatabase, ZTARepository


def test_explicit_connection_state_machine_rejects_invalid_transition():
    machine = ConnectionStateMachine()
    assert machine.state == "STARTING"
    machine.transition("CONNECTING")
    machine.transition("ONLINE")
    with pytest.raises(InvalidConnectionTransition):
        machine.transition("STOPPED")
    machine.transition("STOPPING")
    machine.transition("STOPPED")


def test_queue_claim_retry_metadata_and_restart_recovery(tmp_path):
    path = tmp_path / "agent.db"
    queue = OfflineQueue(str(path))
    queue.enqueue("event-1", "process", "LOW", {"id": "event-1"}, "2026-01-01T00:00:00+00:00")
    claimed = queue.claim_batch(10)
    assert [item["event_id"] for item in claimed] == ["event-1"]
    with queue._get_connection() as conn:
        row = conn.execute("SELECT status,attempt_count FROM offline_events WHERE event_id='event-1'").fetchone()
        assert tuple(row) == ("IN_FLIGHT", 1)
    restarted = OfflineQueue(str(path))
    with restarted._get_connection() as conn:
        row = conn.execute("SELECT status FROM offline_events WHERE event_id='event-1'").fetchone()
        assert row[0] == "RETRY_PENDING"
    restarted.mark_retry(["event-1"], "invalid payload", "VALIDATION")
    with restarted._get_connection() as conn:
        row = conn.execute("SELECT status,error_class,last_error FROM offline_events WHERE event_id='event-1'").fetchone()
        assert tuple(row) == ("PERMANENT_ERROR", "VALIDATION", "invalid payload")


def test_reconnect_backoff_is_exponential_and_bounded():
    class FakeStop:
        def __init__(self):
            self.delays = []
        def is_set(self):
            return len(self.delays) >= 3
        def wait(self, delay):
            self.delays.append(delay)
            return self.is_set()

    stop = FakeStop()
    supervisor = BackgroundWorkerSupervisor(stop)
    supervisor.register("connection", lambda: (_ for _ in ()).throw(ConnectionError("down")), 1, max_backoff=4)
    supervisor._run(supervisor._workers["connection"])
    assert stop.delays == [2, 4, 4]
    assert supervisor.snapshot()["connection"]["restart_count"] == 3


def test_manager_heartbeat_uses_receipt_time_and_authoritative_state(tmp_path, monkeypatch):
    monkeypatch.setenv("ZTA_AGENT_TOKENS", json.dumps({"task3-agent": "secret"}))
    server = create_zta_server(port=0, db_path=tmp_path / "manager.db")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        url = f"http://127.0.0.1:{server.server_port}/api/v1/agents/heartbeat"
        response = requests.post(url, json={"agent_id": "task3-agent", "hostname": "host",
                                 "connection_state": "RECONNECTING", "timestamp": future, "queue_depth": 0},
                                 headers={"Authorization": "Bearer secret"}, timeout=5)
        assert response.status_code == 200
        agent = server.runtime[0].get_agents()[0]
        assert agent["connection_state"] == "ONLINE"
        assert agent["agent_reported_time"] == future
        assert agent["manager_received_time"] != future
        denied = requests.post(url, json={"agent_id": "task3-agent", "hostname": "host"},
                               headers={"Authorization": "Bearer wrong"}, timeout=5)
        assert denied.status_code in (400, 401)
    finally:
        server.shutdown()
        server.server_close()


def test_manager_liveness_degrades_expires_and_recovers(tmp_path, monkeypatch):
    monkeypatch.setenv("ZTA_HEARTBEAT_DEGRADED_SECONDS", "10")
    monkeypatch.setenv("ZTA_HEARTBEAT_OFFLINE_SECONDS", "20")
    repo = ZTARepository(ZTADatabase(tmp_path / "liveness.db"))
    repo.save_heartbeat({"agent_id": "agent", "hostname": "host", "connection_state": "ONLINE"})
    with repo.db.get_connection() as conn:
        conn.execute("UPDATE agents SET last_seen=?,manager_received_time=? WHERE id='agent'",
                     ((datetime.now(timezone.utc) - timedelta(seconds=15)).isoformat(),) * 2)
    assert repo.get_agents()[0]["connection_state"] == "DEGRADED"
    with repo.db.get_connection() as conn:
        conn.execute("UPDATE agents SET last_seen=? WHERE id='agent'",
                     ((datetime.now(timezone.utc) - timedelta(seconds=25)).isoformat(),))
    assert repo.get_agents()[0]["connection_state"] == "OFFLINE"
    repo.save_heartbeat({"agent_id": "agent", "hostname": "host", "connection_state": "RECONNECTING"})
    assert repo.get_agents()[0]["connection_state"] == "ONLINE"


def test_lost_acknowledgement_retries_idempotently(tmp_path, monkeypatch):
    monkeypatch.setenv("ZTA_AGENT_TOKENS", json.dumps({"task3-agent": "secret"}))
    server = create_zta_server(port=0, db_path=tmp_path / "manager.db")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    agent = ZTAAgentDaemon(f"http://127.0.0.1:{server.server_port}", str(tmp_path / "agent.db"),
                           agent_id="task3-agent", token="secret")
    payload = {"id": "lost-ack-event", "timestamp": "2026-10-14T12:00:00Z",
               "agent": {"id": "task3-agent", "name": "host"}, "event_type": "PROCESS_STARTED",
               "process": {"pid": 123, "name": "harmless.exe"}}
    agent.offline_queue.enqueue("lost-ack-event", "process", "LOW", payload, payload["timestamp"])
    original = agent.post
    committed = {"once": False}

    def lose_first_ack(path, body, timeout=10):
        response = original(path, body, timeout)
        if not committed["once"]:
            committed["once"] = True
            raise requests.ConnectionError("response lost after commit")
        return response

    try:
        agent.connection_state = "ONLINE"
        with patch.object(agent, "post", side_effect=lose_first_ack):
            assert agent.sync_offline_queue() is False
        assert agent.offline_queue.queue_depth() == 1
        agent.connection_state = "ONLINE"
        assert agent.sync_offline_queue() is True
        assert agent.offline_queue.queue_depth() == 0
        with server.runtime[0].db.get_connection() as conn:
            assert conn.execute("SELECT COUNT(*) FROM zta_events WHERE event_id='lost-ack-event'").fetchone()[0] == 1
    finally:
        server.shutdown()
        server.server_close()


def test_tls_verification_and_mtls_configuration_are_preserved(tmp_path, monkeypatch):
    agent = ZTAAgentDaemon("https://manager.example", str(tmp_path / "agent.db"), agent_id="a", token="secret")
    monkeypatch.setenv("ZTA_CA_BUNDLE", "trusted-ca.pem")
    monkeypatch.setenv("ZTA_CLIENT_CERT", "agent-cert.pem")
    monkeypatch.setenv("ZTA_CLIENT_KEY", "agent-key.pem")
    with patch("zta.agent.agent_daemon.requests.post", return_value=MagicMock(status_code=200)) as request:
        agent.post("/api/v1/agents/heartbeat", {"agent_id": "a"})
    assert request.call_args.kwargs["verify"] == "trusted-ca.pem"
    assert request.call_args.kwargs["cert"] == ("agent-cert.pem", "agent-key.pem")
    monkeypatch.delenv("ZTA_CLIENT_KEY")
    with pytest.raises(ValueError, match="Both ZTA_CLIENT_CERT"):
        agent.post("/api/v1/agents/heartbeat", {"agent_id": "a"})


def test_heartbeat_queues_commands_when_background_workers_are_running(tmp_path):
    agent = ZTAAgentDaemon("http://127.0.0.1:8080", str(tmp_path / "agent.db"), agent_id="a", token="secret")
    response = MagicMock(status_code=200)
    response.json.return_value = {"pending_commands": [{"command_id": "safe-command"}]}
    agent.worker_supervisor._started = True
    with patch.object(agent, "post", return_value=response), patch.object(agent, "execute_command") as execute:
        assert agent.send_heartbeat()
    execute.assert_not_called()
    assert agent.command_queue.get_nowait()["command_id"] == "safe-command"
