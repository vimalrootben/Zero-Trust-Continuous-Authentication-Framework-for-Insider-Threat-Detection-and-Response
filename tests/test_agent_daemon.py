"""Tests for ZTA Agent Daemon and Manager Heartbeat endpoint."""

import json
import threading
import time
from http.server import HTTPServer
from unittest.mock import patch, MagicMock

import pytest
import requests

from zta.agent.agent_daemon import ZTAAgentDaemon
from zta.api.server import create_zta_server


# ─── Agent Daemon Unit Tests ──────────────────────────────────────────────────


class TestZTAAgentDaemon:
    """Unit tests for ZTAAgentDaemon class."""

    def test_instantiation(self, tmp_path):
        """Daemon initialises with correct defaults and OfflineQueue connects."""
        db = tmp_path / "test.db"
        daemon = ZTAAgentDaemon(manager_url="http://10.0.0.1:9090", db_path=str(db))
        assert daemon.manager_url == "http://10.0.0.1:9090"
        assert daemon.is_running is False
        assert daemon.offline_queue is not None

    def test_get_system_telemetry_structure(self, tmp_path):
        """Telemetry dict contains all required fields."""
        db = tmp_path / "test.db"
        daemon = ZTAAgentDaemon(db_path=str(db))
        telem = daemon.get_system_telemetry()
        required_keys = {"agent_id", "hostname", "os", "platform", "python_version", "timestamp"}
        assert required_keys.issubset(telem.keys())
        assert telem["timestamp"].endswith("Z")

    def test_heartbeat_failure_queues_offline_event(self, tmp_path):
        """When Manager is unreachable, heartbeat failure is queued to OfflineQueue."""
        db = tmp_path / "offline.db"
        daemon = ZTAAgentDaemon(manager_url="http://192.0.2.1:1", db_path=str(db))

        with patch("zta.agent.agent_daemon.requests.post", side_effect=requests.ConnectionError("Manager unreachable")):
            result = daemon.send_heartbeat()
        assert result is False
        assert daemon.offline_queue.queue_depth() >= 1

        batch = daemon.offline_queue.dequeue_batch(10)
        assert len(batch) >= 1
        assert batch[0]["collector_type"] == "HEARTBEAT_FAILURE"

    def test_heartbeat_success_with_mock_server(self, tmp_path):
        """When Manager responds 200 with pending_commands, heartbeat returns True."""
        db = tmp_path / "offline.db"
        daemon = ZTAAgentDaemon(manager_url="http://127.0.0.1:8080", db_path=str(db))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "ACKNOWLEDGED",
            "agent_id": "test",
            "pending_commands": []
        }

        with patch("zta.agent.agent_daemon.requests.post", return_value=mock_response):
            result = daemon.send_heartbeat()
        assert result is True

    def test_heartbeat_processes_pending_commands(self, tmp_path):
        """Commands received in heartbeat response are dispatched to AgentCommandReceiver."""
        db = tmp_path / "offline.db"
        daemon = ZTAAgentDaemon(manager_url="http://127.0.0.1:8080", db_path=str(db))

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "ACKNOWLEDGED",
            "agent_id": "test",
            "pending_commands": [
                {"command_id": "cmd-99", "action": "KILL_PROCESS", "params": {"ProcessName": "notepad.exe"}}
            ]
        }

        with patch("zta.agent.agent_daemon.requests.post", return_value=mock_response):
            result = daemon.send_heartbeat()
        assert result is True

    def test_sync_offline_queue_noop_when_empty(self, tmp_path):
        """sync_offline_queue does nothing when queue is empty."""
        db = tmp_path / "offline.db"
        daemon = ZTAAgentDaemon(manager_url="http://127.0.0.1:8080", db_path=str(db))
        # Should not raise or call requests
        daemon.sync_offline_queue()


# ─── Heartbeat API Integration Test ──────────────────────────────────────────


class TestHeartbeatEndpoint:
    """Integration test for /api/v1/agents/heartbeat on the ZTA API server."""

    @pytest.fixture(autouse=True)
    def _start_server(self, tmp_path):
        """Start ZTA API server on a random port for testing."""
        self.server = create_zta_server(port=0, db_path=tmp_path / "api.db")
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        yield
        self.server.shutdown()
        self.server.server_close()

    def test_heartbeat_post_returns_acknowledged(self):
        """POST to /api/v1/agents/heartbeat returns ACKNOWLEDGED JSON."""
        url = f"http://127.0.0.1:{self.port}/api/v1/agents/heartbeat"
        payload = {
            "agent_id": "TEST-HOST-01",
            "hostname": "TEST-HOST-01",
            "os": "Windows",
            "timestamp": "2026-09-02T04:00:00Z"
        }
        resp = requests.post(url, json=payload, headers={"Authorization":"Bearer fixture-agent-token"}, timeout=5)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ACKNOWLEDGED"
        assert data["agent_id"] == "TEST-HOST-01"
        assert "pending_commands" in data
        assert isinstance(data["pending_commands"], list)

    def test_heartbeat_post_empty_body(self):
        """Reject empty heartbeats instead of creating an unknown agent."""
        url = f"http://127.0.0.1:{self.port}/api/v1/agents/heartbeat"
        resp = requests.post(url, data=b"", headers={"Content-Length": "0"}, timeout=5)
        assert resp.status_code == 400
        assert "error" in resp.json()

    def test_heartbeat_get_returns_404(self):
        """GET to heartbeat path should return 404 (only POST is handled)."""
        url = f"http://127.0.0.1:{self.port}/api/v1/agents/heartbeat"
        resp = requests.get(url, timeout=5)
        assert resp.status_code == 404


def test_offline_matched_event_is_persisted(tmp_path):
    from datetime import datetime, timezone
    from zta.engine.events.models import ZTAAgent, ZTAEvent, ZTAProcess
    from zta.agent.commands.command_receiver import CommandExecutionReport

    daemon = ZTAAgentDaemon(db_path=str(tmp_path / "offline.db"))
    event = ZTAEvent("offline-match", datetime.now(timezone.utc), ZTAAgent("a", "host"),
                     process=ZTAProcess(name="powershell.exe", command_line="powershell -enc abc"))
    report = CommandExecutionReport("offline-command", "LOGOUT_USER", "FAILED", "", error="test executor")
    with patch.object(daemon.command_receiver, "process_command", return_value=report):
        result = daemon.process_offline_event(event)
    queued = daemon.offline_queue.dequeue_batch()
    assert len(queued) == 1
    assert queued[0]["event_id"] == event.event_id
    assert queued[0]["payload"]["normalized_event"]["event_id"] == event.event_id
    assert result is None  # No authenticated offline policy cache: no action.


@pytest.mark.parametrize("outcome, expected_state, remaining", [
    (requests.ConnectionError("unreachable"), "OFFLINE", 2),
    (503, "DEGRADED", 2),
    (None, "DEGRADED", 2),
    (["one"], "SYNCING", 1),
    (["one", "two"], "ONLINE", 0),
])
def test_sync_state_and_queue_retention(tmp_path, outcome, expected_state, remaining):
    daemon = ZTAAgentDaemon(db_path=str(tmp_path / "offline.db"))
    daemon.offline_queue.enqueue({"id": "one"})
    daemon.offline_queue.enqueue({"id": "two"})
    response = MagicMock(status_code=outcome if isinstance(outcome, int) else 201)
    response.json.return_value = {"accepted_event_ids": outcome}
    with patch("zta.agent.agent_daemon.requests.post", return_value=response,
               side_effect=outcome if isinstance(outcome, Exception) else None):
        daemon.sync_offline_queue()
    assert daemon.connection_state == expected_state
    assert daemon.offline_queue.queue_depth() == remaining
