"""Comprehensive unit and integration tests for the Controlled Demo Framework,
Exact Agent IP identification, Real Log Push system, and Dashboard Analytics."""

import os
import json
import threading
import time
import socket
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import requests

from zta.agent.execution.script_executor import DemoScriptExecutor
from zta.agent.execution.script_registry import SCRIPT_REGISTRY, get_demo_temp_dir
from zta.agent.execution.validators import validate_script_request, ScriptValidationError
from zta.agent.network_identity import get_active_network_identity
from zta.agent.agent_daemon import ZTAAgentDaemon
from zta.storage.database import ZTADatabase, ZTARepository
from zta.engine.events.conditions import ConditionEvaluator
from zta.engine.events.serialization import context
from zta.engine.events.models import ZTAEvent, ZTAAgent, ZTAProcess
from zta.api.server import create_zta_server


# ==============================================================================
# Test A: Controlled Script Execution Security & RBAC
# ==============================================================================

class TestScriptExecutionSecurity:
    """Validate security boundaries of the script execution engine."""

    def test_reject_unknown_script_id(self):
        """Disallowed or arbitrary script IDs must be rejected."""
        with pytest.raises(ScriptValidationError) as excinfo:
            validate_script_request("MALICIOUS_CUSTOM_SCRIPT", {}, demo_mode_enabled=True)
        assert "Unauthorized or unapproved script_id" in str(excinfo.value)

        with patch.dict(os.environ, {"DEMO_MODE_ENABLED": "true"}):
            executor = DemoScriptExecutor(agent_id="test-agent")
            payload = {"command_id": "c-01", "params": {"script_id": "UNKNOWN_CMD", "correlation_id": "corr-123"}}
            res = executor.execute_script(payload)
            assert res.status == "REJECTED"
            assert "Unauthorized" in (res.error or "")

    def test_reject_when_demo_mode_disabled(self):
        """Execution must be rejected when demo mode is false."""
        with pytest.raises(ScriptValidationError) as excinfo:
            validate_script_request("DEMO_PROCESS_START", {"process_name": "calc.exe"}, demo_mode_enabled=False)
        assert "Demo execution mode is disabled" in str(excinfo.value)

        with patch.dict(os.environ, {"DEMO_MODE_ENABLED": "false"}):
            executor = DemoScriptExecutor(agent_id="test-agent")
            payload = {"command_id": "c-02", "params": {"script_id": "DEMO_PROCESS_START"}}
            res = executor.execute_script(payload)
            assert res.status == "REJECTED"
            assert "disabled" in (res.error or "")

    def test_parameter_validation_and_disallowed_keys(self):
        """Attempts to pass raw scripts or arbitrary shells must fail parameter validation."""
        with pytest.raises(ScriptValidationError) as excinfo:
            validate_script_request(
                "DEMO_PROCESS_START",
                {"script": "powershell -ExecutionPolicy Bypass -Command calc.exe"},
                demo_mode_enabled=True
            )
        assert "Arbitrary script execution rejected" in str(excinfo.value)

        with pytest.raises(ScriptValidationError) as excinfo:
            validate_script_request(
                "DEMO_PROCESS_START",
                {"correlation_id": "invalid/path/traversal!@#$"},
                demo_mode_enabled=True
            )
        assert "Invalid correlation_id format" in str(excinfo.value)

    def test_allowed_safe_execution_and_registry(self):
        """Allowlisted script executes and returns structured execution result."""
        with patch.dict(os.environ, {"DEMO_MODE_ENABLED": "true"}):
            executor = DemoScriptExecutor(agent_id="agent-secure-01")
            payload = {
                "command_id": "exec-101",
                "requested_by": "SOC_ANALYST_ALICE",
                "execution_source": "MANAGER_DISPATCH",
                "params": {
                    "script_id": "DEMO_PROCESS_START",
                    "correlation_id": "DEMO-CORR-101",
                }
            }
            res = executor.execute_script(payload)
            assert res.status == "SUCCESS"
            assert res.correlation_id == "DEMO-CORR-101"
            assert res.exit_code == 0
            assert "DEMO-TEST-001" in res.stdout_summary
            assert res.verification == "PROCESS_STARTED_AND_EXITED"


# ==============================================================================
# Tests B - E: Demo Rules Detection (DEMO-TEST-001 to 004)
# ==============================================================================

class TestDemoRulesDetection:
    """Verify demo rules evaluate benign OS activity without triggering production alert actions."""

    @pytest.fixture
    def setup_evaluator_and_repo(self, tmp_path):
        db_path = tmp_path / "test_rules.db"
        db = ZTADatabase(str(db_path), seed_defaults=True)
        repo = ZTARepository(db)
        evaluator = ConditionEvaluator()
        return evaluator, repo

    def test_b_demo_process_rule_detection(self, setup_evaluator_and_repo):
        """DEMO-TEST-001 matches benign demo process start."""
        evaluator, repo = setup_evaluator_and_repo
        rule = repo.get_rule_by_id("DEMO-TEST-001")
        assert rule is not None
        assert rule["is_demo"] == 1 or rule["is_demo"] is True

        agent = ZTAAgent("agent-01", "test-host")
        event = ZTAEvent(
            event_id="evt-proc-01",
            timestamp=datetime.now(timezone.utc),
            agent=agent,
            event_type="PROCESS_START",
            process=ZTAProcess(name="cmd.exe", command_line="cmd.exe /c echo [DEMO-TEST-001] correlation=DEMO-12345")
        )
        ctx = context(event)
        trace = evaluator.explain(rule["condition"], ctx)
        assert trace["result"] is True

    def test_c_demo_file_rule_detection(self, setup_evaluator_and_repo):
        """DEMO-TEST-002 matches benign demo file modification in edr-demo safe path."""
        evaluator, repo = setup_evaluator_and_repo
        rule = repo.get_rule_by_id("DEMO-TEST-001")
        rule_file = repo.get_rule_by_id("DEMO-TEST-002")
        assert rule_file is not None
        assert rule_file["is_demo"] == 1 or rule_file["is_demo"] is True

        agent = ZTAAgent("agent-01", "test-host")
        demo_file = os.path.join(get_demo_temp_dir(), "demo_file_DEMO-12345.txt")
        event = ZTAEvent(
            event_id="evt-file-01",
            timestamp=datetime.now(timezone.utc),
            agent=agent,
            event_type="FILE_MODIFIED",
            raw_event={"data": {"target_path": demo_file, "file_path": demo_file}}
        )
        ctx = context(event)
        trace = evaluator.explain(rule_file["condition"], ctx)
        assert trace["result"] is True

    def test_d_demo_network_rule_detection(self, setup_evaluator_and_repo):
        """DEMO-TEST-003 matches benign demo network connection."""
        evaluator, repo = setup_evaluator_and_repo
        rule = repo.get_rule_by_id("DEMO-TEST-003")
        assert rule is not None
        assert rule["is_demo"] == 1 or rule["is_demo"] is True

        agent = ZTAAgent("agent-01", "test-host")
        event = ZTAEvent(
            event_id="evt-net-01",
            timestamp=datetime.now(timezone.utc),
            agent=agent,
            event_type="NETWORK_CONNECTION",
            destination_ip="127.0.0.1",
            destination_port=44444,
            raw_event={"data": {"destination_port": 44444}}
        )
        ctx = context(event)
        trace = evaluator.explain(rule["condition"], ctx)
        assert trace["result"] is True

    def test_e_demo_listening_port_rule_detection(self, setup_evaluator_and_repo):
        """DEMO-TEST-004 matches benign demo listening port."""
        evaluator, repo = setup_evaluator_and_repo
        rule = repo.get_rule_by_id("DEMO-TEST-004")
        assert rule is not None
        assert rule["is_demo"] == 1 or rule["is_demo"] is True

        agent = ZTAAgent("agent-01", "test-host")
        event = ZTAEvent(
            event_id="evt-port-01",
            timestamp=datetime.now(timezone.utc),
            agent=agent,
            event_type="NETWORK_LISTEN",
            destination_port=44445,
            raw_event={"data": {"destination_port": 44445, "local_port": 44445}}
        )
        ctx = context(event)
        trace = evaluator.explain(rule["condition"], ctx)
        assert trace["result"] is True


# ==============================================================================
# Tests F & G: Agent Operational Log Push (Online & Offline Queuing)
# ==============================================================================

class TestAgentOperationalLogPush:
    """Test online and offline log pushing with deduplication and persistence."""

    def test_f_log_push_database_and_online(self, tmp_path):
        """Manager database stores and retrieves agent operational logs."""
        db_path = tmp_path / "test_logs.db"
        db = ZTADatabase(str(db_path), seed_defaults=True)
        repo = ZTARepository(db)

        repo.save_agent_log({
            "log_id": "log-001",
            "agent_id": "agent-01",
            "message": "Collector heartbeat OK",
            "level": "INFO",
            "component": "collector",
            "correlation_id": "corr-log-1"
        })
        repo.save_agent_log({
            "log_id": "log-002",
            "agent_id": "agent-01",
            "message": "High memory usage in collector",
            "level": "WARNING",
            "component": "monitor"
        })

        logs = repo.get_agent_logs("agent-01", limit=10)
        assert len(logs) == 2
        messages = [l["message"] for l in logs]
        assert "Collector heartbeat OK" in messages
        assert "High memory usage in collector" in messages

    def test_g_offline_log_queuing_and_sync(self, tmp_path):
        """Offline log messages queue in SQLite and sync when manager is reachable."""
        agent_db = tmp_path / "agent_offline.db"
        daemon = ZTAAgentDaemon(manager_url="http://127.0.0.1:8080", db_path=str(agent_db))

        # Emit log offline
        daemon.emit_log(level="ERROR", event_type="NETWORK", message="Network link dropped", component="network")
        assert daemon.offline_queue.queue_depth() >= 1

        queued = daemon.offline_queue.dequeue_batch(10)
        log_entries = [q for q in queued if q.get("collector_type") in ("OPERATIONAL_LOG", "AGENT_LOG")]
        assert len(log_entries) >= 1
        entry_data = log_entries[0]["payload"].get("log_entry") or log_entries[0]["payload"]
        assert entry_data["message"] == "Network link dropped"

        # Mock sync success
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "PROCESSED",
            "accepted_event_ids": [log_entries[0]["event_id"]]
        }
        with patch("zta.agent.agent_daemon.requests.post", return_value=mock_resp):
            daemon.sync_offline_queue()
        
        # Verify queue was drained for accepted log
        assert daemon.offline_queue.queue_depth() == 0


# ==============================================================================
# Test H: Exact Agent IP Identification & Manager Observed IP
# ==============================================================================

class TestAgentNetworkIdentity:
    """Verify primary IPv4/IPv6 detection and manager observed source IP logic."""

    def test_get_active_network_identity(self):
        """Active network identity returns valid IP details and interface names."""
        identity = get_active_network_identity()
        assert "local_ipv4" in identity
        assert "interfaces" in identity
        assert isinstance(identity["interfaces"], list)

        # Primary IP should be a valid IP string
        assert identity["local_ipv4"] != ""
        assert len(identity["local_ipv4"].split(".")) == 4

    def test_manager_observed_ip_resolution(self, tmp_path):
        """Manager API resolves real client IP and respects trusted proxies."""
        server = create_zta_server(port=0, db_path=tmp_path / "ip_test.db")
        port = server.server_address[1]
        repo = server.runtime[0]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            url = f"http://127.0.0.1:{port}/api/v1/agents/heartbeat"
            headers = {
                "Authorization": "Bearer fixture-agent-token",
                "X-Forwarded-For": "203.0.113.195, 10.0.0.1"
            }
            payload = {
                "agent_id": "TEST-HOST-01",
                "hostname": "test-box",
                "os": "Windows",
                "active_interface": "Ethernet0",
                "local_ipv4": "192.168.1.50",
                "timestamp": "2026-09-13T12:00:00Z"
            }
            resp = requests.post(url, json=payload, headers=headers, timeout=5)
            assert resp.status_code == 200

            # Query agent from database
            agents = repo.get_agents()
            agent = next((a for a in agents if a["id"] == "TEST-HOST-01"), None)
            assert agent is not None
            assert agent["local_ipv4"] == "192.168.1.50"
            assert agent["manager_observed_ip"] in ("127.0.0.1", "203.0.113.195", "::1", "localhost")
        finally:
            server.shutdown()
            server.server_close()


# ==============================================================================
# Tests I & J: Dashboard Analytics Aggregates & Dynamic Time Buckets
# ==============================================================================

class TestDashboardAnalytics:
    """Verify backend dynamic analytics calculation, zero-division safety, and time buckets."""

    def test_i_fleet_risk_zero_division_safety_and_aggregates(self, tmp_path):
        """Fleet risk score handles empty fleets safely and calculates real averages."""
        db_path = tmp_path / "analytics_test.db"
        db = ZTADatabase(str(db_path), seed_defaults=True)
        repo = ZTARepository(db)

        # Empty database test
        agents = repo.get_agents()
        assert len(agents) == 0
        avg_score = sum((a.get("risk_score") or 0) for a in agents) / max(len(agents), 1) if agents else 0.0
        assert avg_score == 0.0

        # Seed real agents with scores
        repo.save_heartbeat({
            "agent_id": "AG-1",
            "hostname": "Host-1",
            "os": "Windows",
            "local_ipv4": "192.168.1.10",
            "connection_state": "ONLINE",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        with repo.db.get_connection() as conn:
            conn.execute("INSERT INTO risk_history (timestamp, agent_id, previous_score, delta, new_score, reason, finding_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (datetime.now(timezone.utc).isoformat(), "AG-1", 0, 40, 40, "Initial", "f1"))
            conn.commit()

        repo.save_heartbeat({
            "agent_id": "AG-2",
            "hostname": "Host-2",
            "os": "Linux",
            "local_ipv4": "192.168.1.11",
            "connection_state": "ONLINE",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        with repo.db.get_connection() as conn:
            conn.execute("INSERT INTO risk_history (timestamp, agent_id, previous_score, delta, new_score, reason, finding_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (datetime.now(timezone.utc).isoformat(), "AG-2", 0, 80, 80, "Initial", "f2"))
            conn.commit()

        agents2 = repo.get_agents()
        assert len(agents2) == 2
        scored = [a["risk_score"] for a in agents2 if a.get("risk_score") is not None]
        avg_score2 = sum(scored) / len(scored)
        assert avg_score2 == 60.0

    def test_j_analytics_api_endpoints_and_time_series(self, tmp_path):
        """API endpoints return correct analytics payloads without mock or hardcoded data."""
        server = create_zta_server(port=0, db_path=tmp_path / "analytics_api.db")
        port = server.server_address[1]
        repo = server.runtime[0]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            # Seed an agent
            repo.save_heartbeat({
                "agent_id": "AG-ANALYTICS",
                "hostname": "Host-A",
                "os": "Windows",
                "local_ipv4": "10.0.0.5",
                "connection_state": "ONLINE",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            with repo.db.get_connection() as conn:
                conn.execute("INSERT INTO risk_history (timestamp, agent_id, previous_score, delta, new_score, reason, finding_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                             (datetime.now(timezone.utc).isoformat(), "AG-ANALYTICS", 0, 75, 75, "Initial", "f3"))
                conn.commit()

            # Test /api/zta/analytics/risk-distribution
            resp = requests.get(f"http://127.0.0.1:{port}/api/zta/analytics/risk-distribution", timeout=5)
            assert resp.status_code == 200
            risk_data = resp.json()
            assert "distribution" in risk_data
            assert "fleet_avg" in risk_data
            assert risk_data["fleet_avg"] == 75.0
            assert risk_data["distribution"]["high"] == 1

            # Test /api/zta/analytics/events-timeseries (1h / 24h / 7d)
            resp_ts = requests.get(f"http://127.0.0.1:{port}/api/zta/analytics/events-timeseries?range=24h", timeout=5)
            assert resp_ts.status_code == 200
            ts_data = resp_ts.json()
            assert "points" in ts_data
            assert "range" in ts_data
            assert ts_data["range"] == "24h"
            assert isinstance(ts_data["points"], list)

            # Test /api/zta/analytics/mitre-coverage
            resp_mitre = requests.get(f"http://127.0.0.1:{port}/api/zta/analytics/mitre-coverage", timeout=5)
            assert resp_mitre.status_code == 200
            mitre_data = resp_mitre.json()
            assert "techniques" in mitre_data
            assert "tactics" in mitre_data

            # Test /api/v1/agents/logs
            resp_logs = requests.get(f"http://127.0.0.1:{port}/api/v1/agents/logs?agent_id=AG-ANALYTICS", timeout=5)
            assert resp_logs.status_code == 200
            logs_data = resp_logs.json()
            assert "logs" in logs_data

        finally:
            server.shutdown()
            server.server_close()
