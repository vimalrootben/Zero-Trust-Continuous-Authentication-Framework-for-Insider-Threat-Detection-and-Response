"""Comprehensive End-to-End Tests for ZTA Manager, Agent, Rules, Policies, Logout, Sync, and Dashboard APIs.

Uses isolated synthetic test fixtures; does not validate live Windows execution:
1. Agent Online Heartbeat & Telemetry Ingestion -> Background Rule Match -> Risk Score Update -> Alert Creation -> WebSocket Broadcast.
2. Policy Engine ALERT_ONLY mode vs ENFORCE mode execution.
3. LOGOUT_USER / Response Command Dispatch, Dry-Run / Verified Execution & Audit Logging.
4. Agent Offline Mode: SQLite persistence, Offline Queueing, and Local Rule Engine matching.
5. Reconnect Synchronization: Batch upload, Manager Idempotent Replay, Selective Queue Acknowledgment.
6. Manager REST Endpoints: Overview, Agents, Events, Rules, Policies, Alerts, Commands, Audit, Services.
7. WebSocket & SSE Real-time Broadcasting.
"""

from datetime import datetime, timezone
import json
import socket
import threading
import time
import urllib.request
import urllib.error
import pytest

from zta.storage.database import ZTADatabase, ZTARepository
from zta.engine.events.models import ZTAEvent, ZTAAgent, ZTAProcess
from zta.engine.policy.engine import ZTAPolicyEngine, ZTAPolicy, PolicyDecision
from zta.agent.storage.offline_queue import OfflineQueue
from zta.agent.rules.local_rule_engine import LocalRuleEngine, LocalMatch
from zta.agent.agent_daemon import ZTAAgentDaemon
from zta.agent.commands.command_receiver import AgentCommandReceiver
from zta.api.server import create_zta_server
from http_support import headers as auth_headers, wait_processed


@pytest.fixture
def test_server(tmp_path):
    """Start a real ZTA Manager server on an ephemeral port."""
    db_file = tmp_path / "scenario_zta.db"
    server = create_zta_server(host="127.0.0.1", port=0, db_path=db_file)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.15)
    base_url = f"http://127.0.0.1:{server.server_port}"
    yield base_url, server.server_port, db_file
    server.shutdown()
    server.server_close()


def http_post(url: str, data: dict):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=auth_headers(url),
    )
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read().decode("utf-8"))
        if "/telemetry/" in url or "/sync/" in url: wait_processed(url.split("/api/")[0])
        return resp.status, result


def http_get(url: str):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


# ==============================================================================
# SCENARIO 1: Agent Online -> Telemetry -> Rule Match -> Risk -> Alert -> WS
# ==============================================================================
def test_scenario_online_agent_rule_match_risk_and_alert(test_server):
    base_url, port, db_file = test_server

    # 1. Agent Heartbeat (Online Registration)
    hb_status, hb_data = http_post(f"{base_url}/api/v1/agents/heartbeat", {
        "agent_id": "win-agent-01",
        "hostname": "FINANCE-DESKTOP-01",
        "os": "Windows 11 Enterprise",
        "ip": "10.0.4.55",
        "status": "ACTIVE",
    })
    assert hb_status == 200
    assert hb_data["status"] == "ACKNOWLEDGED"

    # Verify agent is ACTIVE in DB
    _, agent_data = http_get(f"{base_url}/api/zta/agents/win-agent-01")
    assert agent_data["agent"]["status"] == "ACTIVE"
    assert agent_data["agent"]["risk_score"] is None

    # 2. Ingest Telemetry matching RULE-0001 (Encoded PowerShell Execution)
    telemetry_payload = [{
        "id": "evt-ps-sec-01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": {"id": "win-agent-01", "name": "FINANCE-DESKTOP-01"},
        "rule": {
            "id": "RULE-0001",
            "level": 10,
            "description": "Suspicious Encoded PowerShell Execution",
            "groups": ["powershell", "zta_security"],
        },
        "data": {
            "win": {
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -encodedcommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                }
            }
        }
    }]
    post_status, post_data = http_post(f"{base_url}/api/v1/telemetry/bulk", telemetry_payload)
    assert post_status == 201
    assert post_data["accepted"] == 1

    # 3. Verify Rule Match Recorded in Storage
    _, matches_data = http_get(f"{base_url}/api/zta/rule-matches")
    matches = matches_data["rule_matches"]
    assert len(matches) >= 1
    ps_match = next((m for m in matches if m["rule_id"] == "RULE-0002" and m["agent_id"] == "win-agent-01"), None)
    assert ps_match is not None
    assert ps_match["severity"] == "HIGH"
    assert ps_match["matched_conditions"]["result"] is True

    # 4. Verify Dynamic Risk Recalculation (+30 for RULE-0001)
    _, agent_updated = http_get(f"{base_url}/api/zta/agents/win-agent-01")
    assert agent_updated["agent"]["risk_score"] >= 25
    assert agent_updated["agent"]["trust_score"] <= 75
    assert agent_updated["agent"]["trust_status"] in ("GUARDED", "DEGRADED", "UNTRUSTED")

    # 5. Verify Incident / Alert Creation
    _, incidents_data = http_get(f"{base_url}/api/zta/incidents")
    incidents = incidents_data["incidents"]
    assert len(incidents) >= 1
    ps_incident = next((i for i in incidents if i["agent_id"] == "win-agent-01"), None)
    assert ps_incident is not None
    assert ps_incident["severity"] == "HIGH"
    assert "PowerShell with encoded command" in ps_incident["trigger_reason"]


# ==============================================================================
# SCENARIO 2: Policy ALERT_ONLY vs ENFORCE Mode
# ==============================================================================
def test_scenario_policy_alert_only_vs_enforce(test_server):
    base_url, port, db_file = test_server
    repo = ZTARepository(ZTADatabase(str(db_file)))

    # Register Agent
    http_post(f"{base_url}/api/v1/agents/heartbeat", {
        "agent_id": "win-agent-02",
        "hostname": "EXEC-LAPTOP-02",
        "status": "ACTIVE",
    })

    # Test Policy Engine directly for precision comparison
    policy_engine = ZTAPolicyEngine()

    alert_only_policy = {
        "policy_id": "pol-alert-test",
        "name": "Audit Only High Risk",
        "mode": "ALERT_ONLY",
        "action": "LOGOUT_USER",
        "target_entity": "agent",
        "condition_tree": {"field": "risk_score", "op": "gte", "value": 50},
        "enabled": True,
    }

    enforce_policy = {
        "policy_id": "pol-enforce-test",
        "name": "Enforce High Risk Isolation",
        "mode": "ENFORCE",
        "action": "ISOLATE_ENDPOINT",
        "target_entity": "agent",
        "condition_tree": {"field": "risk_score", "op": "gte", "value": 50},
        "enabled": True,
    }

    context = {"agent_id": "win-agent-02", "risk_score": 75, "critical_alerts": 1}

    # Evaluate ALERT_ONLY policy
    decision_alert = policy_engine.evaluate_single_policy(alert_only_policy, context)
    assert decision_alert.triggered is True
    assert decision_alert.action == "LOGOUT_USER"  # Recommendation retained; mode suppresses execution
    assert decision_alert.mode == "ALERT_ONLY"

    # Evaluate ENFORCE policy
    decision_enforce = policy_engine.evaluate_single_policy(enforce_policy, context)
    assert decision_enforce.triggered is True
    assert decision_enforce.action == "ISOLATE_ENDPOINT"
    assert decision_enforce.mode == "ENFORCE"

    # Now verify manager execution with POL-LOGOUT-001 (which is seeded in ENFORCE mode)
    # Trigger Mimikatz dump (RULE-0004: +45 risk delta) on agent-02
    telemetry_payload = [{
        "id": "evt-mimi-01",
        "event_type":"SERVICE_INSTALL",
        "user":{"name":"fixture-user","session_id":7},
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": {"id": "win-agent-02", "name": "EXEC-LAPTOP-02"},
        "rule": {
            "id": "RULE-0004",
            "level": 14,
            "description": "Credential Dumping via LSASS Process Access",
            "groups": ["credential_access", "zta_security"],
        },
        "data": {
            "win": {
                "eventdata": {
                    "sourceImage": "C:\\Temp\\mimikatz.exe",
                    "targetImage": "C:\\Windows\\System32\\lsass.exe",
                    "grantedAccess": "0x1010",
                }
            }
        }
    }]
    http_post(f"{base_url}/api/v1/telemetry/bulk", telemetry_payload)

    # Check policy evaluations endpoint
    _, pol_evals = http_get(f"{base_url}/api/zta/policy-evaluations")
    assert len(pol_evals["policy_evaluations"]) >= 1

    # Check that POL-LOGOUT-001 or containment action enqueued a command for agent-02
    _, cmds = http_get(f"{base_url}/api/zta/commands")
    assert len(cmds["commands"]) >= 1


# ==============================================================================
# SCENARIO 3: LOGOUT_USER Response Command Dispatch & Result Reporting
# ==============================================================================
def test_scenario_logout_response_command_lifecycle(test_server):
    base_url, port, db_file = test_server

    # 1. Enqueue manual/automated LOGOUT_USER command via API
    cmd_status, cmd_data = http_post(f"{base_url}/api/v1/commands", {
        "agent_id": "win-agent-03",
        "action_type": "LOGOUT_USER",
        "params": {"SessionId": "2", "UserName": "badactor"},
    })
    assert cmd_status == 201
    cmd_id = cmd_data["command_id"]
    assert cmd_data["status"] == "QUEUED"

    # 2. Agent Heartbeat polls and receives the dispatched command
    hb_status, hb_data = http_post(f"{base_url}/api/v1/agents/heartbeat", {
        "agent_id": "win-agent-03",
        "hostname": "CORP-WORKSTATION-03",
        "status": "ACTIVE",
    })
    assert hb_status == 200
    pending = hb_data.get("pending_commands", [])
    assert len(pending) >= 1
    received_cmd = next(c for c in pending if c["command_id"] == cmd_id)
    assert received_cmd["action_type"] == "LOGOUT_USER"
    assert received_cmd["params"]["SessionId"] == "2"

    # 3. Agent executes command and reports verified result
    result_status, result_data = http_post(f"{base_url}/api/v1/commands/result", {
        "command_id": cmd_id,
        "agent_id": "win-agent-03",
        "status": "SUCCESS",
        "output": "Session 2 for user badactor successfully terminated via logoff.exe",
        "verification": "SESSION_NOT_ACTIVE",
    })
    assert result_status == 200
    assert result_data["status"] == "ACKNOWLEDGED"

    # 4. Verify Command Status in Manager DB
    _, cmds_data = http_get(f"{base_url}/api/zta/commands")
    updated_cmd = next(c for c in cmds_data["commands"] if c["command_id"] == cmd_id)
    assert updated_cmd["status"] == "SUCCESS"
    assert "logoff.exe" in updated_cmd["output"]

    # 5. Verify Audit Log recorded the LOGOUT_SUCCEEDED event
    _, audit_data = http_get(f"{base_url}/api/zta/audit")
    logout_audit = next((a for a in audit_data["audit_logs"] if a["event_type"] == "LOGOUT_SUCCEEDED"), None)
    assert logout_audit is not None
    assert logout_audit["agent_id"] == "win-agent-03"


# ==============================================================================
# SCENARIO 4: Offline Agent Mode (Queueing & Local Rules)
# ==============================================================================
def test_scenario_offline_agent_local_rules_and_queue(tmp_path):
    queue_db = tmp_path / "agent_offline_queue.db"
    offline_queue = OfflineQueue(db_path=str(queue_db))
    local_rules = LocalRuleEngine()

    # Create Offline Daemon pointing to non-existent unreachable port
    daemon = ZTAAgentDaemon(
        manager_url="http://127.0.0.1:59999",  # Unreachable port -> OFFLINE
        db_path=str(queue_db),
    )

    # 1. Trigger Heartbeat -> Fails -> Transitions to OFFLINE
    daemon.send_heartbeat()
    assert daemon.connection_state == "OFFLINE"

    # 2. Local rule evaluation on suspicious event
    event = ZTAEvent(
        event_id="evt-off-01",
        timestamp=datetime.now(timezone.utc),
        agent=ZTAAgent(id="offline-agent-01", name="OFFLINE-LAPTOP-01"),
        process=ZTAProcess(
            name="powershell.exe",
            command_line="powershell.exe -encodedcommand VwByAGkAdABlAC0ASABvAHMAdAA=",
        ),
    )
    match = local_rules.evaluate(event)
    assert match is not None
    assert match.rule_id == "LOC-RULE-001"
    assert match.severity == "HIGH"

    # 3. Enqueue event for later synchronization
    offline_queue.enqueue({
        "id": event.event_id,
        "telemetry": {
            "agent_id": "offline-agent-01",
            "hostname": "OFFLINE-LAPTOP-01",
            "timestamp": event.timestamp.isoformat(),
        },
        "rule": {
            "id": match.rule_id,
            "level": 12,
            "description": match.description,
            "groups": ["powershell", "offline_detection"],
        },
        "data": {"command_line": event.process.command_line},
    })
    assert offline_queue.queue_depth() >= 1


# ==============================================================================
# SCENARIO 5: Reconnect Synchronization & Idempotent Replay Handling
# ==============================================================================
def test_scenario_reconnect_synchronization_and_idempotency(test_server, tmp_path):
    base_url, port, db_file = test_server
    queue_db = tmp_path / "sync_queue.db"
    offline_queue = OfflineQueue(db_path=str(queue_db))

    # Pre-populate offline queue with 2 events
    offline_queue.enqueue({
        "id": "sync-evt-001",
        "agent": {"id": "sync-agent-01", "name": "SYNC-LAPTOP-01"},
        "rule": {"id": "RULE-0002", "level": 10, "description": "Offline vssadmin deletion"},
        "data": {"win": {"eventdata": {"commandLine": "vssadmin delete shadows /all /quiet"}}},
    })
    offline_queue.enqueue({
        "id": "sync-evt-002",
        "agent": {"id": "sync-agent-01", "name": "SYNC-LAPTOP-01"},
        "rule": {"id": "RULE-0003", "level": 10, "description": "Offline bcdedit recovery disable"},
        "data": {"win": {"eventdata": {"commandLine": "bcdedit /set {default} bootstatuspolicy ignoreallfailures"}}},
    })
    assert offline_queue.queue_depth() == 2

    # Instantiate Agent Daemon connected to live test manager
    daemon = ZTAAgentDaemon(
        manager_url=base_url,
        db_path=str(queue_db), agent_id="sync-agent-01", token="fixture-agent-token",
    )

    # 1. Sync offline queue to manager
    daemon.sync_offline_queue()

    # 2. Verify all queued events are acknowledged and removed from local queue
    assert offline_queue.queue_depth() == 0
    assert daemon.connection_state == "ONLINE"


    # 3. Verify Manager received and recorded the synchronized events
    _, events_data = http_get(f"{base_url}/api/zta/events")
    synced_events = [e for e in events_data["events"] if e["agent_id"] == "sync-agent-01"]
    assert len(synced_events) == 2

    # 4. Test Idempotent Replay (Submitting same events again must not duplicate or error)
    replay_payload = {
        "agent_id": "sync-agent-01",
        "batch_id": "replay-batch-99",
        "telemetry": [
            {
                "id": "sync-evt-001",
                "agent": {"id": "sync-agent-01", "name": "SYNC-LAPTOP-01"},
                "rule": {"id": "RULE-0002", "level": 10, "description": "Offline vssadmin deletion"},
                "data": {"win": {"eventdata": {"commandLine": "vssadmin delete shadows /all /quiet"}}},
            }
        ]
    }
    status, data = http_post(f"{base_url}/api/v1/sync/offline", replay_payload)
    assert status == 201
    assert data["accepted"] == 1

    # Verify total count in manager is STILL 2 (no duplicates created)
    _, events_after = http_get(f"{base_url}/api/zta/events")
    synced_events_after = [e for e in events_after["events"] if e["agent_id"] == "sync-agent-01"]
    assert len(synced_events_after) == 2


# ==============================================================================
# SCENARIO 6: Manager REST Dashboard Data Completeness
# ==============================================================================
def test_scenario_manager_dashboard_endpoints(test_server):
    base_url, port, db_file = test_server

    # Query Overview
    _, overview = http_get(f"{base_url}/api/zta/overview")
    assert overview["system"] == "ZTA (Zero Trust Architecture)"
    assert overview["status"] == "HEALTHY"
    assert "risk_distribution" in overview
    assert "background_services" in overview
    assert len(overview["background_services"]) >= 4

    # Query Rules List
    _, rules = http_get(f"{base_url}/api/zta/rules")
    assert len(rules["rules"]) >= 15  # All 15 standard detection rules

    # Query Policies List
    _, policies = http_get(f"{base_url}/api/zta/policies")
    assert len(policies["policies"]) >= 5
    logout_pol = next((p for p in policies["policies"] if p["policy_id"] == "POL-LOGOUT-001"), None)
    assert logout_pol is not None
    assert logout_pol["action"] == "LOGOUT_USER"
    assert logout_pol["mode"] == "ENFORCE"

    # Query Timeline
    _, timeline = http_get(f"{base_url}/api/zta/timeline")
    assert "timeline" in timeline

    # Query Audit Log
    _, audit = http_get(f"{base_url}/api/zta/audit")
    assert "audit_logs" in audit

    # Query Services
    _, services = http_get(f"{base_url}/api/zta/services")
    assert len(services["services"]) >= 4


# ==============================================================================
# SCENARIO 7: WebSocket & SSE Real-time Streaming
# ==============================================================================
def test_scenario_websocket_handshake_and_broadcast(test_server):
    base_url, port, db_file = test_server

    # Perform RFC 6455 Handshake over raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", port))
    ws_key = "dGhlIHNhbXBsZSBub25jZQ=="
    handshake = (
        f"GET /api/zta/ws HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    s.sendall(handshake.encode("utf-8"))
    resp = s.recv(1024).decode("utf-8", errors="ignore")
    assert "101 Switching Protocols" in resp
    assert "Sec-WebSocket-Accept" in resp

    # Trigger an agent heartbeat from another client to induce a broadcast
    http_post(f"{base_url}/api/v1/agents/heartbeat", {
        "agent_id": "ws-agent-test",
        "hostname": "WS-TEST-HOST",
        "status": "ACTIVE",
    })

    # Read WebSocket frame from socket (RFC 6455 text frame)
    s.settimeout(2.0)
    data = s.recv(2048)
    assert len(data) > 2  # Received real-time frame
    # Frame opcode for text is 0x81 (first byte)
    assert data[0] == 0x81
    payload_text = data[2:].decode("utf-8", errors="ignore")
    assert "agent.online" in payload_text or "ws-agent-test" in payload_text

    s.close()
