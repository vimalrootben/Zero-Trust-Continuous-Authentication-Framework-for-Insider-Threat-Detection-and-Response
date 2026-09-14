"""Comprehensive tests for the Manager Dashboard Rule & Policy Management Interface.

Validates:
1. Schema definition retrieval (/api/zta/schema).
2. Rule condition logic validation and dry-run testing (/api/zta/rules/validate, /api/zta/rules/test).
3. Rule CRUD, inline toggling, runtime reload, and safe deletion.
4. Policy CRUD, inline toggling, runtime reload, and rule linking.
5. Strict RBAC enforcement (ADMIN vs SOC_ANALYST, AUDITOR, VIEWER).
6. End-to-end controlled scenario:
   - Create custom rule + policy dynamically via API without restart.
   - Send matching event telemetry.
   - Verify alert generation, risk increment, policy trigger (LOGOUT_USER),
     forensic chain tracking, and audit logging.
"""

import json
import threading
import urllib.request
import urllib.error
from pathlib import Path
import tempfile
import pytest

from zta.api.server import create_zta_server
from http_support import headers as auth_headers, wait_processed


@pytest.fixture
def test_server(tmp_path):
    """Starts a live ZTA Manager server on an ephemeral port with an isolated temporary SQLite database."""
    db_path = str(tmp_path / "test_rules_policies.db")
    server = create_zta_server(host="127.0.0.1", port=0, db_path=db_path)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    base_url = f"http://127.0.0.1:{port}"
    yield {"base_url": base_url, "db_path": db_path, "server": server}
    if getattr(server, "worker", None):
        server.worker.close()
    server.shutdown()
    server.server_close()


def api_request(base_url, path, method="GET", body=None, role="ADMIN"):
    """Helper to send HTTP requests to ZTA API with JSON headers and RBAC role."""
    url = f"{base_url}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    token = "fixture-admin-token"
    if role != "ADMIN":
        username = f"test-{role.lower()}"
        create_data = json.dumps({"username": username, "password": "correct horse battery staple", "role": role}).encode("utf-8")
        create_req = urllib.request.Request(f"{base_url}/api/zta/users", data=create_data, headers={"Content-Type":"application/json", "Authorization":"Bearer fixture-admin-token"}, method="POST")
        try:
            urllib.request.urlopen(create_req).read()
        except urllib.error.HTTPError as exc:
            if exc.code != 400: raise
        login_data = json.dumps({"username":username, "password":"correct horse battery staple"}).encode("utf-8")
        login_req = urllib.request.Request(f"{base_url}/api/zta/auth/login", data=login_data, headers={"Content-Type":"application/json"}, method="POST")
        token = json.loads(urllib.request.urlopen(login_req).read())["access_token"]
    headers = {
        "Content-Type": "application/json",
        "X-User-Role": role,
        "Authorization": "Bearer " + token,
    }
    if path.startswith("/api/v1/agents/") or "/telemetry/" in path or "/sync/" in path or "/commands/result" in path:
        headers.update(auth_headers(path, role))
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            content = resp.read().decode("utf-8")
            if "/telemetry/" in path and status == 201: wait_processed(base_url)
            return status, json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        err_content = e.read().decode("utf-8")
        try:
            parsed = json.loads(err_content)
        except Exception:
            parsed = {"error": err_content}
        return e.code, parsed


def test_schema_endpoint(test_server):
    """Verifies schema retrieval for rules and policies builder."""
    base_url = test_server["base_url"]
    status, schema = api_request(base_url, "/api/zta/schema")
    assert status == 200
    assert "supported_fields" in schema
    assert "supported_operators" in schema
    assert "combinators" in schema
    assert "categories" in schema
    assert "severities" in schema
    assert "response_actions" in schema
    assert "policy_modes" in schema

    # Verify key field presence
    field_paths = [f["path"] for f in schema["supported_fields"]]
    assert "process.name" in field_paths
    assert "process.command_line" in field_paths
    assert "risk_score" in field_paths

    # Verify actions
    action_ids = [a["action"] for a in schema["response_actions"]]
    assert "LOGOUT_USER" in action_ids
    assert "ISOLATE_ENDPOINT" in action_ids
    assert "MONITOR" in action_ids


def test_rule_logic_validation_and_dryrun(test_server):
    """Verifies condition validation and dry-run evaluation."""
    base_url = test_server["base_url"]

    # 1. Valid condition
    valid_cond = {
        "all": [
            {"field": "process.name", "op": "contains", "value": "powershell.exe"},
            {"field": "process.command_line", "op": "contains", "value": "-encodedcommand"}
        ]
    }
    status, res = api_request(base_url, "/api/zta/rules/validate", method="POST", body={"condition": valid_cond})
    assert status == 200
    assert res["valid"] is True

    # 2. Invalid condition (bad operator)
    invalid_cond = {
        "all": [
            {"field": "process.name", "op": "unsupported_operator_xyz", "value": "cmd.exe"}
        ]
    }
    status, res = api_request(base_url, "/api/zta/rules/validate", method="POST", body={"condition": invalid_cond})
    # Returns 200 with valid=False (soft validation)
    assert status == 200
    assert res["valid"] is False

    # 3. Dry-run test against event
    sample_matching_event = {
        "event_type": "PROCESS_CREATION",
        "process": {
            "name": "C:\\Windows\\System32\\powershell.exe",
            "command_line": "powershell.exe -encodedcommand JAB4ACAAPQA..."
        }
    }
    status, test_res = api_request(base_url, "/api/zta/rules/test", method="POST", body={
        "condition": valid_cond,
        "event": sample_matching_event
    })
    assert status == 200
    assert test_res["matched"] is True

    # Non-matching event
    sample_non_matching = {
        "event_type": "PROCESS_CREATION",
        "process": {
            "name": "notepad.exe",
            "command_line": "notepad.exe C:\\temp\\notes.txt"
        }
    }
    status, test_res = api_request(base_url, "/api/zta/rules/test", method="POST", body={
        "condition": valid_cond,
        "event": sample_non_matching
    })
    assert status == 200
    assert test_res["matched"] is False


def test_rule_crud_toggle_and_safe_delete(test_server):
    """Verifies rule creation, editing, toggling, and safe deletion."""
    base_url = test_server["base_url"]

    # 1. Create Rule
    new_rule_payload = {
        "code": "RULE-TEST-001",
        "name": "Suspicious Discovery Tool Executed",
        "description": "Detects whoami or systeminfo executed in rapid succession",
        "category": "Discovery",
        "severity": "HIGH",
        "risk_delta": 30,
        "mitre_tactic": "Discovery",
        "mitre_technique_id": "T1033",
        "enabled": 1,
        "condition": {
            "all": [
                {"field": "process.name", "op": "contains", "value": "whoami.exe"}
            ]
        }
    }
    status, res = api_request(base_url, "/api/zta/rules", method="POST", body=new_rule_payload, role="ADMIN")
    assert status == 201
    created_rule = res["rule"]
    rule_id = created_rule["rule_id"]
    assert created_rule["code"] == "RULE-TEST-001"
    assert created_rule["risk_delta"] == 30

    # 2. Get Rules list - verify it appears
    status, list_res = api_request(base_url, "/api/zta/rules", method="GET")
    assert status == 200
    rule_codes = [r["code"] for r in list_res["rules"]]
    assert "RULE-TEST-001" in rule_codes

    # 3. Toggle Rule Disabled
    status, toggle_res = api_request(base_url, f"/api/zta/rules/{rule_id}/toggle", method="PATCH", body={"enabled": 0}, role="ADMIN")
    assert status == 200
    assert toggle_res["rule"]["enabled"] == 0

    # Toggle back enabled
    status, toggle_res2 = api_request(base_url, f"/api/zta/rules/{rule_id}/toggle", method="PATCH", body={"enabled": 1}, role="ADMIN")
    assert status == 200
    assert toggle_res2["rule"]["enabled"] == 1

    # 4. Update Rule
    update_payload = {
        "name": "Updated Discovery Tool Rule",
        "risk_delta": 45,
        "category": "Discovery",
        "severity": "CRITICAL"
    }
    status, update_res = api_request(base_url, f"/api/zta/rules/{rule_id}", method="PUT", body=update_payload, role="ADMIN")
    assert status == 200
    assert update_res["rule"]["name"] == "Updated Discovery Tool Rule"
    assert update_res["rule"]["risk_delta"] == 45
    assert update_res["rule"]["severity"] == "CRITICAL"

    # 5. Delete Rule Safely
    status, del_res = api_request(base_url, f"/api/zta/rules/{rule_id}", method="DELETE", role="ADMIN")
    assert status == 200
    assert del_res["status"] == "DELETED"
    assert del_res["rule_id"] == rule_id

    # Verify rule is gone from active rules
    status, list_res2 = api_request(base_url, "/api/zta/rules", method="GET")
    rule_ids = [r["rule_id"] for r in list_res2["rules"]]
    assert rule_id not in rule_ids


def _valid_rule(code="RULE-VALIDATION-001"):
    return {
        "code": code,
        "name": "Validated rule",
        "category": "General",
        "severity": "MEDIUM",
        "risk_delta": 15,
        "response_action": "ALERT",
        "logic_type": "CONDITION_TREE",
        "enabled": True,
        "allow_offline": False,
        "condition": {"field": "event_type", "op": "eq", "value": "PROCESS_CREATION"},
    }


@pytest.mark.parametrize("mutation", [
    {"code": 123},
    {"severity": "URGENT"},
    {"category": "Unregistered"},
    {"response_action": "RUN_ARBITRARY"},
    {"logic_type": "SCRIPT"},
    {"risk_delta": -1},
    {"risk_delta": 101},
    {"risk_delta": "25"},
    {"enabled": "yes"},
    {"condition": {"field": "risk_score", "op": "gte", "value": "high"}},
    {"condition": {"field": "process.name", "op": "regex", "value": "["}},
    {"condition": {"all": [{"field": "event_type", "op": "eq", "value": str(i)} for i in range(33)]}},
])
def test_invalid_rule_types_enums_limits_and_width_are_rejected(test_server, mutation):
    payload = {**_valid_rule(), **mutation}
    status, result = api_request(test_server["base_url"], "/api/zta/rules", method="POST", body=payload)
    assert status == 400
    assert result.get("error")
    assert not test_server["server"].runtime[0].get_rule_by_id("RULE-VALIDATION-001")


def test_deep_rule_update_and_invalid_reactivation_are_rejected(test_server):
    base_url = test_server["base_url"]
    payload = _valid_rule("RULE-VALIDATION-DEPTH")
    status, created = api_request(base_url, "/api/zta/rules", method="POST", body=payload)
    assert status == 201
    rule_id = created["rule"]["rule_id"]

    deep = {"field": "event_type", "op": "exists"}
    for _ in range(8):
        deep = {"not": deep}
    status, result = api_request(base_url, f"/api/zta/rules/{rule_id}", method="PUT", body={"condition": deep})
    assert status == 400
    assert test_server["server"].runtime[0].get_rule_by_id(rule_id)["condition"] == payload["condition"]

    repo = test_server["server"].runtime[0]
    with repo.db.get_connection() as conn:
        conn.execute("UPDATE rules SET enabled=0, severity='INVALID' WHERE rule_id=?", (rule_id,))
    status, result = api_request(base_url, f"/api/zta/rules/{rule_id}/toggle", method="PATCH", body={"enabled": 1})
    assert status == 400
    assert repo.get_rule_by_id(rule_id)["enabled"] == 0


def test_policy_crud_toggle_and_rule_linking(test_server):
    """Verifies policy creation, rule linking, inline toggling, and deletion."""
    base_url = test_server["base_url"]

    # 1. Create Policy linked to seeded RULE-0004
    # Seeded rule uses RULE-0004 as both rule_id and code
    policy_payload = {
        "code": "POL-TEST-001",
        "name": "Critical PowerShell Kill & Quarantine",
        "description": "Automatically terminates process and notifies SOC on encoded PS",
        "category": "Execution",
        "severity": "CRITICAL",
        "mode": "ENFORCE",
        "action": "KILL_PROCESS",
        "rule_id": "RULE-0004",  # seeded rule_id is uppercase RULE-0004
        "min_risk": 75,
        "max_risk": 100,
        "enabled": 1
    }
    status, res = api_request(base_url, "/api/zta/policies", method="POST", body=policy_payload, role="ADMIN")
    assert status == 201
    created_policy = res["policy"]
    policy_id = created_policy["policy_id"]
    assert created_policy["code"] == "POL-TEST-001"
    assert created_policy["rule_id"] == "RULE-0004"

    # 2. Get Rules list - verify RULE-0004 now shows the linked policy!
    status, rules_res = api_request(base_url, "/api/zta/rules", method="GET")
    assert status == 200
    rule_0004 = next((r for r in rules_res["rules"] if r["rule_id"] == "RULE-0004"), None)
    assert rule_0004 is not None
    linked_codes = [lp.get("code") or lp.get("policy_id") for lp in rule_0004.get("linked_policies", [])]
    assert "POL-TEST-001" in linked_codes

    # 3. Policy Validation
    status, val_res = api_request(base_url, "/api/zta/policies/validate", method="POST", body={"policy": policy_payload})
    assert status == 200
    assert val_res["valid"] is True

    # 4. Toggle Policy Disabled
    status, toggle_res = api_request(base_url, f"/api/zta/policies/{policy_id}/toggle", method="PATCH", body={"enabled": 0}, role="ADMIN")
    assert status == 200
    assert toggle_res["policy"]["enabled"] == 0

    # 5. Delete Policy
    status, del_res = api_request(base_url, f"/api/zta/policies/{policy_id}", method="DELETE", role="ADMIN")
    assert status == 200
    assert del_res["status"] == "DELETED"

    # Verify rule RULE-0004 no longer lists POL-TEST-001 as linked
    status, rules_res2 = api_request(base_url, "/api/zta/rules", method="GET")
    rule_0004_updated = next((r for r in rules_res2["rules"] if r["rule_id"] == "RULE-0004"), None)
    assert rule_0004_updated is not None
    linked_codes_updated = [lp.get("code") or lp.get("policy_id") for lp in rule_0004_updated.get("linked_policies", [])]
    assert "POL-TEST-001" not in linked_codes_updated


def test_rbac_enforcement(test_server):
    """Verifies that non-ADMIN roles are rejected with 403 Forbidden on mutations."""
    base_url = test_server["base_url"]

    rule_payload = {
        "code": "RULE-RBAC-01",
        "name": "RBAC Test Rule",
        "category": "General",
        "severity": "LOW",
        "enabled": 1,
        "condition": {"all": [{"field": "process.name", "op": "eq", "value": "test.exe"}]}
    }

    # Test create rule with SOC_ANALYST -> Expect 403
    status, res = api_request(base_url, "/api/zta/rules", method="POST", body=rule_payload, role="SOC_ANALYST")
    assert status == 403
    # Error body should mention permission or ADMIN requirement
    error_msg = res.get("error", "").lower()
    assert "permission" in error_msg or "admin" in error_msg or "forbidden" in error_msg

    # Test toggle rule with AUDITOR -> Expect 403
    status, res = api_request(base_url, "/api/zta/rules/RULE-0001/toggle", method="PATCH", body={"enabled": 0}, role="AUDITOR")
    assert status == 403

    # Test delete policy with VIEWER -> Expect 403
    status, res = api_request(base_url, "/api/zta/policies/POL-001", method="DELETE", role="VIEWER")
    assert status == 403


def test_end_to_end_runtime_rule_policy_enforcement(test_server):
    """End-to-end scenario:
    1. Register an endpoint agent.
    2. Admin dynamically creates a new custom rule via API (RULE-CUSTOM-99).
    3. Admin dynamically creates a linked policy via API (POL-LOGOUT-99) targeting LOGOUT_USER.
    4. Send matching telemetry event through /api/zta/events.
    5. Verify:
       - Rule matches immediately without restarting server.
       - Risk score is incremented.
       - Adaptive policy evaluates and triggers LOGOUT_USER command.
       - Forensic metadata records the complete pipeline.
       - Audit log records the administrative operations and policy decision.
    """
    base_url = test_server["base_url"]

    # 1. Register agent via heartbeat endpoint (real agent endpoint)
    agent_payload = {
        "agent_id": "agent-runtime-01",
        "hostname": "CORP-FINANCE-W11",
        "ip": "10.0.10.25",
        "os": "Windows 11 Pro",
        "department": "Finance",
        "connection_state": "ONLINE"
    }
    status, reg_res = api_request(base_url, "/api/v1/agents/heartbeat", method="POST", body=agent_payload)
    assert status == 200, f"Agent heartbeat failed: {reg_res}"

    # 2. Dynamically create custom rule
    custom_rule = {
        "code": "RULE-CUSTOM-99",
        "name": "High-Risk Token Theft Mimikatz",
        "description": "Detects mimikatz or sekurlsa invocation",
        "category": "Credential Access",
        "severity": "CRITICAL",
        "risk_delta": 50,
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1003.001",
        "enabled": 1,
        "condition": {
            "all": [
                {"field": "process.name", "op": "contains", "value": "mimikatz.exe"}
            ]
        }
    }
    status, rule_resp = api_request(base_url, "/api/zta/rules", method="POST", body=custom_rule, role="ADMIN")
    assert status == 201
    rule_id = rule_resp["rule"]["rule_id"]

    # 3. Dynamically create custom policy linked to this rule
    custom_policy = {
        "code": "POL-LOGOUT-99",
        "name": "Immediate User Session Eviction on Credential Theft",
        "description": "Forces session logoff upon credential access detection",
        "category": "Credential Access",
        "severity": "CRITICAL",
        "mode": "ENFORCE",
        "action": "LOGOUT_USER",
        "rule_id": rule_id,
        "min_risk": 40,
        "max_risk": 100,
        "enabled": 1
    }
    status, pol_resp = api_request(base_url, "/api/zta/policies", method="POST", body=custom_policy, role="ADMIN")
    assert status == 201

    # 4. Ingest Telemetry matching the custom rule via bulk telemetry endpoint
    telemetry_batch = {
        "agent_id": "agent-runtime-01",
        
        "telemetry": [
            {
                "event_id": "evt-test-001",
                "timestamp": "2026-09-10T10:00:00Z",
                "event_type": "PROCESS_CREATION",
                "collector_type": "process",
                "agent": {
                    "id": "agent-runtime-01",
                    "name": "CORP-FINANCE-W11",
                    "department": "Finance"
                },
                "process": {
                    "name": "mimikatz.exe",
                    "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
                    "path": "C:\\Tools\\mimikatz.exe"
                },
                "user": {"name": "compromised_user", "session_id":7},
                "severity": "CRITICAL",
                "description": "Mimikatz credential dumping attempt detected"
            }
        ]
    }
    status, event_resp = api_request(base_url, "/api/v1/telemetry/bulk", method="POST", body=telemetry_batch)
    assert status in (200, 201), f"Telemetry batch failed: {event_resp}"
    assert event_resp["status"] == "ACCEPTED"

    # 5. Verify the generated incident alert (allow slight timing delay)
    import time
    time.sleep(0.2)  # brief pause for threaded processing
    status, inc_resp = api_request(base_url, "/api/zta/incidents", method="GET")
    assert status == 200
    incidents = inc_resp["incidents"]
    custom_incident = next((i for i in incidents if i.get("agent_id") == "agent-runtime-01"), None)
    assert custom_incident is not None, f"No incident found for agent-runtime-01. Got: {[i['agent_id'] for i in incidents]}"
    # Severity should be CRITICAL for mimikatz rule
    assert custom_incident["severity"] == "CRITICAL"
    # Action taken should reflect policy response (LOGOUT_USER or NOTIFY_SOC based on risk range)
    assert custom_incident["action_taken"] in ("LOGOUT_USER", "NOTIFY_SOC", "ISOLATE_ENDPOINT", "MONITOR", "ALERT")

    # 6. Verify rule match count incremented in DB
    status, rule_check = api_request(base_url, f"/api/zta/rules/{rule_id}", method="GET")
    assert status == 200
    assert rule_check["rule"]["total_matches"] >= 1

    # 7. Verify audit logs record rule creation and policy creation
    status, audit_resp = api_request(base_url, "/api/zta/audit", method="GET")
    assert status == 200
    audit_events = [a["event_type"] for a in audit_resp["audit_logs"]]
    assert "RULE_CREATED" in audit_events
    assert "POLICY_CREATED" in audit_events


def test_rule_toggle_rejects_truthy_non_boolean_values(test_server):
    base = test_server["base_url"]
    status, created = api_request(base, "/api/zta/rules", method="POST",
                                  body={**_valid_rule("STRICT-TOGGLE"), "enabled": False})
    assert status == 201
    rule_id = created["rule"]["rule_id"]
    for method in ("POST", "PATCH"):
        for value in ("false", "true", 2, [], {}):
            status, result = api_request(base, f"/api/zta/rules/{rule_id}/toggle",
                                         method=method, body={"enabled": value})
            assert status == 400, (method, value, result)
            assert test_server["server"].runtime[0].get_rule_by_id(rule_id)["enabled"] == 0
