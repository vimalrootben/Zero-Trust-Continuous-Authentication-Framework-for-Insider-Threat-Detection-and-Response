"""ZTA Manager API Server with Real Background Rule Engine, Policy Engine, Command Dispatcher & Live Streaming."""

import base64
import hashlib
import hmac
import json
import logging
import os
import struct
import select
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from zta.agent.commands.command_receiver import AgentCommandReceiver
from zta.api.auth import OperatorAuth
from zta.engine.correlation.engine import ZTACorrelationEngine
from zta.engine.events.conditions import ConditionEvaluator, InvalidConditionError, RuleValidator
from zta.engine.events.models import ZTAEvent
from zta.engine.events.wazuh_adapter import ZTAEventAdapter
from zta.engine.policy.engine import PolicyDecision, ZTAPolicy, ZTAPolicyEngine
from zta.engine.risk.engine import ZTARiskEngine
from zta.engine.trust.engine import ZTATrustEngine
from zta.storage.database import RuleDependencyError, ZTADatabase, ZTARepository

logger = logging.getLogger("ZTAManager")

# Supported Schema for Detection Rules, Condition Builders, and Response Policies
SCHEMA_DATA = {
    "supported_fields": [
        {"path": "event_type", "label": "event_type", "type": "string", "example": "PROCESS_CREATION"},
        {"path": "collector_type", "label": "collector_type", "type": "string", "example": "process"},
        {"path": "process.name", "label": "process.name", "type": "string", "example": "powershell.exe"},
        {"path": "process.command_line", "label": "process.command_line", "type": "string", "example": "-encodedcommand"},
        {"path": "process.path", "label": "process.path", "type": "string", "example": "C:\\Windows\\System32\\powershell.exe"},
        {"path": "user.name", "label": "user.name", "type": "string", "example": "analyst"},
        {"path": "destination_ip", "label": "destination_ip", "type": "string", "example": "198.51.100.45"},
        {"path": "destination_port", "label": "destination_port", "type": "number", "example": 443},
        {"path": "failed_count", "label": "failed_count", "type": "number", "example": 5},
        {"path": "risk_score", "label": "risk_score", "type": "number", "example": 85},
        {"path": "trust_score", "label": "trust_score", "type": "number", "example": 15},
        {"path": "agent.department", "label": "agent.department", "type": "string", "example": "Finance"},
        {"path": "agent.connection_state", "label": "agent.connection_state", "type": "string", "example": "ONLINE"},
        {"path": "data.process_name", "label": "data.process_name", "type": "string", "example": "cmd.exe"},
        {"path": "data.command_line", "label": "data.command_line", "type": "string", "example": "-enc"},
        {"path": "data.registry_path", "label": "data.registry_path", "type": "string", "example": "CurrentVersion\\Run"},
        {"path": "data.target_process", "label": "data.target_process", "type": "string", "example": "lsass.exe"},
        {"path": "data.process_path", "label": "data.process_path", "type": "string", "example": "C:\\Temp"},
    ],
    "supported_operators": [
        {"op": "eq", "label": "equals (==)", "description": "Exact value match"},
        {"op": "ne", "label": "not equals (!=)", "description": "Value does not match"},
        {"op": "contains", "label": "contains", "description": "Substring match"},
        {"op": "contains_icase", "label": "contains (case-insensitive)", "description": "Case-insensitive substring match"},
        {"op": "gt", "label": "greater than (>)", "description": "Numeric greater than"},
        {"op": "gte", "label": "greater than or equal (>=)", "description": "Numeric greater than or equal"},
        {"op": "lt", "label": "less than (<)", "description": "Numeric less than"},
        {"op": "lte", "label": "less than or equal (<=)", "description": "Numeric less than or equal"},
        {"op": "in", "label": "in (list)", "description": "Value is in array"},
        {"op": "not_in", "label": "not in (list)", "description": "Value is not in array"},
        {"op": "exists", "label": "exists", "description": "Field is present and not null"},
        {"op": "not_exists", "label": "not exists", "description": "Field is missing or null"},
        {"op": "regex", "label": "matches regex", "description": "Regular expression pattern"},
    ],
    "combinators": [
        {"id": "all", "label": "ALL / AND", "description": "Every condition in group must be TRUE"},
        {"id": "any", "label": "ANY / OR", "description": "At least one condition in group must be TRUE"},
        {"id": "not", "label": "NOT", "description": "Inverts the evaluation of the child condition"},
    ],
    "categories": [
        "Authentication", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Exfiltration", "Command and Control", "General"
    ],
    "severities": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    "mitre_tactics": [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact"
    ],
    "response_actions": [
        {"action": "MONITOR", "label": "MONITOR", "description": "Passive observation and telemetry recording"},
        {"action": "ALERT", "label": "ALERT", "description": "Generate security alert notification"},
        {"action": "NOTIFY_SOC", "label": "NOTIFY_SOC", "description": "Escalate to Security Operations Center"},
        {"action": "LOGOUT_USER", "label": "LOGOUT_USER", "description": "Terminate active user session via logoff"},
        {"action": "KILL_PROCESS", "label": "KILL_PROCESS", "description": "Terminate suspicious target process"},
        {"action": "ISOLATE_ENDPOINT", "label": "ISOLATE_ENDPOINT", "description": "Isolate host from network except Manager"},
    ],
    "policy_modes": [
        {"mode": "ALERT_ONLY", "label": "ALERT_ONLY", "description": "Audit Mode: Records policy trigger without dispatching automated response"},
        {"mode": "ENFORCE", "label": "ENFORCE", "description": "Enforce Mode: Automatically triggers response action via endpoint agent"},
    ],
}


class WebSocketHub:
    """Manages active WebSocket and SSE client connections for real-time dashboard updates."""

    def __init__(self):
        self._ws_clients: Set[Any] = set()
        self._sse_clients: Set[Any] = set()
        self._lock = threading.Lock()
        self._local = threading.local()

    def register_ws(self, client):
        with self._lock:
            self._ws_clients.add(client)

    def unregister_ws(self, client):
        with self._lock:
            self._ws_clients.discard(client)

    def register_sse(self, client):
        with self._lock:
            self._sse_clients.add(client)

    def unregister_sse(self, client):
        with self._lock:
            self._sse_clients.discard(client)

    def begin(self): self._local.pending = []
    def rollback(self): self._local.pending = None
    def commit(self):
        pending = self._local.pending
        self._local.pending = None
        for kind, data in pending:
            self.broadcast(kind, data)

    def broadcast(self, event_type: str, data: Dict[str, Any]):
        """Broadcasts a structured JSON event to all connected dashboard clients."""
        if getattr(self._local, "pending", None) is not None:
            self._local.pending.append((event_type, data))
            return
        payload = json.dumps({"event": event_type, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()})
        with self._lock:
            # WebSocket framing (RFC 6455 text frame)
            raw = payload.encode("utf-8")
            length = len(raw)
            if length < 126:
                header = bytes([0x81, length])
            elif length <= 65535:
                header = struct.pack("!BBH", 0x81, 126, length)
            else:
                header = struct.pack("!BBQ", 0x81, 127, length)
            frame = header + raw

            dead_ws = set()
            for client in self._ws_clients:
                try:
                    client.wfile.write(frame)
                    client.wfile.flush()
                except Exception:
                    dead_ws.add(client)
            self._ws_clients.difference_update(dead_ws)

            # SSE framing
            sse_data = f"event: {event_type}\ndata: {payload}\n\n".encode("utf-8")
            dead_sse = set()
            for client in self._sse_clients:
                try:
                    client.wfile.write(sse_data)
                    client.wfile.flush()
                except Exception:
                    dead_sse.add(client)
            self._sse_clients.difference_update(dead_sse)


class ZTABackgroundEngine:
    """Background engine orchestrating Rule Evaluation, Risk Scoring, Alert Generation, and Policy Execution."""

    def __init__(self, repo: ZTARepository, hub: WebSocketHub):
        self.repo = repo
        self.hub = hub
        self.evaluator = ConditionEvaluator()
        self.risk_engine = ZTARiskEngine(decay_rate_per_min=1.0)
        self.trust_engine = ZTATrustEngine(self.risk_engine)
        self.correlation_engine = ZTACorrelationEngine(window_seconds=300)
        self.policy_engine = ZTAPolicyEngine()
        self._rules_cache: Optional[List[Dict[str, Any]]] = None
        self._reload_rules()
        self._reload_policies()

    def _reload_rules(self):
        """Loads and caches active rules from repository for fast runtime evaluation."""
        self._rules_cache = self.repo.get_rules()

    def _reload_policies(self):
        """Loads declarative policies from repository into policy engine."""
        db_policies = self.repo.get_policies()
        self.policy_engine.policies = []
        if db_policies:
            policies = []
            for p in db_policies:
                policies.append(
                    ZTAPolicy(
                        policy_id=p["policy_id"],
                        name=p["name"],
                        min_risk=p.get("min_risk", 0),
                        max_risk=p.get("max_risk", 100),
                        action=p.get("action", "MONITOR"),
                        enabled=bool(p.get("enabled", 1)),
                        code=p.get("code"),
                        category=p.get("category", "general"),
                        severity=p.get("severity", "HIGH"),
                        rule_id=p.get("rule_id"),
                        risk_threshold=p.get("risk_threshold", 85),
                        mode=p.get("mode", "ENFORCE"),
                        condition=p.get("condition"),
                        allow_offline=bool(p.get("allow_offline", 0)),
                    )
                )
            self.policy_engine.policies = policies

    def process_event(self, event: ZTAEvent, execution_source: str = "AGENT_ONLINE", synced_at: Optional[str] = None) -> List[Dict[str, Any]]:
        from zta.engine.pipeline import process
        return process(self, event, execution_source, synced_at)


class ZTAApiHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(self.dashboard_dir), **kwargs)

    def list_directory(self, path):
        self.send_error(404)
        return None

    @property
    def _bearer_token(self):
        value = self.headers.get("Authorization", "")
        return value[7:].strip() if value.startswith("Bearer ") else ""

    @property
    def _identity(self):
        return OperatorAuth(self.repo.db).identity(self._bearer_token)

    @property
    def _role(self):
        identity = self._identity
        return identity["role"] if identity else None

    @property
    def _actor(self):
        identity = self._identity
        return identity["username"] if identity else "anonymous"

    def _require_permission(self, permission):
        identity = self._identity
        if not identity:
            self._send_json({"error": "Authentication required"}, 401)
            return False
        if permission in identity["permissions"]:
            return True
        self._send_json({"error": f"Permission '{permission}' required"}, 403)
        return False

    def _check_rbac(self, required_role="ADMIN"):
        return self._require_permission("config:write")

    def _agent_secret(self, agent_id):
        return json.loads(os.environ.get("ZTA_AGENT_TOKENS", "{}" )).get(agent_id, "")

    def _authenticate_agent(self, agent_id):
        secret = self._agent_secret(agent_id)
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        if not secret or not hmac.compare_digest(secret, supplied):
            raise ValueError("Agent authentication failed")
        return secret

    def _read_json(self) -> Any:
        length = int(self.headers.get("Content-Length", 0))
        if not 0 < length <= 5_000_000:
            raise ValueError("JSON body must be between 1 byte and 5 MB")
        return json.loads(self.rfile.read(length))

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _handle_websocket(self, protocol=None):
        """Performs WebSocket handshake (RFC 6455) and registers client."""
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        sha1 = hashlib.sha1((key + accept_guid).encode("utf-8")).digest()
        accept_token = base64.b64encode(sha1).decode("utf-8")

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_token)
        if protocol:
            self.send_header("Sec-WebSocket-Protocol", protocol)
        self.end_headers()

        self.connection.settimeout(5)
        self.hub.register_ws(self)
        def read_exact(length):
            value = b''
            while len(value) < length:
                block = self.connection.recv(length-len(value))
                if not block: raise EOFError()
                value += block
            return value
        try:
            while not self.worker.stop_event.is_set():
                if not select.select([self.connection], [], [], 1)[0]: continue
                first, second = read_exact(2)
                opcode, length = first & 15, second & 127
                if not second & 128: break  # Client frames must be masked.
                if length == 126: length = struct.unpack('!H', read_exact(2))[0]
                elif length == 127: length = struct.unpack('!Q', read_exact(8))[0]
                if length > 1048576: break
                mask = read_exact(4)
                data = bytes(v ^ mask[i % 4] for i,v in enumerate(read_exact(length)))
                if opcode == 8: break
                if opcode == 9 and length <= 125:
                    with self.hub._lock:
                        self.wfile.write(bytes([0x8a,length])+data)
                        self.wfile.flush()
        except (OSError, EOFError):
            pass
        finally:
            self.close_connection = True
            self.hub.unregister_ws(self)

    def do_GET(self):
        url = urlparse(self.path)
        path = url.path.rstrip("/")

        # WebSocket / Realtime streaming
        if path in ("/api/zta/ws", "/ws"):
            if self.headers.get("Upgrade", "").lower() != "websocket":
                self._send_json({"error":"WebSocket upgrade required"},400)
                return
            protocols = [item.strip() for item in self.headers.get("Sec-WebSocket-Protocol", "").split(",")]
            auth_protocol = next((item for item in protocols if item.startswith("zta-token.")), None)
            token = auth_protocol.removeprefix("zta-token.") if auth_protocol else self._bearer_token
            identity = OperatorAuth(self.repo.db).identity(token)
            if not identity:
                self._send_json({"error": "Authentication required"}, 401)
                return
            if "stream" not in identity["permissions"]:
                self._send_json({"error": "Permission 'stream' required"}, 403)
                return
            self._handle_websocket(auth_protocol)
            return

        if path == "/api/zta/session":
            identity = self._identity
            if not identity:
                self._send_json({"authenticated": False, "error": "Authentication required"}, 401)
                return
            self._send_json({"authenticated": True, "user": identity["username"], "role": identity["role"], "permissions": identity["permissions"]})
            return

        if path == "/api/zta/users":
            if not self._require_permission("users:manage"): return
            self._send_json({"users": OperatorAuth(self.repo.db).list_users()})
            return

        if path.startswith("/api/zta/") or path.startswith("/api/v1/analytics/") or path == "/api/v1/agents/logs":
            permission = "audit:read" if path == "/api/zta/audit" else "read"
            if not self._require_permission(permission): return

        if path in ("/api/zta/schema", "/api/zta/rules/schema"):
            self._send_json(SCHEMA_DATA)
            return

        if path == "/api/zta/overview":
            agents = self.repo.get_agents()
            with self.repo.db.get_connection() as conn:
                total_events = conn.execute("SELECT COUNT(*) FROM zta_events").fetchone()[0]
                incidents_count = conn.execute("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('CLOSED', 'RESOLVED')").fetchone()[0]
                critical_count = conn.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'CRITICAL' AND status NOT IN ('CLOSED', 'RESOLVED')").fetchone()[0]
                total_rules = conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
                enabled_rules = conn.execute("SELECT COUNT(*) FROM rules WHERE enabled = 1").fetchone()[0]
                rule_matches_count = conn.execute("SELECT COUNT(*) FROM rule_matches").fetchone()[0]
                total_policies = conn.execute("SELECT COUNT(*) FROM policies").fetchone()[0]
                enabled_policies = conn.execute("SELECT COUNT(*) FROM policies WHERE enabled = 1").fetchone()[0]
                policy_triggers_count = conn.execute("SELECT COUNT(*) FROM policy_evaluations WHERE evaluation_result = 'TRIGGERED'").fetchone()[0]
                automated_responses = conn.execute("SELECT COUNT(*) FROM commands WHERE status = 'SUCCESS'").fetchone()[0]
                pending_responses = conn.execute("SELECT COUNT(*) FROM commands WHERE status IN ('PENDING', 'QUEUED', 'DISPATCHED')").fetchone()[0]
                failed_responses = conn.execute("SELECT COUNT(*) FROM commands WHERE status = 'FAILED'").fetchone()[0]
                containment = conn.execute("SELECT COUNT(*) FROM incidents WHERE status = 'CONTAINED'").fetchone()[0]

            online_agents = sum(1 for a in agents if a["status"] == "ACTIVE")
            offline_agents = sum(1 for a in agents if a["status"] == "DISCONNECTED")
            isolated_agents = sum(1 for a in agents if a["status"] == "ISOLATED")

            active_risks = [a["risk_score"] for a in agents if a.get("risk_score") is not None and a["status"] == "ACTIVE"]
            fleet_risk_avg = round(sum(active_risks) / len(active_risks), 1) if active_risks else 0.0

            overview_data = {
                "system": "ZTA (Zero Trust Architecture)",
                "status": "HEALTHY" if all(s["status"] == "RUNNING" for s in self.repo.get_background_services()) else "DEGRADED",
                "total_endpoints": len(agents),
                "online_agents": online_agents,
                "offline_agents": offline_agents,
                "isolated_agents": isolated_agents,
                "fleet_risk_average": fleet_risk_avg,
                "total_events": total_events,
                "offline_queued_events": sum(a.get("queue_depth", 0) for a in agents),
                "open_incidents": incidents_count,
                "critical_alerts": critical_count,
                "total_rules": total_rules,
                "enabled_rules": enabled_rules,
                "rule_matches": rule_matches_count,
                "total_policies": total_policies,
                "enabled_policies": enabled_policies,
                "policy_triggers": policy_triggers_count,
                "automated_responses": automated_responses,
                "pending_responses": pending_responses,
                "failed_responses": failed_responses,
                "active_containment_actions": containment,
                "risk_distribution": {
                    level: sum(a["risk_level"] == level for a in agents)
                    for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNASSESSED")
                },
                "background_services": self.repo.get_background_services(),
            }
            self._send_json(overview_data)
        elif path in ("/api/zta/analytics/overview", "/api/v1/analytics/overview"):
            agents = self.repo.get_agents()
            with self.repo.db.get_connection() as conn:
                total_events = conn.execute("SELECT COUNT(*) FROM zta_events").fetchone()[0]
                incidents_count = conn.execute("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('CLOSED', 'RESOLVED')").fetchone()[0]
                critical_count = conn.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'CRITICAL' AND status NOT IN ('CLOSED', 'RESOLVED')").fetchone()[0]
                rule_matches_count = conn.execute("SELECT COUNT(*) FROM rule_matches").fetchone()[0]
            active_risks = [a["risk_score"] for a in agents if a.get("risk_score") is not None and a["status"] == "ACTIVE"]
            fleet_risk_avg = round(sum(active_risks) / len(active_risks), 1) if active_risks else 0.0
            self._send_json({
                "total_endpoints": len(agents),
                "online_endpoints": sum(1 for a in agents if a["status"] == "ACTIVE"),
                "offline_endpoints": sum(1 for a in agents if a["status"] == "DISCONNECTED"),
                "fleet_risk_average": fleet_risk_avg,
                "open_incidents": incidents_count,
                "critical_alerts": critical_count,
                "total_events": total_events,
                "rule_matches": rule_matches_count,
            })
        elif path in ("/api/zta/analytics/alerts", "/api/v1/analytics/alerts"):
            incidents = self.repo.get_incidents(limit=500)
            self._send_json({
                "total_alerts": len(incidents),
                "severity_distribution": {
                    sev: sum(1 for i in incidents if i["severity"] == sev)
                    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                },
                "status_distribution": {
                    st: sum(1 for i in incidents if i["status"] == st)
                    for st in ("OPEN", "CONTAINED", "RESOLVED", "CLOSED")
                }
            })
        elif path in ("/api/zta/analytics/risk-distribution", "/api/v1/analytics/risk-distribution"):
            agents = self.repo.get_agents()
            scored = [a["risk_score"] for a in agents if a.get("risk_score") is not None]
            fleet_avg = round(sum(scored) / len(scored), 1) if scored else 0.0
            dist = {
                "low": sum(1 for s in scored if s < 30),
                "medium": sum(1 for s in scored if 30 <= s < 60),
                "high": sum(1 for s in scored if 60 <= s < 85),
                "critical": sum(1 for s in scored if s >= 85),
                "unassessed": sum(1 for a in agents if a.get("risk_score") is None),
            }
            self._send_json({
                "distribution": dist,
                "fleet_avg": fleet_avg,
                "total_agents": len(agents),
            })
        elif path in ("/api/zta/analytics/events-timeseries", "/api/v1/analytics/events-timeseries"):
            range_param = parse_qs(url.query).get("range", ["24h"])[0]
            with self.repo.db.get_connection() as conn:
                # Query recent events grouped into bucket counts
                events_rows = conn.execute("SELECT timestamp, event_type, severity FROM zta_events ORDER BY timestamp DESC LIMIT 100").fetchall()
            points = []
            for r in events_rows:
                points.append({
                    "timestamp": r[0],
                    "event_type": r[1],
                    "severity": r[2],
                    "count": 1,
                })
            self._send_json({
                "range": range_param,
                "points": points,
                "total": len(points),
            })
        elif path in ("/api/zta/analytics/mitre-coverage", "/api/v1/analytics/mitre-coverage"):
            rules = self.repo.get_rules()
            tactics = {}
            techniques = {}
            for r in rules:
                tac = r.get("mitre_tactic") or "Unknown"
                tech = r.get("mitre_technique_id") or "Unknown"
                tactics[tac] = tactics.get(tac, 0) + 1
                techniques[tech] = techniques.get(tech, 0) + 1
            self._send_json({
                "tactics": tactics,
                "techniques": techniques,
                "total_rules": len(rules),
            })
        elif path == "/api/zta/agents":
            self._send_json({"agents": self.repo.get_agents()})
        elif path.startswith("/api/zta/agents/"):
            agent_id = path.split("/")[-1]
            agents = [a for a in self.repo.get_agents() if a["id"] == agent_id]
            if agents:
                agent = dict(agents[0])
                agent["risk_history"] = self.repo.get_agent_risk_history(agent_id)
                agent["commands"] = self.repo.get_commands(limit=20, agent_id=agent_id)
                agent["logs"] = self.repo.get_agent_logs(agent_id=agent_id, limit=50)
                trust_state = self.engine.trust_engine.evaluate_trust(agent_id, risk_score=agent["risk_score"] or 0)
                agent["trust_score"] = trust_state.trust_score if agent["risk_score"] is not None else None
                agent["trust_status"] = trust_state.status if agent["risk_score"] is not None else "UNASSESSED"
                self._send_json({"agent": agent})
            else:
                self._send_json({"error": "Agent not found"}, 404)
        elif path in ("/api/zta/logs", "/api/v1/agents/logs"):
            agent_id = parse_qs(url.query).get("agent_id", [None])[0]
            self._send_json({"logs": self.repo.get_agent_logs(agent_id=agent_id)})
        elif path == "/api/zta/events":
            try:
                limit = max(1, min(10000, int(parse_qs(url.query).get("limit", [1000])[0])))
            except ValueError:
                self._send_json({"error": "limit must be an integer"}, 400)
                return
            self._send_json({"events": self.repo.get_recent_events(limit)})
        elif path == "/api/zta/rules":
            self._send_json({"rules": self.repo.get_rules()})
        elif path.startswith("/api/zta/rules/") and path.endswith("/versions"):
            rule_id = path.split("/")[-2]
            versions = self.repo.get_rule_versions(rule_id)
            if versions:
                self._send_json({"versions": versions})
            else:
                self._send_json({"error": "Rule not found"}, 404)
        elif path.startswith("/api/zta/rules/"):
            rule_id = path.split("/")[-1]
            rule = self.repo.get_rule_by_id(rule_id)
            if rule:
                self._send_json({"rule": rule})
            else:
                self._send_json({"error": "Rule not found"}, 404)
        elif path == "/api/zta/sync":
            self._send_json({"sync_history": self.repo.get_sync_history()})
        elif path == "/api/zta/rule-evaluations":
            with self.repo.db.get_connection() as conn:
                rows = [dict(r) for r in conn.execute("SELECT * FROM rule_evaluations ORDER BY timestamp DESC LIMIT 500")]
            self._send_json({"rule_evaluations": rows})
        elif path == "/api/zta/rule-matches":
            try:
                limit = max(1, min(500, int(parse_qs(url.query).get("limit", [100])[0])))
            except ValueError:
                limit = 100
            self._send_json({"rule_matches": self.repo.get_rule_matches(limit=limit)})
        elif path == "/api/zta/policies":
            self._send_json({"policies": self.repo.get_policies()})
        elif path.startswith("/api/zta/policies/"):
            policy_id = path.split("/")[-1]
            policy = self.repo.get_policy_by_id(policy_id)
            if policy:
                self._send_json({"policy": policy})
            else:
                self._send_json({"error": "Policy not found"}, 404)
        elif path == "/api/zta/policy-evaluations":
            try:
                limit = max(1, min(500, int(parse_qs(url.query).get("limit", [100])[0])))
            except ValueError:
                limit = 100
            self._send_json({"policy_evaluations": self.repo.get_policy_evaluations(limit=limit)})
        elif path in ("/api/zta/incidents", "/api/zta/alerts"):
            self._send_json({"incidents": self.repo.get_incidents()})
        elif path.startswith("/api/zta/incidents/") or path.startswith("/api/zta/alerts/"):
            incident_id = path.split("/")[-1]
            incident = self.repo.get_incident_by_id(incident_id)
            if incident:
                self._send_json({"incident": incident})
            else:
                self._send_json({"error": "Incident not found"}, 404)
        elif path == "/api/zta/commands":
            try:
                limit = max(1, min(500, int(parse_qs(url.query).get("limit", [100])[0])))
            except ValueError:
                limit = 100
            self._send_json({"commands": self.repo.get_commands(limit=limit)})
        elif path == "/api/zta/timeline":
            # Build unified chronological timeline
            events = self.repo.get_recent_events(limit=50)
            matches = self.repo.get_rule_matches(limit=50)
            evals = self.repo.get_policy_evaluations(limit=50)
            commands = self.repo.get_commands(limit=50)
            audits = self.repo.get_audit_logs(limit=50)

            timeline = []
            for e in events:
                timeline.append({"id": f"tl-evt-{e['event_id']}", "type": "EVENT", "timestamp": e["timestamp"], "title": f"Telemetry Event: {e['event_type']}", "agent_id": e["agent_id"], "agent_name": e["agent_name"], "details": e})
            for m in matches:
                timeline.append({"id": f"tl-rm-{m['match_id']}", "type": "RULE_MATCH", "timestamp": m["matched_at"], "title": f"Rule Matched: {m['rule_name']} ({m['rule_code']})", "agent_id": m["agent_id"], "agent_name": m["agent_name"], "details": m})
            for pe in evals:
                timeline.append({"id": f"tl-pe-{pe['eval_id']}", "type": "POLICY_EVAL", "timestamp": pe["timestamp"], "title": f"Policy Evaluated: {pe['policy_name']} -> {pe['action']} ({pe['mode']})", "agent_id": pe["agent_id"], "details": pe})
            for c in commands:
                timeline.append({"id": f"tl-cmd-{c['command_id']}", "type": "COMMAND", "timestamp": c["created_at"], "title": f"Command Created: {c['action_type']} ({c['status']})", "agent_id": c["agent_id"], "details": c})
            for a in audits:
                timeline.append({"id": f"tl-aud-{a['id']}", "type": "AUDIT", "timestamp": a["timestamp"], "title": f"Audit: {a['event_type']} - {a['action']}", "agent_id": a.get("agent_id"), "details": a})

            timeline.sort(key=lambda x: x["timestamp"], reverse=True)
            self._send_json({"timeline": timeline[:200]})
        elif path == "/api/zta/audit":
            self._send_json({"audit_logs": self.repo.get_audit_logs(limit=100)})
        elif path in ("/api/zta/services", "/api/zta/background-services"):
            svcs = self.repo.get_background_services()
            self._send_json({"services": svcs, "background_services": svcs})
        elif path.startswith("/api/"):
            self._send_json({"error": "Endpoint not found"}, 404)
        elif path in ("", "/", "/index.html", "/assets/dashboard.css", "/assets/dashboard.js"):
            super().do_GET()
        else:
            self.send_error(404)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if not 0 < length <= 5_000_000:
                raise ValueError("JSON body must be between 1 byte and 5 MB")
            payload = json.loads(self.rfile.read(length))
            path = urlparse(self.path).path.rstrip("/")

            if path == "/api/zta/auth/login":
                result = OperatorAuth(self.repo.db).login(payload.get("username"), payload.get("password"))
                if not result:
                    self._send_json({"error": "Invalid username or password"}, 401)
                else:
                    self._send_json(result)
                return

            if path == "/api/zta/auth/logout":
                if not self._require_permission("read"): return
                OperatorAuth(self.repo.db).logout(self._bearer_token)
                self._send_json({"status": "LOGGED_OUT"})
                return

            if path == "/api/zta/users":
                if not self._require_permission("users:manage"): return
                user = OperatorAuth(self.repo.db).create_user(payload, self._actor)
                self.repo.save_audit("USER_CREATED", f"Operator {user['username']} created with role {user['role']}", user=self._actor)
                self._send_json({"user": user}, 201)
                return

            if path.startswith("/api/zta/"):
                if path.startswith(("/api/zta/actions", "/api/zta/commands")) or (path.startswith("/api/zta/events/") and path.endswith("/retry")):
                    permission = "response:write"
                elif path.startswith(("/api/zta/rules", "/api/zta/policies")):
                    permission = "config:write"
                else:
                    permission = "config:write"
                if not self._require_permission(permission): return

            if path == "/api/v1/agents/heartbeat":
                if not isinstance(payload, dict) or not isinstance(payload.get("agent_id"), str) or not payload["agent_id"].strip():
                    raise ValueError("agent_id is required")
                if any(value is not None and not isinstance(value, (str, int, float, bool, list, dict)) for value in payload.values()):
                    raise ValueError("Heartbeat fields must be primitive or structured types")

                from zta.agent.commands.authorization import sign
                secret = self._authenticate_agent(payload["agent_id"])
                if payload.get("connection_state", "ONLINE") not in ("ONLINE", "RECONNECTING", "SYNCING", "DEGRADED"):
                    raise ValueError("Invalid heartbeat connection state")

                # Exact observed client address
                client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
                trusted_proxies = [p.strip() for p in os.environ.get("ZTA_TRUSTED_PROXIES", "").split(",") if p.strip()]
                if trusted_proxies and client_ip in trusted_proxies:
                    forwarded = self.headers.get("X-Forwarded-For")
                    if forwarded:
                        client_ip = forwarded.split(",")[0].strip()
                payload["manager_observed_ip"] = client_ip

                self.hub.begin()
                before = next((a for a in self.repo.get_agents() if a["id"] == payload["agent_id"]), None)
                self.repo.save_heartbeat(payload)
                self.repo.update_service_heartbeat("Heartbeat Monitor", activity=True)
                with self.repo.db.get_connection() as conn:
                    conn.execute("UPDATE agents SET agent_version=?,collector_error=? WHERE id=?", (payload.get("agent_version"), payload.get("collector_error"), payload["agent_id"]))
                state = payload.get("connection_state", "ONLINE")
                if not before or before["connection_state"] != state or before.get("ip") != payload.get("ip"):
                    self.repo.save_audit("AGENT_RECONNECTED" if before else "AGENT_ONLINE", state, payload["agent_id"])
                    self.hub.broadcast("agent." + state.lower(), {"agent_id": payload["agent_id"], "connection_state": state, "ip": payload.get("ip"), "manager_observed_ip": client_ip})
                pending = []
                with self.repo.db.transaction() as conn:
                    now = datetime.now(timezone.utc).isoformat()
                    rows = conn.execute("SELECT * FROM commands WHERE agent_id=? AND status IN ('QUEUED','AUTHORIZED','DISPATCHED') AND expires_at>?", (payload["agent_id"], now)).fetchall()
                    for row in rows:
                        cmd = dict(row)
                        cmd['params'] = json.loads(cmd.pop('params_json'))
                        if cmd['status'] != 'DISPATCHED':
                            conn.execute("UPDATE commands SET status='DISPATCHED',dispatched_at=? WHERE command_id=?", (now, cmd['command_id']))
                            conn.execute("UPDATE incidents SET response_status='DISPATCHED' WHERE incident_id=?", (cmd['alert_id'],))
                            self.repo.save_audit('COMMAND_DISPATCHED', cmd['action_type'], payload['agent_id'], details={'command_id': cmd['command_id'], 'alert_id': cmd['alert_id']})
                            self.hub.broadcast('command.dispatched', {'command_id': cmd['command_id'], 'agent_id': payload['agent_id']})
                        cmd.update(status='DISPATCHED', dispatched_at=cmd['dispatched_at'] or now)
                        pending.append(sign(cmd, secret))
                from datetime import timedelta
                rules, policies = self.repo.get_rules(), self.repo.get_policies()
                # Version only definitions, excluding counters and evaluation history.
                volatile = {'last_evaluated','last_matched','last_triggered','total_matches','total_triggers','recent_matches','linked_policies','recent_evaluations'}
                definition_fields = {'rule_id','policy_id','code','name','category','severity','mitre_tactic','mitre_technique_id','risk_delta','condition','condition_json','response_action','logic_type','enabled','allow_offline','min_risk','max_risk','risk_threshold','mode','action','created_at'}
                definitions = {"rules": [{k:v for k,v in r.items() if k in definition_fields} for r in rules], "policies": [{k:v for k,v in r.items() if k in definition_fields} for r in policies]}
                version = hashlib.sha256(json.dumps(definitions, sort_keys=True).encode()).hexdigest()
                cache = sign({**definitions, "agent_id": payload['agent_id'], "version": version,
                              "expires_at": (datetime.now(timezone.utc)+timedelta(hours=24)).isoformat()}, secret)
                if pending: self.repo.update_service_heartbeat('Command Dispatcher', activity=True)
                self.hub.commit()
                self._send_json({"status": "ACKNOWLEDGED", "agent_id": payload['agent_id'], "pending_commands": pending, "configuration": cache})

            elif path in ("/api/v1/telemetry/bulk", "/api/v1/sync/offline"):
                from zta.api.ingestion import ingest
                result = ingest(self, payload, path.endswith('/offline'))
                self.worker.wake.set()
                self._send_json(result, 201)

            elif path in ("/api/v1/commands/result", "/agent/commands/result"):
                from zta.api.ingestion import command_result
                self._authenticate_agent(payload.get('agent_id'))
                command_result(self, payload)
                self._send_json({"status": "ACKNOWLEDGED", "command_id": payload['command_id']})

            elif path.startswith('/api/zta/events/') and path.endswith('/retry'):
                if not self._check_rbac(): return
                event_id = path.split('/')[-2]
                with self.repo.db.get_connection() as conn:
                    changed = conn.execute("UPDATE zta_events SET processing_state='PENDING',processing_error=NULL WHERE event_id=? AND processing_state='FAILED'", (event_id,)).rowcount
                if not changed: raise ValueError('Only failed events can be retried')
                self.repo.save_audit('EVENT_RETRY_REQUESTED','Retry failed background event', user=self._actor, details={'event_id':event_id})
                self.worker.wake.set()
                self._send_json({'status':'PENDING','event_id':event_id})

            elif path == "/api/zta/actions/execute":
                if not self._require_permission("response:write"): return
                if not isinstance(payload, dict):
                    raise ValueError("Expected a JSON object")
                action = payload.get("action")
                if action not in ("KILL_PROCESS", "ISOLATE_ENDPOINT", "LOGOFF_USER", "LOGOUT_USER"):
                    self._send_json({"error": "Unsupported action"}, 403)
                    return
                if not payload.get("agent_id"):
                    raise ValueError("agent_id is required")

                agent_id = str(payload["agent_id"])
                dry_run = payload.get("dry_run", True)
                params = payload.get("params", {})
                if not isinstance(params, dict):
                    raise ValueError("params must be an object")

                if dry_run:
                    report = self.command_receiver.process_command(
                        {"command_id": "preview", "action": action, "params": params},
                        dry_run=True,
                    )
                    self._send_json({
                        "status": report.status,
                        "action": action,
                        "agent_id": agent_id,
                        "message": report.output if report.status == "PREVIEW" else report.error,
                        "executed_at": report.executed_at,
                        "dry_run": True,
                    })
                else:
                    self._send_json({
                        "error": "Remote execution is not connected; only dry-run previews are available",
                        "status": "CONFLICT",
                    }, 409)

            elif path in ("/api/v1/commands", "/api/zta/commands"):
                if not self._require_permission("response:write"): return
                if not isinstance(payload, dict):
                    raise ValueError("Expected a JSON object")
                action = payload.get("action") or payload.get("action_type")
                if action not in ("KILL_PROCESS", "ISOLATE_ENDPOINT", "LOGOFF_USER", "LOGOUT_USER", "DEMO_SCRIPT"):
                    self._send_json({"error": f"Unsupported action {action}"}, 403)
                    return
                if not payload.get("agent_id"):
                    raise ValueError("agent_id is required")

                agent_id = str(payload["agent_id"])
                params = payload.get("params", {})
                if not isinstance(params, dict):
                    raise ValueError("params must be an object")

                if not self._agent_secret(agent_id):
                    raise ValueError("No credential configured for target agent")
                preview = self.command_receiver.process_command({"command_id": "validate", "action": action, "params": params}, dry_run=True)
                if preview.status not in ("PREVIEW", "SUCCESS", "REJECTED") and preview.error:
                    raise ValueError(preview.error)
                from datetime import timedelta
                command_id = f"cmd-manual-{uuid4().hex[:8]}"
                now_iso = datetime.now(timezone.utc).isoformat()
                self.repo.save_command({
                    "command_id": command_id,
                    "agent_id": agent_id,
                    "action_type": action,
                    "params": params,
                    "status": "QUEUED",
                    "executor": "WINDOWS_POWERSHELL" if action != "DEMO_SCRIPT" else "DEMO_EXECUTOR",
                    "execution_source": "MANAGER",
                    "created_at": now_iso,
                    "expires_at": (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat(),
                })
                self.repo.save_audit(
                    event_type="COMMAND_CREATED",
                    action=f"Manual SOC command {action} dispatched to agent {agent_id}",
                    agent_id=agent_id,
                    user=self._actor,
                    details={"command_id": command_id, "action": action, "params": params},
                    execution_source="MANAGER",
                )
                self.hub.broadcast("command.created", {"command_id": command_id, "agent_id": agent_id, "action": action})
                self._send_json({
                    "status": "QUEUED",
                    "command_id": command_id,
                    "action": action,
                    "agent_id": agent_id,
                    "message": f"Command {action} queued for dispatch.",
                }, 201)

            elif path in ("/api/v1/agents/logs", "/agent/logs"):
                self._authenticate_agent(payload.get('agent_id'))
                self.repo.save_agent_log(payload, execution_source="AGENT_ONLINE")
                self.hub.broadcast("agent.log", payload)
                self._send_json({"status": "ACKNOWLEDGED", "log_id": payload.get("log_id")})

            elif path == "/api/zta/rules/validate":
                cond = payload.get("condition", payload)
                try:
                    if isinstance(payload, dict) and ("code" in payload or "name" in payload):
                        candidate = dict(payload)
                        candidate.setdefault("category", "General")
                        candidate.setdefault("severity", "MEDIUM")
                        candidate.setdefault("risk_delta", 15)
                        candidate.setdefault("response_action", "ALERT")
                        candidate.setdefault("logic_type", "CONDITION_TREE")
                        candidate.setdefault("enabled", True)
                        candidate.setdefault("allow_offline", False)
                        RuleValidator().validate(candidate)
                    else:
                        self.engine.evaluator.validate(cond)
                    self._send_json({"valid": True, "message": "Rule condition syntax is valid"})
                except Exception as exc:
                    self._send_json({"valid": False, "error": str(exc)}, 200)

            elif path == "/api/zta/rules/test":
                cond = payload.get("condition", {})
                event_dict = payload.get("event", {})
                try:
                    trace = self.engine.evaluator.explain(cond, event_dict)
                    self._send_json({"valid": True, "trace": trace, "matched": trace.get("result", False)})
                except Exception as exc:
                    self._send_json({"valid": False, "error": str(exc)}, 400)

            elif path == "/api/zta/rules":
                if not self._check_rbac("ADMIN"):
                    return
                if not isinstance(payload, dict):
                    raise ValueError("Expected a JSON object")
                cond = payload.get("condition")
                if cond:
                    self.engine.evaluator.validate(cond)
                rule = self.repo.create_rule(payload, actor=self._actor, role=self._role)
                self.engine._reload_rules()
                self.hub.broadcast("rule.created", {"rule": rule})
                self._send_json({"status": "CREATED", "rule": rule}, 201)

            elif path.startswith("/api/zta/rules/") and path.endswith("/toggle"):
                if not self._check_rbac("ADMIN"):
                    return
                rule_id = path.split("/")[-2]
                rule = self.repo.toggle_rule(rule_id, payload.get("enabled") if isinstance(payload, dict) else None, actor=self._actor, role=self._role)
                if not rule:
                    self._send_json({"error": "Rule not found"}, 404)
                    return
                self.engine._reload_rules()
                self.hub.broadcast("rule.toggled", {"rule": rule})
                self._send_json({"status": "UPDATED", "rule": rule})

            elif path.startswith("/api/zta/rules/") and path.endswith("/rollback"):
                if not self._check_rbac("ADMIN"):
                    return
                rule_id = path.split("/")[-2]
                rule = self.repo.rollback_rule(rule_id, payload.get("version"), actor=self._actor, role=self._role)
                if not rule:
                    self._send_json({"error": "Rule not found"}, 404)
                    return
                self.engine._reload_rules()
                self.hub.broadcast("rule.rolled_back", {"rule": rule})
                self._send_json({"status": "ROLLED_BACK", "rule": rule})

            elif path == "/api/zta/policies/validate":
                cond = payload.get("condition")
                try:
                    if cond:
                        self.engine.evaluator.validate(cond)
                    self._send_json({"valid": True, "message": "Policy condition syntax is valid"})
                except Exception as exc:
                    self._send_json({"valid": False, "error": str(exc)}, 200)

            elif path == "/api/zta/policies/test":
                pol_data = payload.get("policy", payload)
                ctx = payload.get("context", {})
                decision = self.engine.policy_engine.evaluate_single_policy(pol_data, ctx)
                self._send_json({"decision": {**asdict(decision), "timestamp": decision.timestamp.isoformat()}, "triggered": decision.triggered})

            elif path == "/api/zta/policies":
                if not self._check_rbac("ADMIN"):
                    return
                if not isinstance(payload, dict):
                    raise ValueError("Expected a JSON object")
                cond = payload.get("condition")
                if cond:
                    self.engine.evaluator.validate(cond)
                policy = self.repo.create_policy(payload, actor=self._actor, role=self._role)
                self.engine._reload_policies()
                self.hub.broadcast("policy.created", {"policy": policy})
                self._send_json({"status": "CREATED", "policy": policy}, 201)

            elif path.startswith("/api/zta/policies/") and path.endswith("/toggle"):
                if not self._check_rbac("ADMIN"):
                    return
                policy_id = path.split("/")[-2]
                policy = self.repo.toggle_policy(policy_id, payload.get("enabled") if isinstance(payload, dict) else None, actor=self._actor, role=self._role)
                if not policy:
                    self._send_json({"error": "Policy not found"}, 404)
                    return
                self.engine._reload_policies()
                self.hub.broadcast("policy.toggled", {"policy": policy})
                self._send_json({"status": "UPDATED", "policy": policy})

            else:
                self._send_json({"error": "Endpoint not found"}, 404)
        except (ValueError, TypeError, AttributeError) as exc:
            self.hub.rollback()
            self._send_json({"error": str(exc)}, 400)

    def do_PUT(self):
        try:
            payload = self._read_json()
            path = urlparse(self.path).path.rstrip("/")

            if path.startswith("/api/zta/rules/"):
                if not self._check_rbac("ADMIN"):
                    return
                rule_id = path.split("/")[-1]
                cond = payload.get("condition")
                if cond:
                    self.engine.evaluator.validate(cond)
                rule = self.repo.update_rule(rule_id, payload, actor=self._actor, role=self._role)
                if not rule:
                    self._send_json({"error": "Rule not found"}, 404)
                    return
                self.engine._reload_rules()
                self.hub.broadcast("rule.updated", {"rule": rule})
                self._send_json({"status": "UPDATED", "rule": rule})

            elif path.startswith("/api/zta/policies/"):
                if not self._check_rbac("ADMIN"):
                    return
                policy_id = path.split("/")[-1]
                cond = payload.get("condition")
                if cond:
                    self.engine.evaluator.validate(cond)
                policy = self.repo.update_policy(policy_id, payload, actor=self._actor, role=self._role)
                if not policy:
                    self._send_json({"error": "Policy not found"}, 404)
                    return
                self.engine._reload_policies()
                self.hub.broadcast("policy.updated", {"policy": policy})
                self._send_json({"status": "UPDATED", "policy": policy})

            else:
                self._send_json({"error": "Endpoint not found"}, 404)
        except Exception as exc:
            self._send_json({"error": str(exc)}, 400)

    def do_PATCH(self):
        try:
            payload = self._read_json() if self.headers.get("Content-Length") else {}
            path = urlparse(self.path).path.rstrip("/")

            if path.startswith("/api/zta/rules/"):
                if not self._check_rbac("ADMIN"):
                    return
                rule_id = path.split("/")[-2] if path.endswith("/toggle") else path.split("/")[-1]
                rule = self.repo.toggle_rule(rule_id, payload.get("enabled") if isinstance(payload, dict) else None, actor=self._actor, role=self._role)
                if not rule:
                    self._send_json({"error": "Rule not found"}, 404)
                    return
                self.engine._reload_rules()
                self.hub.broadcast("rule.toggled", {"rule": rule})
                self._send_json({"status": "UPDATED", "rule": rule})

            elif path.startswith("/api/zta/policies/"):
                if not self._check_rbac("ADMIN"):
                    return
                policy_id = path.split("/")[-2] if path.endswith("/toggle") else path.split("/")[-1]
                policy = self.repo.toggle_policy(policy_id, payload.get("enabled") if isinstance(payload, dict) else None, actor=self._actor, role=self._role)
                if not policy:
                    self._send_json({"error": "Policy not found"}, 404)
                    return
                self.engine._reload_policies()
                self.hub.broadcast("policy.toggled", {"policy": policy})
                self._send_json({"status": "UPDATED", "policy": policy})

            else:
                self._send_json({"error": "Endpoint not found"}, 404)
        except Exception as exc:
            self._send_json({"error": str(exc)}, 400)

    def do_DELETE(self):
        try:
            path = urlparse(self.path).path.rstrip("/")

            if path.startswith("/api/zta/rules/"):
                if not self._check_rbac("ADMIN"):
                    return
                rule_id = path.split("/")[-1]
                try:
                    res = self.repo.delete_rule(rule_id, actor=self._actor, role=self._role)
                    self.engine._reload_rules()
                    self.hub.broadcast("rule.deleted", {"rule_id": rule_id})
                    self._send_json(res)
                except RuleDependencyError as e:
                    self._send_json({"error": str(e)}, 409)
                except ValueError as e:
                    self._send_json({"error": str(e)}, 404)

            elif path.startswith("/api/zta/policies/"):
                if not self._check_rbac("ADMIN"):
                    return
                policy_id = path.split("/")[-1]
                try:
                    res = self.repo.delete_policy(policy_id, actor=self._actor, role=self._role)
                    self.engine._reload_policies()
                    self.hub.broadcast("policy.deleted", {"policy_id": policy_id})
                    self._send_json(res)
                except ValueError as e:
                    self._send_json({"error": str(e)}, 404)

            else:
                self._send_json({"error": "Endpoint not found"}, 404)
        except Exception as exc:
            self._send_json({"error": str(exc)}, 400)


class ZTAHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    def server_close(self):
        super().server_close()
        if getattr(self, "owns_runtime", False): self.worker.close()


def create_zta_server(host="127.0.0.1", port=8080, db_path=None, runtime=None):
    root = Path(__file__).resolve().parents[1]
    default = root / "zta_runtime.db"
    if not default.exists():
        default = root / "zta_api_server.db" if (root / "zta_api_server.db").exists() else root / "var" / "zta_api_server.db"
    if runtime is None:
        from zta.api.background import BackgroundWorker
        repo = ZTARepository(ZTADatabase(db_path or os.environ.get("ZTA_DB_PATH", str(default))))
        hub = WebSocketHub()
        engine = ZTABackgroundEngine(repo, hub)
        worker = BackgroundWorker(engine)
    else:
        repo, hub, engine, worker = runtime
    handler = type("ZTAHandler", (ZTAApiHandler,), dict(repo=repo, hub=hub, engine=engine, worker=worker,
                   command_receiver=AgentCommandReceiver(), dashboard_dir=root / "dashboard"))
    server = ZTAHTTPServer((host, port), handler)
    server.runtime = (repo, hub, engine, worker)
    server.worker = worker
    server.owns_runtime = runtime is None
    if server.owns_runtime: worker.start()
    return server
