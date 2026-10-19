"""ZTA Manager API Server with Real Background Rule Engine, Policy Engine, Command Dispatcher & Live Streaming."""

import base64
import csv
import hashlib
import hmac
import json
import io
import logging
import os
import queue
import struct
import select
import secrets
import threading
import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
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
from zta.engine.policy.engine import PolicyDecision, PolicyValidator, ZTAPolicy, ZTAPolicyEngine
from zta.engine.risk.engine import ZTARiskEngine
from zta.engine.trust.engine import ZTATrustEngine
from zta.storage.database import RuleDependencyError, ZTADatabase, ZTARepository

logger = logging.getLogger("ZTAManager")


class AgentAuthenticationError(PermissionError):
    """The endpoint credential is missing or does not match its registered identity."""

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
        {"action": "LOCK_LOCAL_ACCOUNT", "label": "LOCK_LOCAL_ACCOUNT", "description": "Disable a verified local account"},
        {"action": "UNLOCK_LOCAL_ACCOUNT", "label": "UNLOCK_LOCAL_ACCOUNT", "description": "Restore a previously contained local account"},
        {"action": "UNISOLATE_ENDPOINT", "label": "UNISOLATE_ENDPOINT", "description": "Remove only ZTA-owned isolation controls"},
        {"action": "LOCK_WORKSTATION", "label": "LOCK_WORKSTATION", "description": "Lock a verified interactive session"},
        {"action": "QUARANTINE_FILE", "label": "QUARANTINE_FILE", "description": "Move a hash-verified file to controlled quarantine"},
    ],
    "policy_modes": [
        {"mode": "ALERT_ONLY", "label": "ALERT_ONLY", "description": "Audit Mode: Records policy trigger without dispatching automated response"},
        {"mode": "ENFORCE", "label": "ENFORCE", "description": "Enforce Mode: Automatically triggers response action via endpoint agent"},
    ],
}


class WebSocketHub:
    """Manages active WebSocket and SSE client connections for real-time dashboard updates."""

    def __init__(self, repo=None):
        self._ws_clients: Set[Any] = set()
        self._ws_authorizers = {}
        self._ws_queues = {}
        self._queue_size = max(8, int(os.environ.get("ZTA_WS_CLIENT_QUEUE_SIZE", "256")))
        self._sse_clients: Set[Any] = set()
        self._lock = threading.Lock()
        self._local = threading.local()
        self.repo = repo
        self._max_payload = 1_048_576

    def register_ws(self, client, authorize=None):
        outbound = queue.Queue(maxsize=self._queue_size)
        with self._lock:
            self._ws_clients.add(client)
            self._ws_queues[client] = outbound
            if authorize is not None:
                self._ws_authorizers[client] = authorize
        threading.Thread(target=self._writer, args=(client, outbound), name="zta-ws-writer", daemon=True).start()

    def unregister_ws(self, client):
        with self._lock:
            self._ws_clients.discard(client)
            self._ws_authorizers.pop(client, None)
            self._ws_queues.pop(client, None)

    def _writer(self, client, outbound):
        """Isolate socket writes so one slow browser cannot block fan-out."""
        try:
            while not getattr(client, "close_connection", False):
                try:
                    frame = outbound.get(timeout=1)
                except queue.Empty:
                    authorize = self._ws_authorizers.get(client)
                    if authorize is not None and not authorize(): break
                    continue
                if frame is None: break
                authorize = self._ws_authorizers.get(client)
                if authorize is not None and not authorize(): break
                client.wfile.write(frame)
                client.wfile.flush()
        except Exception:
            logger.info("websocket.client_disconnected", extra={"event_name": "websocket.client_disconnected"})
        finally:
            client.close_connection = True
            self.unregister_ws(client)

    def register_sse(self, client):
        with self._lock:
            self._sse_clients.add(client)

    def unregister_sse(self, client):
        with self._lock:
            self._sse_clients.discard(client)

    def begin(self): self._local.pending = []
    def rollback(self): self._local.pending = None
    def commit(self):
        pending = self._local.pending or []
        self._local.pending = None
        for item in pending:
            kind, data, publication = item
            self._send(kind, data, publication)

    def broadcast(self, event_type: str, data: Dict[str, Any]):
        """Broadcasts a structured JSON event to all connected dashboard clients."""
        publication = self.repo.enqueue_realtime_event(event_type, data) if self.repo else None
        if getattr(self._local, "pending", None) is not None:
            self._local.pending.append((event_type, data, publication))
            return
        self._send(event_type, data, publication)

    def _send(self, event_type, data, publication=None):
        envelope = {"event": event_type, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()}
        if publication:
            envelope.update(event_id=publication["event_id"], sequence_number=publication["sequence_number"], created_at=publication["created_at"])
        payload = json.dumps(envelope, default=str)
        if len(payload.encode("utf-8")) > self._max_payload:
            if publication: self.repo.mark_realtime_delivery(publication["event_id"], False, "payload too large")
            return
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
            for client in tuple(self._ws_clients):
                authorize = self._ws_authorizers.get(client)
                outbound = self._ws_queues.get(client)
                try:
                    if authorize is not None and not authorize():
                        raise PermissionError("stream authorization revoked")
                    outbound.put_nowait(frame)
                except (queue.Full, AttributeError, PermissionError):
                    dead_ws.add(client)
                    client.close_connection = True
            for client in dead_ws:
                self._ws_clients.discard(client)
                self._ws_authorizers.pop(client, None)
                self._ws_queues.pop(client, None)

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
        if publication:
            self.repo.mark_realtime_delivery(publication["event_id"], True)

    def recover_pending(self, limit=200):
        if not self.repo: return 0
        rows = self.repo.get_realtime_events(0, limit, pending_only=True)
        for row in rows: self._send(row["event_type"], row["data"], row)
        return len(rows)


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
                        mode=p.get("mode", "ALERT_ONLY"),
                        condition=p.get("condition"),
                        allow_offline=bool(p.get("allow_offline", 0)),
                        priority=p.get("priority", 1000),
                    )
                )
            self.policy_engine.policies = policies

    def process_event(self, event: ZTAEvent, execution_source: str = "AGENT_ONLINE", synced_at: Optional[str] = None) -> List[Dict[str, Any]]:
        from zta.engine.pipeline import process
        return process(self, event, execution_source, synced_at)


class ZTAApiHandler(SimpleHTTPRequestHandler):
    _db_clear_tokens = {}
    _db_clear_lock = threading.Lock()
    _inventory_digests = {}
    _inventory_lock = threading.Lock()
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

    @classmethod
    def _inventory_changed(cls, agent_id, kind, value):
        digest = hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()
        key = (agent_id, kind)
        with cls._inventory_lock:
            changed = cls._inventory_digests.get(key) != digest
            cls._inventory_digests[key] = digest
        return changed

    def _authenticate_agent(self, agent_id):
        secret = self._agent_secret(agent_id)
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        if not secret or not hmac.compare_digest(secret, supplied):
            raise AgentAuthenticationError("Agent authentication failed")
        return secret

    def _read_json(self) -> Any:
        length = int(self.headers.get("Content-Length", 0))
        if not 0 < length <= 5_000_000:
            raise ValueError("JSON body must be between 1 byte and 5 MB")
        return json.loads(self.rfile.read(length))

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            self.close_connection = True
            logger.debug("http.client_disconnected", extra={"event_name": "http.client_disconnected"})

    def _send_download(self, body, content_type, filename):
        try:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            self.close_connection = True
            logger.debug("http.client_disconnected", extra={"event_name": "http.client_disconnected"})

    def _handle_websocket(self, protocol=None, token=None):
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
        self.close_connection = False
        def authorized():
            identity = OperatorAuth(self.repo.db).identity(token)
            return identity is not None and "stream" in identity["permissions"]

        self.hub.register_ws(self, authorized)
        def read_exact(length):
            value = b''
            while len(value) < length:
                block = self.connection.recv(length-len(value))
                if not block: raise EOFError()
                value += block
            return value
        try:
            while not self.worker.stop_event.is_set():
                if self.close_connection or not authorized():
                    break
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
                    try:
                        self.hub._ws_queues[self].put_nowait(bytes([0x8a,length])+data)
                    except (KeyError, queue.Full):
                        break
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
            self._handle_websocket(auth_protocol, token)
            return

        if path == "/api/zta/session":
            identity = self._identity
            if not identity:
                self._send_json({"authenticated": False, "error": "Authentication required"}, 401)
                return
            self._send_json({"authenticated": True, "user": identity["username"], "role": identity["role"], "permissions": identity["permissions"]})
            return

        if path == "/api/zta/realtime-events":
            if not self._require_permission("stream"): return
            query = parse_qs(url.query)
            try:
                after = max(0, int(query.get("after_sequence", ["0"])[0]))
                limit = max(1, min(1000, int(query.get("limit", ["200"])[0])))
            except ValueError:
                self._send_json({"error": "Invalid realtime cursor"}, 400); return
            events = self.repo.get_realtime_events(after, limit)
            self._send_json({"events": events, "watermark": events[-1]["sequence_number"] if events else after})
            return

        if path == "/api/zta/users":
            if not self._require_permission("users:manage"): return
            self._send_json({"users": OperatorAuth(self.repo.db).list_users()})
            return

        if path.startswith("/api/zta/") or path.startswith("/api/v1/analytics/") or path == "/api/v1/agents/logs":
            permission = "audit:read" if path == "/api/zta/audit" or path.startswith("/api/zta/reports") else "read"
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
                automated_responses = conn.execute("""SELECT COUNT(*) FROM commands WHERE status='VERIFIED_SUCCESS'
                    OR (status='SUCCESS' AND verification_status='VERIFIED_SUCCESS')""").fetchone()[0]
                pending_responses = conn.execute("SELECT COUNT(*) FROM commands WHERE status IN ('PENDING', 'QUEUED', 'DELIVERED', 'RECEIVED', 'DISPATCHED', 'EXECUTING', 'VERIFYING')").fetchone()[0]
                failed_responses = conn.execute("SELECT COUNT(*) FROM commands WHERE status = 'FAILED'").fetchone()[0]
                containment = conn.execute("SELECT COUNT(*) FROM incidents WHERE status = 'CONTAINED'").fetchone()[0]

            online_agents = sum(1 for a in agents if a["status"] in ("ACTIVE", "SYNCING"))
            offline_agents = sum(1 for a in agents if a["status"] == "DISCONNECTED")
            isolated_agents = sum(1 for a in agents if a["status"] == "ISOLATED")
            degraded_agents = sum(1 for a in agents if a.get("connection_state") == "DEGRADED")

            active_risks = [a["risk_score"] for a in agents if a.get("risk_score") is not None and a["status"] in ("ACTIVE", "SYNCING")]
            fleet_risk_avg = round(sum(active_risks) / len(active_risks), 1) if active_risks else 0.0

            overview_data = {
                "system": "ZTA (Zero Trust Architecture)",
                "status": "HEALTHY" if all(s["status"] == "RUNNING" for s in self.repo.get_background_services()) else "DEGRADED",
                "total_endpoints": len(agents),
                "online_agents": online_agents,
                "offline_agents": offline_agents,
                "degraded_agents": degraded_agents,
                "isolated_agents": isolated_agents,
                "fleet_risk_average": fleet_risk_avg,
                "high_risk_endpoints": sum(1 for a in agents if (a.get("risk_score") or 0) >= 60),
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
                "verified_successful_responses": automated_responses,
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
            windows = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
            if range_param not in windows:
                self._send_json({"error": "range must be one of 1h, 24h, 7d, 30d"}, 400); return
            since = (datetime.now(timezone.utc) - timedelta(hours=windows[range_param])).isoformat()
            bucket = "substr(timestamp,1,13)" if windows[range_param] <= 24 else "substr(timestamp,1,10)"
            with self.repo.db.get_connection() as conn:
                events_rows = conn.execute(f"""SELECT {bucket} bucket,event_type,severity,COUNT(*) count
                    FROM zta_events WHERE timestamp>=? GROUP BY bucket,event_type,severity ORDER BY bucket""", (since,)).fetchall()
            points = [{"timestamp": r[0], "event_type": r[1], "severity": r[2], "count": r[3]} for r in events_rows]
            self._send_json({
                "range": range_param,
                "points": points,
                "timezone": "UTC", "since": since,
                "total": sum(point["count"] for point in points),
            })
        elif path in ("/api/zta/analytics/mitre-coverage", "/api/v1/analytics/mitre-coverage"):
            rules = self.repo.get_rules()
            tactics, techniques = {}, {}
            with self.repo.db.get_connection() as conn:
                observed = {row[0]: {"matches": row[1], "last_observed": row[2]}
                    for row in conn.execute("""SELECT mitre_technique_id,COUNT(*),MAX(matched_at) FROM rule_matches
                    WHERE mitre_technique_id IS NOT NULL GROUP BY mitre_technique_id""")}
                observed_tactics = {row[0]: row[1] for row in conn.execute("""SELECT mitre_tactic,COUNT(*)
                    FROM rule_matches WHERE mitre_tactic IS NOT NULL GROUP BY mitre_tactic""")}
            for r in rules:
                tac, tech = r.get("mitre_tactic"), r.get("mitre_technique_id")
                if not tac or not tech: continue
                tactics.setdefault(tac, {"configured_rules": 0, "enabled_rules": 0, "observed_matches": 0})
                tactics[tac]["configured_rules"] += 1
                tactics[tac]["enabled_rules"] += int(bool(r.get("enabled")))
                tactics[tac]["observed_matches"] = observed_tactics.get(tac, 0)
                item = techniques.setdefault(tech, {"technique_id": tech, "tactic": tac, "configured_rules": 0,
                    "enabled_rules": 0, "observed_matches": observed.get(tech, {}).get("matches", 0),
                    "last_observed": observed.get(tech, {}).get("last_observed"), "rules": []})
                item["configured_rules"] += 1; item["enabled_rules"] += int(bool(r.get("enabled")))
                item["rules"].append({"rule_id": r["rule_id"], "code": r["code"], "name": r["name"], "enabled": bool(r["enabled"])})
            self._send_json({
                "tactics": tactics,
                "techniques": list(techniques.values()),
                "total_rules": len(rules),
                "observed_techniques": sum(1 for item in techniques.values() if item["observed_matches"]),
                "reference": "Mappings stored on local detection rules; unknown mappings are omitted",
            })
        elif path == "/api/zta/threat-intelligence":
            self._send_json({"sources": [], "indicators": [], "configured": False,
                             "message": "No threat-intelligence feed is configured."})
        elif path == "/api/zta/settings":
            self._send_json({"settings": {
                "event_retry_max_attempts": int(os.environ.get("ZTA_EVENT_MAX_ATTEMPTS", "5")),
                "outbox_retention": int(os.environ.get("ZTA_OUTBOX_RETENTION", "10000")),
                "websocket_client_queue_size": int(os.environ.get("ZTA_WS_CLIENT_QUEUE_SIZE", "256")),
                "risk_decay_per_minute": float(os.environ.get("ZTA_RISK_DECAY_PER_MINUTE", "1")),
            }, "read_only": True})
        elif path == "/api/zta/reports/security-summary":
            query = parse_qs(url.query); export_format = query.get("format", ["json"])[0]
            if export_format not in ("json", "csv"):
                self._send_json({"error": "format must be json or csv"}, 400); return
            agents = self.repo.get_agents()
            with self.repo.db.get_connection() as conn:
                rows = conn.execute("""SELECT severity,status,COUNT(*) count FROM incidents
                    GROUP BY severity,status ORDER BY severity,status""").fetchall()
                commands = conn.execute("SELECT status,COUNT(*) count FROM commands GROUP BY status ORDER BY status").fetchall()
            report = {"generated_at": datetime.now(timezone.utc).isoformat(), "timezone": "UTC",
                "endpoints": {"total": len(agents), "online": sum(a["connection_state"] in ("ONLINE", "SYNCING") for a in agents),
                              "degraded": sum(a["connection_state"] == "DEGRADED" for a in agents),
                              "offline": sum(a["connection_state"] == "OFFLINE" for a in agents)},
                "alerts": [{"severity": r[0], "status": r[1], "count": r[2]} for r in rows],
                "responses": [{"status": r[0], "count": r[1]} for r in commands]}
            if export_format == "json": self._send_json({"report": report}); return
            output = io.StringIO(); writer = csv.writer(output, lineterminator="\n")
            writer.writerow(["section", "dimension", "value"])
            for key, value in report["endpoints"].items(): writer.writerow(["endpoints", key, value])
            for row in report["alerts"]: writer.writerow(["alerts", f'{row["severity"]}:{row["status"]}', row["count"]])
            for row in report["responses"]: writer.writerow(["responses", row["status"], row["count"]])
            self._send_download(output.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8", "zta-security-summary.csv")
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
        elif path == "/api/zta/listening-ports":
            agent_id = parse_qs(url.query).get("agent_id", [None])[0]
            self._send_json({"listening_ports": self.repo.get_listening_ports(agent_id)})
        elif path == "/api/zta/processes":
            agent_id = parse_qs(url.query).get("agent_id", [None])[0]
            self._send_json({"processes": self.repo.get_process_inventory(agent_id)})
        elif path == "/api/zta/sessions":
            agent_id = parse_qs(url.query).get("agent_id", [None])[0]
            self._send_json({"sessions": self.repo.get_sessions(agent_id)})
        elif path == "/api/zta/scripts":
            from zta.agent.execution.validators import ALLOWED_SCRIPT_IDS
            self._send_json({"scripts": sorted(ALLOWED_SCRIPT_IDS)})
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
            query = parse_qs(url.query)
            try: limit = max(1, min(500, int(query.get("limit", ["100"])[0])))
            except ValueError: self._send_json({"error": "Invalid audit limit"}, 400); return
            self._send_json({"audit_logs": self.repo.get_audit_logs(
                limit=limit, event_type=query.get("event_type", [None])[0],
                correlation_id=query.get("correlation_id", [None])[0])})
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
            if path != "/api/v1/telemetry/bulk" and not isinstance(payload, dict):
                raise ValueError("Expected a JSON object")

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

            if path == "/api/zta/auth/password":
                if not self._require_permission("read"): return
                identity = self._identity
                if identity.get("legacy"):
                    self._send_json({"error": "Password changes require a named operator account"}, 400)
                    return
                result = OperatorAuth(self.repo.db).change_password(
                    identity["user_id"], payload.get("current_password"),
                    payload.get("new_password"), self._bearer_token,
                )
                self.repo.save_audit("PASSWORD_CHANGED", f"Operator {identity['username']} changed password", user=identity["username"])
                self._send_json(result)
                return

            if path == "/api/zta/users":
                if not self._require_permission("users:manage"): return
                user = OperatorAuth(self.repo.db).create_user(payload, self._actor)
                self.repo.save_audit("USER_CREATED", f"Operator {user['username']} created with role {user['role']}", user=self._actor)
                self._send_json({"user": user}, 201)
                return

            if path.startswith("/api/zta/"):
                if path.startswith(("/api/zta/actions", "/api/zta/commands", "/api/zta/scripts/execute")) or (path.startswith("/api/zta/events/") and path.endswith("/retry")):
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
                try:
                    secret = self._authenticate_agent(payload["agent_id"])
                except AgentAuthenticationError as exc:
                    self._send_json({"error": str(exc)}, 401)
                    return
                if payload.get("connection_state", "CONNECTING") not in ("STARTING", "CONNECTING", "ONLINE", "RECONNECTING", "SYNCING", "DEGRADED"):
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
                ports = payload.get("listening_ports", [])
                if not isinstance(ports, list) or any(not isinstance(port, dict) for port in ports):
                    raise ValueError("listening_ports must be a list of objects")
                if self._inventory_changed(payload["agent_id"], "ports", ports):
                    self.repo.save_listening_ports(payload["agent_id"], ports)
                processes = payload.get("process_inventory", [])
                if not isinstance(processes, list) or any(not isinstance(process, dict) for process in processes):
                    raise ValueError("process_inventory must be a list of objects")
                if self._inventory_changed(payload["agent_id"], "processes", processes):
                    self.repo.save_process_inventory(payload["agent_id"], processes)
                sessions = payload.get("sessions", [])
                if not isinstance(sessions, list) or any(not isinstance(session, dict) for session in sessions):
                    raise ValueError("sessions must be a list of objects")
                if self._inventory_changed(payload["agent_id"], "sessions", sessions):
                    self.repo.save_sessions(payload["agent_id"], sessions)
                self.repo.update_service_heartbeat("Heartbeat Monitor", activity=True)
                with self.repo.db.get_connection() as conn:
                    conn.execute("UPDATE agents SET agent_version=?,collector_error=? WHERE id=?", (payload.get("agent_version"), payload.get("collector_error"), payload["agent_id"]))
                reported_state = payload.get("connection_state", "CONNECTING")
                stored = next((a for a in self.repo.get_agents() if a["id"] == payload["agent_id"]), None)
                authoritative_state = stored["connection_state"] if stored else "ONLINE"
                status_changed = (not before or before["connection_state"] != authoritative_state
                                  or before.get("ip") != payload.get("ip")
                                  or before.get("reported_connection_state") != reported_state)
                if status_changed:
                    self.repo.save_audit("AGENT_RECONNECTED" if before else "AGENT_ONLINE", authoritative_state, payload["agent_id"],
                                         details={"reported_state": reported_state, "manager_received_time": datetime.now(timezone.utc).isoformat()})
                    event_state = "reconnecting" if reported_state in ("STARTING", "CONNECTING", "RECONNECTING") else authoritative_state.lower()
                    self.hub.broadcast("agent." + event_state, {"agent_id": payload["agent_id"], "connection_state": authoritative_state,
                                       "reported_connection_state": reported_state, "ip": payload.get("ip"), "manager_observed_ip": client_ip})
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
                rules, policies = self.repo.get_rules(), self.repo.get_policies()
                # Version only definitions, excluding counters and evaluation history.
                volatile = {'last_evaluated','last_matched','last_triggered','total_matches','total_triggers','recent_matches','linked_policies','recent_evaluations'}
                definition_fields = {'rule_id','policy_id','code','name','category','severity','mitre_tactic','mitre_technique_id','risk_delta','condition','condition_json','response_action','logic_type','enabled','allow_offline','min_risk','max_risk','risk_threshold','mode','action','priority','created_at'}
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
                    changed = conn.execute("""UPDATE zta_events SET processing_state='PENDING',processing_error=NULL,
                        processing_next_attempt_at=NULL,processing_started_at=NULL,processing_worker_id=NULL,
                        processing_attempt_count=0
                        WHERE event_id=? AND processing_state='FAILED'""", (event_id,)).rowcount
                if not changed: raise ValueError('Only failed events can be retried')
                self.repo.save_audit('EVENT_RETRY_REQUESTED','Retry failed background event', user=self._actor, details={'event_id':event_id})
                self.worker.wake.set()
                self._send_json({'status':'PENDING','event_id':event_id})

            elif path == "/api/zta/actions/execute":
                if not self._require_permission("response:write"): return
                if not isinstance(payload, dict):
                    raise ValueError("Expected a JSON object")
                action = payload.get("action")
                if action not in ("KILL_PROCESS", "ISOLATE_ENDPOINT", "UNISOLATE_ENDPOINT", "LOGOFF_USER", "LOGOUT_USER",
                                  "LOCK_LOCAL_ACCOUNT", "UNLOCK_LOCAL_ACCOUNT", "LOCK_WORKSTATION", "QUARANTINE_FILE"):
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
                if action not in ("KILL_PROCESS", "ISOLATE_ENDPOINT", "UNISOLATE_ENDPOINT", "LOGOFF_USER", "LOGOUT_USER",
                                  "LOCK_LOCAL_ACCOUNT", "UNLOCK_LOCAL_ACCOUNT", "LOCK_WORKSTATION", "QUARANTINE_FILE", "DEMO_SCRIPT"):
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
                if preview.status not in ("PREVIEW", "SUCCESS"):
                    raise ValueError(preview.error or 'Command validation failed')
                command_id = f"cmd-manual-{uuid4().hex[:8]}"
                correlation_id = str(payload.get('correlation_id') or command_id)
                now_iso = datetime.now(timezone.utc).isoformat()
                self.repo.save_command({
                    "command_id": command_id,
                    "agent_id": agent_id,
                    "action_type": action,
                    "params": params,
                    "status": "QUEUED",
                "executor": "WINDOWS_POWERSHELL" if action != "DEMO_SCRIPT" else "ALLOWLISTED_SCRIPT",
                    "execution_source": "MANAGER",
                    "created_at": now_iso,
                    "expires_at": (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat(),
                    "correlation_id": correlation_id,
                })
                self.repo.save_audit(
                    event_type="COMMAND_CREATED",
                    action=f"Manual SOC command {action} dispatched to agent {agent_id}",
                    agent_id=agent_id,
                    user=self._actor,
                    details={"command_id": command_id, "action": action, "params": params, "correlation_id": correlation_id},
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

            elif path == "/api/zta/scripts/execute":
                if not self._require_permission("response:write"): return
                from zta.agent.execution.validators import ScriptValidationError, validate_script_request
                agent_id = str(payload.get("agent_id") or "")
                script_id = str(payload.get("script_id") or "")
                parameters = payload.get("parameters", {})
                if not agent_id:
                    raise ValueError("agent_id is required")
                try:
                    validate_script_request(script_id, parameters)
                except ScriptValidationError as exc:
                    raise ValueError(str(exc)) from exc
                if not self._agent_secret(agent_id):
                    raise ValueError("No credential configured for target agent")
                correlation_id = str(parameters.get("correlation_id") or f"manual-{uuid4().hex}")
                parameters = {**parameters, "correlation_id": correlation_id}
                command_id = f"cmd-manual-{uuid4().hex}"
                now_iso = datetime.now(timezone.utc).isoformat()
                self.repo.save_command({
                    "command_id": command_id, "agent_id": agent_id, "action_type": "DEMO_SCRIPT",
                    "params": {"script_id": script_id, **parameters}, "status": "QUEUED",
                    "executor": "ALLOWLISTED_SCRIPT", "execution_source": "MANAGER",
                    "created_at": now_iso, "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                })
                self.repo.save_audit("MANUAL_SCRIPT_QUEUED", f"Allowlisted script {script_id} queued",
                                     agent_id=agent_id, user=self._actor,
                                     details={"command_id": command_id, "script_id": script_id, "correlation_id": correlation_id})
                self.hub.broadcast("command.created", {"command_id": command_id, "agent_id": agent_id, "action": "DEMO_SCRIPT"})
                self._send_json({"status": "QUEUED", "command_id": command_id, "correlation_id": correlation_id}, 201)

            elif path == "/api/zta/admin/database-clear/request":
                if self._role != "ADMIN":
                    self._send_json({"error": "Admin role required"}, 403)
                    return
                token = secrets.token_urlsafe(32)
                digest = hashlib.sha256(token.encode()).hexdigest()
                expires_at = datetime.now(timezone.utc) + timedelta(minutes=2)
                with self._db_clear_lock:
                    self._db_clear_tokens[digest] = {"actor": self._actor, "expires_at": expires_at, "used": False}
                self._send_json({"confirmation_token": token, "expires_at": expires_at.isoformat()})

            elif path == "/api/zta/admin/database-clear":
                if self._role != "ADMIN":
                    self._send_json({"error": "Admin role required"}, 403)
                    return
                supplied = str(payload.get("confirmation_token") or "")
                digest = hashlib.sha256(supplied.encode()).hexdigest()
                with self._db_clear_lock:
                    record = self._db_clear_tokens.get(digest)
                    valid = bool(record and not record["used"] and record["actor"] == self._actor
                                 and record["expires_at"] > datetime.now(timezone.utc))
                    if valid:
                        record["used"] = True
                if not valid:
                    self._send_json({"error": "Invalid, expired, or already-used confirmation token"}, 400)
                    return
                tables = ("rule_matches", "rule_evaluations", "policy_evaluations", "command_results", "commands", "risk_history",
                          "incidents", "zta_events", "agent_logs", "sync_receipts", "sync_history",
                          "agent_listening_ports", "agent_processes", "agent_sessions", "agents", "audit_log")
                with self.repo.db.transaction() as conn:
                    counts = {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables}
                    for table in tables:
                        conn.execute(f"DELETE FROM {table}")
                self.repo.save_audit("DATABASE_CLEARED", "Operational database records cleared", user=self._actor,
                                     details={"deleted_records": counts})
                self.hub.broadcast("database.cleared", {"actor": self._actor})
                self._send_json({"status": "CLEARED", "deleted_records": counts})

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
                try:
                    candidate = dict(payload.get("policy", payload))
                    candidate.setdefault("code", "POL-VALIDATE")
                    candidate.setdefault("name", "Policy validation")
                    candidate.setdefault("severity", "HIGH")
                    candidate.setdefault("mode", "ALERT_ONLY")
                    candidate.setdefault("action", "MONITOR")
                    candidate.setdefault("min_risk", 0)
                    candidate.setdefault("max_risk", 100)
                    candidate.setdefault("risk_threshold", 85)
                    candidate.setdefault("priority", 1000)
                    PolicyValidator().validate(candidate)
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
        except AgentAuthenticationError as exc:
            self._send_json({"error": str(exc)}, 401)
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
        hub = WebSocketHub(repo)
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
