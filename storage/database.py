"""ZTA Persistence Storage & Database Models using SQLite."""

import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from zta.engine.events.conditions import RuleValidator
from zta.engine.events.models import ZTAAgent, ZTAEvent, ZTAMitre, ZTAProcess, ZTAUser, ZTAWazuhRule
from zta.engine.policy.engine import PolicyValidator
from zta.engine.risk.engine import RiskEvent
from zta.engine.trust.engine import TrustState


class RuleDependencyError(ValueError):
    """Raised when a rule is still referenced by an active definition."""


class _TransactionView:
    def __init__(self, conn): self.conn = conn
    def __getattr__(self, name): return getattr(self.conn, name)
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def commit(self): pass


class ZTADatabase:
    """Manages SQLite database connections and table schemas for ZTA persistence."""

    def __init__(self, db_path: str = "zta_storage.db", seed_defaults: bool = True):
        self.db_path = str(Path(db_path).expanduser().resolve())
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.seed_defaults = seed_defaults
        self._local = threading.local()
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Returns a connection to the SQLite database."""
        if getattr(self._local, "connection", None) is not None:
            return _TransactionView(self._local.connection)
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def transaction(self):
        """One atomic unit across existing repository methods and worker writes."""
        if getattr(self._local, "connection", None) is not None:
            yield self._local.connection
            return
        conn = self.get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._local.connection = conn
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            self._local.connection = None
            conn.close()

    def _init_db(self):
        """Initializes ZTA database tables if they do not exist, and runs idempotent migrations."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Agents Table
            cursor.execute("""CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                ip TEXT,
                os TEXT,
                last_seen TEXT NOT NULL,
                connection_state TEXT DEFAULT 'ONLINE',
                sync_state TEXT DEFAULT 'IDLE',
                queue_depth INTEGER DEFAULT 0
            )""")

            # Add columns to agents if legacy table existed
            self._ensure_column(cursor, "agents", "connection_state", "TEXT DEFAULT 'ONLINE'")
            self._ensure_column(cursor, "agents", "sync_state", "TEXT DEFAULT 'IDLE'")
            self._ensure_column(cursor, "agents", "queue_depth", "INTEGER DEFAULT 0")

            # ZTA Events Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS zta_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    user_name TEXT,
                    process_name TEXT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    wazuh_rule_id INTEGER,
                    mitre_tactic TEXT,
                    mitre_technique_id TEXT,
                    raw_event_json TEXT NOT NULL,
                    execution_source TEXT DEFAULT 'AGENT_ONLINE',
                    synced_at TEXT
                )
            """)
            self._ensure_column(cursor, "zta_events", "execution_source", "TEXT DEFAULT 'AGENT_ONLINE'")
            self._ensure_column(cursor, "zta_events", "synced_at", "TEXT")

            # Rules Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    rule_id TEXT PRIMARY KEY,
                    code TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    mitre_tactic TEXT,
                    mitre_technique_id TEXT,
                    risk_delta INTEGER NOT NULL DEFAULT 10,
                    condition_json TEXT NOT NULL,
                    response_action TEXT DEFAULT 'ALERT',
                    logic_type TEXT DEFAULT 'CONDITION_TREE',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    allow_offline INTEGER NOT NULL DEFAULT 0,
                    last_evaluated TEXT,
                    last_matched TEXT,
                    total_matches INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """)

            # Rule Matches Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rule_matches (
                    match_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    rule_code TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    event_id TEXT,
                    severity TEXT NOT NULL,
                    mitre_tactic TEXT,
                    mitre_technique_id TEXT,
                    matched_conditions_json TEXT,
                    condition_result INTEGER NOT NULL DEFAULT 1,
                    risk_delta INTEGER NOT NULL DEFAULT 0,
                    matched_at TEXT NOT NULL,
                    alert_id TEXT,
                    policy_id TEXT,
                    execution_source TEXT DEFAULT 'AGENT_ONLINE'
                )
            """)

            # Policies Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    policy_id TEXT PRIMARY KEY,
                    code TEXT UNIQUE,
                    name TEXT NOT NULL,
                    category TEXT DEFAULT 'general',
                    severity TEXT DEFAULT 'HIGH',
                    rule_id TEXT,
                    risk_threshold INTEGER DEFAULT 85,
                    min_risk INTEGER NOT NULL DEFAULT 0,
                    max_risk INTEGER NOT NULL DEFAULT 100,
                    action TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'ENFORCE',
                    condition_json TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    allow_offline INTEGER NOT NULL DEFAULT 0,
                    last_evaluated TEXT,
                    last_triggered TEXT,
                    total_triggers INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT
                )
            """)
            self._ensure_column(cursor, "policies", "code", "TEXT")
            self._ensure_column(cursor, "policies", "category", "TEXT DEFAULT 'general'")
            self._ensure_column(cursor, "policies", "severity", "TEXT DEFAULT 'HIGH'")
            self._ensure_column(cursor, "policies", "rule_id", "TEXT")
            self._ensure_column(cursor, "policies", "risk_threshold", "INTEGER DEFAULT 85")
            self._ensure_column(cursor, "policies", "mode", "TEXT NOT NULL DEFAULT 'ENFORCE'")
            self._ensure_column(cursor, "policies", "condition_json", "TEXT")
            self._ensure_column(cursor, "policies", "allow_offline", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(cursor, "policies", "last_evaluated", "TEXT")
            self._ensure_column(cursor, "policies", "last_triggered", "TEXT")
            self._ensure_column(cursor, "policies", "total_triggers", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(cursor, "policies", "created_at", "TEXT")
            self._ensure_column(cursor, "policies", "priority", "INTEGER NOT NULL DEFAULT 1000")

            # Policy Evaluations Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS policy_evaluations (
                    eval_id TEXT PRIMARY KEY,
                    policy_id TEXT NOT NULL,
                    policy_code TEXT NOT NULL,
                    policy_name TEXT NOT NULL,
                    rule_id TEXT,
                    agent_id TEXT NOT NULL,
                    alert_id TEXT,
                    risk_score INTEGER NOT NULL,
                    trust_score INTEGER NOT NULL,
                    mode TEXT NOT NULL,
                    action TEXT NOT NULL,
                    evaluation_result TEXT NOT NULL,
                    reason TEXT,
                    status TEXT,
                    timestamp TEXT NOT NULL,
                    execution_source TEXT DEFAULT 'AGENT_ONLINE'
                )
            """)

            # Incidents / Alerts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    user_name TEXT,
                    severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    trust_score INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    trigger_reason TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    rule_id TEXT,
                    rule_code TEXT,
                    rule_name TEXT,
                    policy_id TEXT,
                    policy_name TEXT,
                    response_action TEXT,
                    response_status TEXT,
                    detection_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    execution_source TEXT DEFAULT 'AGENT_ONLINE'
                )
            """)
            self._ensure_column(cursor, "incidents", "rule_id", "TEXT")
            self._ensure_column(cursor, "incidents", "rule_code", "TEXT")
            self._ensure_column(cursor, "incidents", "rule_name", "TEXT")
            self._ensure_column(cursor, "incidents", "policy_id", "TEXT")
            self._ensure_column(cursor, "incidents", "policy_name", "TEXT")
            self._ensure_column(cursor, "incidents", "response_action", "TEXT")
            self._ensure_column(cursor, "incidents", "response_status", "TEXT")
            self._ensure_column(cursor, "incidents", "detection_json", "TEXT")
            self._ensure_column(cursor, "incidents", "execution_source", "TEXT DEFAULT 'AGENT_ONLINE'")

            # Commands Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS commands (
                    command_id TEXT PRIMARY KEY,
                    policy_id TEXT,
                    policy_code TEXT,
                    alert_id TEXT,
                    agent_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    params_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    executor TEXT DEFAULT 'WINDOWS_POWERSHELL',
                    output TEXT DEFAULT '',
                    error_code INTEGER,
                    error_message TEXT,
                    verification TEXT,
                    dry_run INTEGER NOT NULL DEFAULT 0,
                    execution_source TEXT DEFAULT 'MANAGER',
                    created_at TEXT NOT NULL,
                    dispatched_at TEXT,
                    completed_at TEXT,
                    expires_at TEXT
                )
            """)

            # Risk History Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS risk_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    previous_score INTEGER NOT NULL,
                    delta INTEGER NOT NULL,
                    new_score INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    finding_id TEXT
                )
            """)

            # Audit Log Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    agent_id TEXT,
                    user TEXT,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    execution_source TEXT DEFAULT 'MANAGER',
                    status TEXT NOT NULL DEFAULT 'SUCCESS',
                    timestamp TEXT NOT NULL
                )
            """)

            # Background Services Status Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS background_services (
                    service_name TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'RUNNING',
                    last_heartbeat TEXT NOT NULL,
                    last_activity TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}'
                )
            """)

            # Sync History Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sync_history (
                    sync_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    events_count INTEGER NOT NULL DEFAULT 0,
                    alerts_count INTEGER NOT NULL DEFAULT 0,
                    rule_matches_count INTEGER NOT NULL DEFAULT 0,
                    policy_evals_count INTEGER NOT NULL DEFAULT 0,
                    responses_count INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'COMPLETED',
                    synced_at TEXT NOT NULL
                )
            """)

            # Additive migration 20260910: durable processing and evidence.
            cursor.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)")
            cursor.execute("""CREATE TABLE IF NOT EXISTS operator_users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('ADMIN','SOC_ANALYST','AUDITOR','VIEWER')),
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                last_login_at TEXT
            )""")
            cursor.execute("""CREATE TABLE IF NOT EXISTS operator_sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES operator_users(user_id) ON DELETE CASCADE
            )""")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_operator_sessions_expires ON operator_sessions(expires_at)")
            for table, column, definition in [
                ("zta_events", "normalized_json", "TEXT"),
                ("zta_events", "processing_state", "TEXT DEFAULT 'LEGACY'"),
                ("zta_events", "processing_error", "TEXT"),
                ("policy_evaluations", "condition_trace_json", "TEXT"),
                ("commands", "executing_at", "TEXT"),
                ("commands", "synced_at", "TEXT"),
                ("agents", "agent_version", "TEXT"),
                ("agents", "collector_error", "TEXT"),
                ("agents", "active_interface", "TEXT"),
                ("agents", "interface_name", "TEXT"),
                ("agents", "local_ipv4", "TEXT"),
                ("agents", "local_ipv6", "TEXT"),
                ("agents", "manager_observed_ip", "TEXT"),
                ("agents", "interfaces_json", "TEXT"),
                ("rules", "is_demo", "INTEGER DEFAULT 0"),
                ("rules", "current_version", "INTEGER NOT NULL DEFAULT 1"),
                ("rule_matches", "is_demo", "INTEGER DEFAULT 0"),
                ("rule_matches", "rule_version", "INTEGER"),
                ("incidents", "is_demo", "INTEGER DEFAULT 0"),
                ("incidents", "rule_version", "INTEGER"),
            ]:
                self._ensure_column(cursor, table, column, definition)
            cursor.execute("""CREATE TABLE IF NOT EXISTS rule_versions (
                rule_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                definition_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                change_type TEXT NOT NULL,
                PRIMARY KEY(rule_id, version)
            )""")
            cursor.execute("CREATE TABLE IF NOT EXISTS rule_evaluations (evaluation_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, rule_id TEXT NOT NULL, agent_id TEXT NOT NULL, result INTEGER NOT NULL, trace_json TEXT NOT NULL, timestamp TEXT NOT NULL, execution_source TEXT NOT NULL)")
            cursor.execute("CREATE TABLE IF NOT EXISTS sync_receipts (agent_id TEXT NOT NULL, batch_id TEXT NOT NULL, payload_hash TEXT NOT NULL, response_json TEXT NOT NULL, PRIMARY KEY(agent_id,batch_id))")
            cursor.execute("""CREATE TABLE IF NOT EXISTS agent_logs (
                log_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                hostname TEXT,
                level TEXT NOT NULL,
                component TEXT,
                event_type TEXT,
                message TEXT NOT NULL,
                correlation_id TEXT,
                metadata_json TEXT,
                execution_source TEXT DEFAULT 'AGENT_ONLINE',
                synced_at TEXT
            )""")
            cursor.execute("INSERT OR IGNORE INTO schema_migrations VALUES ('20260910-background-evidence', ?)", (datetime.now(timezone.utc).isoformat(),))
            cursor.execute("INSERT OR IGNORE INTO schema_migrations VALUES ('20260913-demo-and-logs', ?)", (datetime.now(timezone.utc).isoformat(),))
            cursor.execute("INSERT OR IGNORE INTO schema_migrations VALUES ('20260914-operator-rbac', ?)", (datetime.now(timezone.utc).isoformat(),))
            # Seed default rules and policies if empty
            if self.seed_defaults and not cursor.execute("SELECT 1 FROM schema_migrations WHERE version='content-bootstrap'").fetchone():
                self._seed_default_data(conn)
                cursor.execute("INSERT INTO schema_migrations VALUES ('content-bootstrap',?)", (datetime.now(timezone.utc).isoformat(),))
            for row in cursor.execute("SELECT * FROM rules").fetchall():
                definition = ZTARepository.rule_definition(dict(row))
                cursor.execute(
                    "INSERT OR IGNORE INTO rule_versions VALUES (?, 1, ?, ?, 'migration', 'BASELINE')",
                    (row["rule_id"], json.dumps(definition), row["created_at"]),
                )
            cursor.execute("INSERT OR IGNORE INTO schema_migrations VALUES ('20260914-rule-version-history', ?)", (datetime.now(timezone.utc).isoformat(),))
            if not cursor.execute("SELECT 1 FROM schema_migrations WHERE version='20260914-policy-priority'").fetchone():
                existing = cursor.execute(
                    "SELECT policy_id FROM policies ORDER BY CASE WHEN rule_id IS NOT NULL AND rule_id<>'' THEN 0 ELSE 1 END, min_risk ASC, code ASC, policy_id ASC"
                ).fetchall()
                for position, policy in enumerate(existing, start=1):
                    cursor.execute("UPDATE policies SET priority=? WHERE policy_id=?", (position * 10, policy["policy_id"]))
                cursor.execute("INSERT INTO schema_migrations VALUES ('20260914-policy-priority', ?)", (datetime.now(timezone.utc).isoformat(),))
            conn.commit()

    def _ensure_column(self, cursor: sqlite3.Cursor, table_name: str, column_name: str, col_def: str):
        """Adds a column to an existing SQLite table if it does not already exist."""
        cursor.execute(f"PRAGMA table_info({table_name})")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if column_name not in existing_cols:
            try:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {col_def}")
            except sqlite3.OperationalError:
                raise

    def _seed_default_data(self, conn: sqlite3.Connection):
        """Seeds initial blueprint detection rules and adaptive policies if not present."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()

        # Check existing rules count
        cursor.execute("SELECT COUNT(*) FROM rules")
        if cursor.fetchone()[0] == 0:
            default_rules = [
                ("RULE-0001", "RULE-0001", "Unsigned executable dropped in %TEMP%", "Execution", "HIGH", "Execution", "T1059", 30,
                 json.dumps({"all": [{"field": "collector_type", "op": "in", "value": ["process", "file", "PROCESS_CREATION"]}, {"any": [{"field": "data.process_path", "op": "contains_icase", "value": "temp"}, {"field": "process.path", "op": "contains_icase", "value": "temp"}]}]}),
                 "KILL_PROCESS", "CONDITION_TREE", 1, 0, now, 0),
                ("RULE-0002", "RULE-0002", "PowerShell with encoded command", "Execution", "HIGH", "Execution", "T1059.001", 25,
                 json.dumps({"all": [{"any": [{"field": "process.name", "op": "contains_icase", "value": "powershell"}, {"field": "data.process_name", "op": "contains_icase", "value": "powershell"}]}, {"any": [{"field": "process.command_line", "op": "contains_icase", "value": "-enc"}, {"field": "process.command_line", "op": "contains_icase", "value": "-encodedcommand"}, {"field": "data.command_line", "op": "contains_icase", "value": "-enc"}, {"field": "data.command_line", "op": "contains_icase", "value": "-encodedcommand"}]}]}),
                 "KILL_PROCESS", "CONDITION_TREE", 1, 1, now, 0),
                ("RULE-0003", "RULE-0003", "New scheduled task created by non-admin", "Persistence", "MEDIUM", "Persistence", "T1053.005", 20,
                 json.dumps({"all": [{"any": [{"field": "event_type", "op": "eq", "value": "SCHEDULED_TASK"}, {"field": "process.name", "op": "contains_icase", "value": "schtasks"}]}]}),
                 "ALERT", "CONDITION_TREE", 1, 0, now, 0),
                ("RULE-0004", "RULE-0004", "New service installed pointing to unusual path", "Persistence", "HIGH", "Persistence", "T1543.003", 45,
                 json.dumps({"all": [{"any": [{"field": "event_type", "op": "eq", "value": "SERVICE_INSTALL"}, {"field": "process.name", "op": "contains_icase", "value": "sc.exe"}]}]}),
                 "ALERT", "CONDITION_TREE", 1, 0, now, 0),
                ("RULE-0005", "RULE-0005", "Registry Run key modified", "Persistence", "MEDIUM", "Persistence", "T1547.001", 20,
                 json.dumps({"all": [{"any": [{"field": "event_type", "op": "eq", "value": "REGISTRY_MODIFICATION"}, {"field": "data.registry_path", "op": "contains_icase", "value": "CurrentVersion\\Run"}]}]}),
                 "ALERT", "CONDITION_TREE", 1, 0, now, 0),
                ("RULE-0006", "RULE-0006", "Process token elevation without UAC prompt", "Privilege Escalation", "HIGH", "Privilege Escalation", "T1134", 30,
                 json.dumps({"all": [{"field": "event_type", "op": "eq", "value": "TOKEN_ELEVATION"}]}),
                 "ALERT", "CONDITION_TREE", 1, 0, now, 0),
                ("RULE-0007", "RULE-0007", "Security tool / AV process terminated", "Defense Evasion", "CRITICAL", "Defense Evasion", "T1562.001", 35,
                 json.dumps({"all": [{"field": "event_type", "op": "in", "value": ["PROCESS_TERMINATION", "PROCESS_TERMINATION_ATTEMPT"]}, {"any": [{"field": "process.name", "op": "contains_icase", "value": "MsMpEng.exe"}, {"field": "process.name", "op": "contains_icase", "value": "windefend"}, {"field": "process.name", "op": "contains_icase", "value": "zta-agent"}, {"field": "data.process_name", "op": "contains_icase", "value": "MsMpEng.exe"}]}]}),
                 "LOGOUT_USER", "CONDITION_TREE", 1, 1, now, 0),
                ("RULE-0008", "RULE-0008", "Clearing of Windows event logs", "Defense Evasion", "HIGH", "Defense Evasion", "T1070.001", 30,
                 json.dumps({"all": [{"any": [{"field": "event_type", "op": "eq", "value": "EVENT_LOG_CLEARED"}, {"field": "process.command_line", "op": "contains_icase", "value": "wevtutil cl"}]}]}),
                 "ALERT", "CONDITION_TREE", 1, 0, now, 0),
                ("RULE-0009", "RULE-0009", "LSASS memory access by non-system process", "Credential Access", "CRITICAL", "Credential Access", "T1003.001", 40,
                 json.dumps({"all": [{"any": [{"field": "event_type", "op": "eq", "value": "LSASS_ACCESS"}, {"field": "data.target_process", "op": "contains_icase", "value": "lsass.exe"}]}]}),
                 "LOGOUT_USER", "CONDITION_TREE", 1, 0, now, 0),
                ("RULE-0010", "RULE-0010", "Multiple failed logins followed by success", "Credential Access", "HIGH", "Credential Access", "T1110", 30,
                 json.dumps({"all": [{"field": "event_type", "op": "in", "value": ["AUTHENTICATION", "AUTH_SEQUENCE"]}, {"field": "severity", "op": "in", "value": ["HIGH", "CRITICAL"]}]}),
                 "LOGOUT_USER", "CONDITION_TREE", 1, 1, now, 0),
                ("RULE-0011", "RULE-0011", "Discovery command chain executed", "Discovery", "LOW", "Discovery", "T1087", 15,
                 json.dumps({"all": [{"field": "process.name", "op": "in", "value": ["whoami.exe", "net.exe", "systeminfo.exe"]}]}),
                 "MONITOR", "CONDITION_TREE", 1, 0, now, 0),
                ("RULE-0012", "RULE-0012", "SMB connection to unusual internal host", "Lateral Movement", "MEDIUM", "Lateral Movement", "T1021.002", 25,
                 json.dumps({"all": [{"field": "destination_port", "op": "eq", "value": 445}]}),
                 "ALERT", "CONDITION_TREE", 1, 0, now, 0),
                ("RULE-0013", "RULE-0013", "Large USB file copy in short window", "Collection", "MEDIUM", "Collection", "T1052.001", 20,
                 json.dumps({"all": [{"field": "event_type", "op": "eq", "value": "USB_COPY"}]}),
                 "ALERT", "CONDITION_TREE", 1, 0, now, 0),
                ("RULE-0014", "RULE-0014", "DNS query volume spike to single domain", "Exfiltration", "HIGH", "Exfiltration", "T1071.004", 30,
                 json.dumps({"all": [{"field": "event_type", "op": "eq", "value": "DNS_SPIKE"}]}),
                 "ALERT", "CONDITION_TREE", 1, 0, now, 0),
                ("RULE-0015", "RULE-0015", "Outbound connection to known-bad IOC", "Command and Control", "CRITICAL", "Command and Control", "T1071.001", 35,
                 json.dumps({"all": [{"any": [{"field": "event_type", "op": "eq", "value": "IOC_MATCH"}, {"field": "destination_ip", "op": "eq", "value": "198.51.100.45"}]}]}),
                 "ISOLATE_ENDPOINT", "CONDITION_TREE", 1, 0, now, 0),
            ]
            cursor.executemany("""
                INSERT OR IGNORE INTO rules (
                    rule_id, code, name, category, severity, mitre_tactic, mitre_technique_id,
                    risk_delta, condition_json, response_action, logic_type, enabled, allow_offline, created_at, is_demo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, default_rules)

        # Seed demo rules if not present
        demo_rules = [
            ("DEMO-TEST-001", "DEMO-TEST-001", "Controlled Demo Process Trigger", "DEMO", "LOW", "Execution", "T1059", 5,
             json.dumps({"any": [{"field": "process.command_line", "op": "contains", "value": "DEMO-TEST-001"}, {"field": "data.command_line", "op": "contains", "value": "DEMO-TEST-001"}, {"field": "data.process_name", "op": "contains_icase", "value": "DEMO-TEST-001"}]}),
             "ALERT", "CONDITION_TREE", 0, 1, now, 1),
            ("DEMO-TEST-002", "DEMO-TEST-002", "Controlled Demo File Activity", "DEMO", "LOW", "Collection", "T1005", 5,
             json.dumps({"any": [{"field": "data.target_path", "op": "contains_icase", "value": "edr-demo"}, {"field": "data.file_path", "op": "contains_icase", "value": "edr-demo"}, {"field": "process.command_line", "op": "contains_icase", "value": "edr-demo"}, {"field": "data.command_line", "op": "contains_icase", "value": "edr-demo"}]}),
             "ALERT", "CONDITION_TREE", 0, 1, now, 1),
            ("DEMO-TEST-003", "DEMO-TEST-003", "Controlled Demo Network Connection", "DEMO", "LOW", "Command and Control", "T1071", 5,
             json.dumps({"any": [{"field": "destination_port", "op": "eq", "value": 44444}, {"field": "data.destination_port", "op": "eq", "value": 44444}]}),
             "ALERT", "CONDITION_TREE", 0, 1, now, 1),
            ("DEMO-TEST-004", "DEMO-TEST-004", "Controlled Demo Listening Port", "DEMO", "LOW", "Persistence", "T1571", 5,
             json.dumps({"any": [{"field": "destination_port", "op": "eq", "value": 44445}, {"field": "data.destination_port", "op": "eq", "value": 44445}, {"field": "data.local_port", "op": "eq", "value": 44445}]}),
             "ALERT", "CONDITION_TREE", 0, 1, now, 1),
        ]
        cursor.executemany("""
            INSERT OR IGNORE INTO rules (
                rule_id, code, name, category, severity, mitre_tactic, mitre_technique_id,
                risk_delta, condition_json, response_action, logic_type, enabled, allow_offline, created_at, is_demo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, demo_rules)

        # Check existing policies count
        cursor.execute("SELECT COUNT(*) FROM policies")
        if cursor.fetchone()[0] == 0:
            default_policies = [
                ("POL-001", "POL-001", "Baseline Monitoring", "monitoring", "LOW", None, 0, 0, 29, "MONITOR", "ALERT_ONLY", None, 1, 0, now),
                ("POL-002", "POL-002", "Medium Risk Alert", "alerting", "MEDIUM", None, 30, 30, 59, "ALERT", "ALERT_ONLY", None, 1, 0, now),
                ("POL-003", "POL-003", "High Risk SOC Escalation", "escalation", "HIGH", None, 60, 60, 84, "NOTIFY_SOC", "ALERT_ONLY", None, 1, 0, now),
                ("POL-004", "POL-004", "Critical Risk Containment", "containment", "CRITICAL", None, 85, 85, 100, "ISOLATE_ENDPOINT", "ENFORCE", None, 1, 0, now),
                ("POL-LOGOUT-001", "POL-LOGOUT-001", "Critical Login & Session Protection", "protection", "CRITICAL", "RULE-0004", 40, 40, 100, "LOGOUT_USER", "ENFORCE",
                 json.dumps({"all": [{"field": "risk_score", "op": "gte", "value": 40}]}), 1, 1, now),
            ]
            cursor.executemany("""
                INSERT OR IGNORE INTO policies (
                    policy_id, code, name, category, severity, rule_id, risk_threshold, min_risk,
                    max_risk, action, mode, condition_json, enabled, allow_offline, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, default_policies)

        # Ensure background services tracking rows
        services = ["Telemetry Processor", "Rule Engine", "Policy Engine", "Command Dispatcher", "WebSocket Hub", "Heartbeat Monitor", "Offline Sync Processor"]
        for s in services:
            cursor.execute("""
                INSERT OR IGNORE INTO background_services (service_name, status, last_heartbeat, last_activity, details_json)
                VALUES (?, 'STOPPED', ?, ?, '{}')
            """, (s, now, now))


class ZTARepository:
    """Repository providing CRUD operations for ZTA entities."""

    RULE_DEFINITION_FIELDS = (
        "rule_id", "code", "name", "category", "severity", "mitre_tactic",
        "mitre_technique_id", "risk_delta", "condition_json", "response_action",
        "logic_type", "enabled", "allow_offline", "created_at",
    )

    @classmethod
    def rule_definition(cls, rule: Dict[str, Any]) -> Dict[str, Any]:
        return {field: rule.get(field) for field in cls.RULE_DEFINITION_FIELDS}

    def _save_rule_version(self, conn, rule: Dict[str, Any], version: int, actor: str, change_type: str):
        conn.execute(
            "INSERT INTO rule_versions VALUES (?, ?, ?, ?, ?, ?)",
            (rule["rule_id"], version, json.dumps(self.rule_definition(rule)),
             datetime.now(timezone.utc).isoformat(), actor, change_type),
        )

    def get_rule_versions(self, rule_id: str) -> List[Dict[str, Any]]:
        rule = self.get_rule_by_id(rule_id)
        if not rule:
            return []
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM rule_versions WHERE rule_id=? ORDER BY version DESC",
                (rule["rule_id"],),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["definition"] = json.loads(item.pop("definition_json"))
            result.append(item)
        return result
    def __init__(self, db: ZTADatabase):
        self.db = db

    # --- Events ---
    def save_event(self, event: ZTAEvent, execution_source: str = "AGENT_ONLINE", synced_at: Optional[str] = None):
        """Persists a ZTAEvent to SQLite idempotently."""
        with self.db.get_connection() as conn:
            if not getattr(self.db._local, "connection", None):
                conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT raw_event_json, agent_id, normalized_json FROM zta_events WHERE event_id=?", (event.event_id,)).fetchone()
            if existing and (json.loads(existing[0]) != event.raw_event or existing[1] != event.agent.id or (not event.raw_event and existing[2] and json.loads(existing[2]) != json.loads(json.dumps(asdict(event), default=str)))):
                raise ValueError("Event ID already belongs to different telemetry")
            conn.execute(
                """
                INSERT OR IGNORE INTO zta_events (
                    event_id, timestamp, agent_id, agent_name, user_name,
                    process_name, event_type, severity, wazuh_rule_id,
                    mitre_tactic, mitre_technique_id, raw_event_json,
                    execution_source, synced_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.agent.id,
                    event.agent.name,
                    event.user.name,
                    event.process.name,
                    event.event_type,
                    event.severity,
                    event.wazuh_rule.id if event.wazuh_rule else None,
                    event.mitre.tactic,
                    event.mitre.technique_id,
                    json.dumps(event.raw_event),
                    execution_source,
                    synced_at,
                ),
            )
            if not existing:
                conn.execute("UPDATE zta_events SET normalized_json=?, processing_state='PENDING' WHERE event_id=?",
                             (json.dumps(asdict(event), default=str), event.event_id))
            conn.commit()
            return not bool(existing)

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent normalized ZTA events."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM zta_events ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]

    # --- Risk History ---
    def save_risk_event(self, event: RiskEvent):
        """Persists a RiskEvent to SQLite."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO risk_history (
                    timestamp, agent_id, previous_score, delta, new_score, reason, finding_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp.isoformat(),
                    event.agent_id,
                    event.previous_score,
                    event.delta,
                    event.new_score,
                    event.reason,
                    event.finding_id,
                ),
            )
            conn.commit()

    def get_agent_risk_history(self, agent_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieves risk history for a specific agent."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM risk_history WHERE agent_id = ? ORDER BY timestamp DESC, id DESC LIMIT ?",
                (agent_id, limit),
            )
            return [dict(row) for row in cursor.fetchall()]

    # --- Rules & Rule Matches ---
    def get_rules(self) -> List[Dict[str, Any]]:
        """Retrieves all detection and correlation rules with parsed conditions and linked stats."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM rules ORDER BY code ASC")
            rules = [dict(row) for row in cursor.fetchall()]
            for r in rules:
                try:
                    r["condition"] = json.loads(r.get("condition_json") or "{}")
                except Exception:
                    r["condition"] = {}

                # Query linked policies
                p_rows = conn.execute(
                    "SELECT policy_id, code, name, category, severity, mode, action, enabled, total_triggers FROM policies WHERE rule_id = ? OR rule_id = ?",
                    (r["rule_id"], r["code"]),
                ).fetchall()
                r["linked_policies"] = [dict(p) for p in p_rows]
                r["linked_policies_count"] = len(r["linked_policies"])

                # Count matches
                m_count = conn.execute(
                    "SELECT COUNT(*) FROM rule_matches WHERE rule_id = ? OR rule_code = ?",
                    (r["rule_id"], r["code"]),
                ).fetchone()[0]
                r["total_matches"] = m_count
            return rules

    def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single rule by rule_id or code, with condition, linked policies, stats, and recent matches."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM rules WHERE rule_id = ? OR code = ?", (rule_id, rule_id))
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            try:
                res["condition"] = json.loads(res.get("condition_json") or "{}")
            except Exception:
                res["condition"] = {}

            # Linked policies
            p_rows = conn.execute(
                "SELECT policy_id, code, name, category, severity, mode, action, enabled, total_triggers FROM policies WHERE rule_id = ? OR rule_id = ?",
                (res["rule_id"], res["code"]),
            ).fetchall()
            res["linked_policies"] = [dict(p) for p in p_rows]
            res["linked_policies_count"] = len(res["linked_policies"])

            # Alerts generated count
            alert_count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE rule_id = ? OR rule_code = ?",
                (res["rule_id"], res["code"]),
            ).fetchone()[0]
            res["alerts_generated"] = alert_count

            # Recent matches
            m_rows = conn.execute(
                "SELECT * FROM rule_matches WHERE rule_id = ? OR rule_code = ? ORDER BY matched_at DESC LIMIT 20",
                (res["rule_id"], res["code"]),
            ).fetchall()
            recent_matches = []
            for m in m_rows:
                md = dict(m)
                try:
                    md["matched_conditions"] = json.loads(md.get("matched_conditions_json") or "{}")
                except Exception:
                    md["matched_conditions"] = {}
                md["confidence"] = md.get("confidence")
                recent_matches.append(md)
            res["evaluation_history"] = [dict(r) for r in conn.execute("SELECT * FROM rule_evaluations WHERE rule_id=? ORDER BY timestamp DESC LIMIT 100", (res["rule_id"],))]
            res["recent_matches"] = recent_matches
            res["matches"] = recent_matches
            return res

    def create_rule(self, rule_data: Dict[str, Any], actor: str = "admin", role: str = "admin") -> Dict[str, Any]:
        """Creates a new real detection rule in the database with audit trail."""
        candidate = dict(rule_data) if isinstance(rule_data, dict) else rule_data
        if isinstance(candidate, dict):
            candidate.setdefault("category", "General")
            candidate.setdefault("severity", "MEDIUM")
            candidate.setdefault("risk_delta", 15)
            candidate.setdefault("response_action", "ALERT")
            candidate.setdefault("logic_type", "CONDITION_TREE")
            candidate.setdefault("enabled", True)
            candidate.setdefault("allow_offline", False)
        RuleValidator().validate(candidate)
        rule_data = candidate
        code = rule_data["code"].strip()
        name = rule_data["name"].strip()

        # Ensure code uniqueness
        existing = self.get_rule_by_id(code)
        if existing:
            raise ValueError(f"Rule with code '{code}' already exists")

        rule_id = rule_data.get("rule_id") or code
        category = rule_data.get("category", "General")
        severity = rule_data.get("severity", "MEDIUM")
        mitre_tactic = rule_data.get("mitre_tactic")
        mitre_technique_id = rule_data.get("mitre_technique_id")
        risk_delta = rule_data["risk_delta"]
        cond = rule_data.get("condition")
        if cond is None: cond = json.loads(rule_data["condition_json"])
        cond_json = json.dumps(cond) if not isinstance(cond, str) else cond
        response_action = rule_data.get("response_action", "ALERT")
        logic_type = rule_data.get("logic_type", "CONDITION_TREE")
        enabled = 1 if rule_data.get("enabled", True) else 0
        allow_offline = 1 if rule_data.get("allow_offline", False) else 0
        now_iso = datetime.now(timezone.utc).isoformat()

        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO rules (
                    rule_id, code, name, category, severity, mitre_tactic, mitre_technique_id,
                    risk_delta, condition_json, response_action, logic_type, enabled,
                    allow_offline, total_matches, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    rule_id, code, name, category, severity, mitre_tactic, mitre_technique_id,
                    risk_delta, cond_json, response_action, logic_type, enabled,
                    allow_offline, now_iso,
                ),
            )
            created = dict(conn.execute("SELECT * FROM rules WHERE rule_id=?", (rule_id,)).fetchone())
            self._save_rule_version(conn, created, 1, actor, "CREATE")
            conn.commit()

        self.save_audit(
            event_type="RULE_CREATED",
            action=f"Rule {code} ({name}) created",
            user=f"{role}:{actor}",
            details={
                "actor": actor,
                "role": role,
                "rule_id": rule_id,
                "code": code,
                "name": name,
                "severity": severity,
                "risk_delta": risk_delta,
                "enabled": bool(enabled),
                "changes": rule_data,
                "result": "SUCCESS",
            },
            execution_source="MANAGER",
        )

        return self.get_rule_by_id(rule_id)

    def update_rule(self, rule_id: str, update_data: Dict[str, Any], actor: str = "admin", role: str = "admin") -> Optional[Dict[str, Any]]:
        """Updates an existing detection rule in the database with audit trail."""
        rule = self.get_rule_by_id(rule_id)
        if not rule:
            return None

        if not isinstance(update_data, dict):
            raise ValueError("Rule update must be an object")
        candidate = {**rule, **update_data}
        if "condition" not in update_data:
            candidate["condition"] = rule["condition"]
        RuleValidator().validate(candidate)

        name = update_data.get("name", rule["name"])
        category = update_data.get("category", rule["category"])
        severity = update_data.get("severity", rule["severity"])
        mitre_tactic = update_data.get("mitre_tactic", rule.get("mitre_tactic"))
        mitre_technique_id = update_data.get("mitre_technique_id", rule.get("mitre_technique_id"))
        risk_delta = update_data.get("risk_delta", rule.get("risk_delta", 15))
        response_action = update_data.get("response_action", rule.get("response_action", "ALERT"))
        enabled = 1 if update_data.get("enabled", rule.get("enabled", 1)) else 0
        allow_offline = 1 if update_data.get("allow_offline", rule.get("allow_offline", 0)) else 0

        cond = update_data.get("condition")
        cond_json = json.dumps(cond) if cond is not None and not isinstance(cond, str) else (cond or rule.get("condition_json", "{}"))
        next_version = int(rule.get("current_version") or 1) + 1

        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE rules SET
                    name = ?, category = ?, severity = ?, mitre_tactic = ?, mitre_technique_id = ?,
                    risk_delta = ?, condition_json = ?, response_action = ?, enabled = ?, allow_offline = ?,
                    current_version = ?
                WHERE rule_id = ? OR code = ?
                """,
                (
                    name, category, severity, mitre_tactic, mitre_technique_id,
                    risk_delta, cond_json, response_action, enabled, allow_offline, next_version,
                    rule["rule_id"], rule["code"],
                ),
            )
            updated = dict(conn.execute("SELECT * FROM rules WHERE rule_id=?", (rule["rule_id"],)).fetchone())
            self._save_rule_version(conn, updated, next_version, actor, "UPDATE")
            conn.commit()

        self.save_audit(
            event_type="RULE_UPDATED",
            action=f"Rule {rule['code']} ({name}) updated",
            user=f"{role}:{actor}",
            details={
                "actor": actor,
                "role": role,
                "rule_id": rule["rule_id"],
                "code": rule["code"],
                "changes": update_data,
                "result": "SUCCESS",
            },
            execution_source="MANAGER",
        )

        return self.get_rule_by_id(rule["rule_id"])

    def toggle_rule(self, rule_id: str, enabled: Optional[bool] = None, actor: str = "admin", role: str = "admin") -> Optional[Dict[str, Any]]:
        """Toggles or sets the enabled status of a rule."""
        rule = self.get_rule_by_id(rule_id)
        if not rule:
            return None

        new_status = (not bool(rule.get("enabled", 1))) if enabled is None else bool(enabled)
        if new_status:
            candidate = dict(rule)
            candidate["enabled"] = True
            RuleValidator().validate(candidate)
        val = 1 if new_status else 0
        next_version = int(rule.get("current_version") or 1) + 1

        with self.db.get_connection() as conn:
            conn.execute(
                "UPDATE rules SET enabled = ?, current_version = ? WHERE rule_id = ? OR code = ?",
                (val, next_version, rule["rule_id"], rule["code"]),
            )
            updated = dict(conn.execute("SELECT * FROM rules WHERE rule_id=?", (rule["rule_id"],)).fetchone())
            self._save_rule_version(conn, updated, next_version, actor, "TOGGLE")
            conn.commit()

        audit_type = "RULE_ENABLED" if new_status else "RULE_DISABLED"
        self.save_audit(
            event_type=audit_type,
            action=f"Rule {rule['code']} {'enabled' if new_status else 'disabled'}",
            user=f"{role}:{actor}",
            details={
                "actor": actor,
                "role": role,
                "rule_id": rule["rule_id"],
                "code": rule["code"],
                "enabled": new_status,
                "result": "SUCCESS",
            },
            execution_source="MANAGER",
        )

        return self.get_rule_by_id(rule["rule_id"])

    def delete_rule(self, rule_id: str, actor: str = "admin", role: str = "admin") -> Dict[str, Any]:
        """Safely deletes a rule while preserving historical rule matches and alerts."""
        rule = self.get_rule_by_id(rule_id)
        if not rule:
            raise ValueError("Rule not found")

        with self.db.get_connection() as conn:
            # Count historical dependencies
            m_count = conn.execute(
                "SELECT COUNT(*) FROM rule_matches WHERE rule_id = ? OR rule_code = ?",
                (rule["rule_id"], rule["code"]),
            ).fetchone()[0]
            a_count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE rule_id = ? OR rule_code = ?",
                (rule["rule_id"], rule["code"]),
            ).fetchone()[0]
            p_count = conn.execute(
                "SELECT COUNT(*) FROM policies WHERE rule_id = ? OR rule_id = ?",
                (rule["rule_id"], rule["code"]),
            ).fetchone()[0]

            if p_count:
                raise RuleDependencyError(
                    f"Rule is linked to {p_count} policy definition(s); remove or relink them before deletion"
                )

            # Delete the rule definition
            conn.execute("DELETE FROM rules WHERE rule_id = ? OR code = ?", (rule["rule_id"], rule["code"]))
            conn.commit()

        self.save_audit(
            event_type="RULE_DELETED",
            action=f"Rule {rule['code']} ({rule['name']}) deleted (preserved {m_count} matches, {a_count} alerts)",
            user=f"{role}:{actor}",
            details={
                "actor": actor,
                "role": role,
                "rule_id": rule["rule_id"],
                "code": rule["code"],
                "matches_preserved": m_count,
                "alerts_preserved": a_count,
                "linked_policies_count": p_count,
                "result": "SUCCESS",
            },
            execution_source="MANAGER",
        )

        return {
            "status": "DELETED",
            "rule_id": rule["rule_id"],
            "code": rule["code"],
            "name": rule["name"],
            "matches_count": m_count,
            "alerts_count": a_count,
            "linked_policies_count": p_count,
        }

    def rollback_rule(self, rule_id: str, version: int, actor: str = "admin", role: str = "admin") -> Optional[Dict[str, Any]]:
        """Restores a historical definition as a new version without changing identifiers."""
        rule = self.get_rule_by_id(rule_id)
        if not rule:
            return None
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise ValueError("version must be a positive integer")
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT definition_json FROM rule_versions WHERE rule_id=? AND version=?",
                (rule["rule_id"], version),
            ).fetchone()
            if not row:
                raise ValueError(f"Rule version {version} not found")
            definition = json.loads(row["definition_json"])
            definition["rule_id"] = rule["rule_id"]
            definition["code"] = rule["code"]
            definition["created_at"] = rule["created_at"]
            definition["condition"] = json.loads(definition.get("condition_json") or "{}")
            RuleValidator().validate(definition)
            next_version = int(rule.get("current_version") or 1) + 1
            conn.execute(
                """UPDATE rules SET name=?, category=?, severity=?, mitre_tactic=?, mitre_technique_id=?,
                   risk_delta=?, condition_json=?, response_action=?, logic_type=?, enabled=?, allow_offline=?, current_version=?
                   WHERE rule_id=?""",
                tuple(definition.get(field) for field in (
                    "name", "category", "severity", "mitre_tactic", "mitre_technique_id", "risk_delta",
                    "condition_json", "response_action", "logic_type", "enabled", "allow_offline",
                )) + (next_version, rule["rule_id"]),
            )
            restored = dict(conn.execute("SELECT * FROM rules WHERE rule_id=?", (rule["rule_id"],)).fetchone())
            self._save_rule_version(conn, restored, next_version, actor, "ROLLBACK")
            conn.commit()
        self.save_audit(
            "RULE_ROLLED_BACK", f"Rule {rule['code']} restored from version {version}", f"{role}:{actor}",
            details={"rule_id": rule["rule_id"], "source_version": version, "new_version": next_version},
            execution_source="MANAGER",
        )
        return self.get_rule_by_id(rule["rule_id"])

    def get_linked_policies(self, rule_id: str) -> List[Dict[str, Any]]:
        """Retrieves all policies linked to a rule by ID or code."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT p.* FROM policies p
                LEFT JOIN rules r ON p.rule_id = r.rule_id OR p.rule_id = r.code
                WHERE p.rule_id = ? OR r.rule_id = ? OR r.code = ?
                """,
                (rule_id, rule_id, rule_id),
            )
            rows = [dict(row) for row in cursor.fetchall()]
            for p in rows:
                try:
                    p["condition"] = json.loads(p.get("condition_json") or "{}") if p.get("condition_json") else None
                except Exception:
                    p["condition"] = None
            return rows

    def save_rule_match(self, match: Dict[str, Any]):
        """Persists a real rule match record and updates rule statistics."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO rule_matches (
                    match_id, rule_id, rule_code, rule_name, agent_id, agent_name,
                    event_id, severity, mitre_tactic, mitre_technique_id,
                    matched_conditions_json, condition_result, risk_delta,
                    matched_at, alert_id, policy_id, execution_source, is_demo, rule_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    match["match_id"],
                    match["rule_id"],
                    match["rule_code"],
                    match["rule_name"],
                    match["agent_id"],
                    match.get("agent_name", match["agent_id"]),
                    match.get("event_id"),
                    match.get("severity", "MEDIUM"),
                    match.get("mitre_tactic"),
                    match.get("mitre_technique_id"),
                    json.dumps(match.get("matched_conditions", {})),
                    1 if match.get("condition_result", True) else 0,
                    match.get("risk_delta", 0),
                    match.get("matched_at", datetime.now(timezone.utc).isoformat()),
                    match.get("alert_id"),
                    match.get("policy_id"),
                    match.get("execution_source", "AGENT_ONLINE"),
                    1 if match.get("is_demo") or str(match.get("rule_code", "")).startswith("DEMO-") else 0,
                    match.get("rule_version"),
                ),
            )
            # Increment rule total_matches and update last_matched
            conn.execute(
                """
                UPDATE rules SET total_matches = total_matches + 1, last_matched = ?
                WHERE rule_id = ? OR code = ?
                """,
                (match.get("matched_at", datetime.now(timezone.utc).isoformat()), match["rule_id"], match["rule_code"]),
            )
            conn.commit()

    def get_rule_matches(self, limit: int = 50, rule_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves rule matches with parsed conditions and confidence."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            if rule_id:
                cursor.execute(
                    "SELECT * FROM rule_matches WHERE rule_id = ? OR rule_code = ? ORDER BY matched_at DESC LIMIT ?",
                    (rule_id, rule_id, limit),
                )
            else:
                cursor.execute("SELECT * FROM rule_matches ORDER BY matched_at DESC LIMIT ?", (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            for r in rows:
                try:
                    r["matched_conditions"] = json.loads(r.get("matched_conditions_json") or "{}")
                except Exception:
                    r["matched_conditions"] = {}
                r["confidence"] = r.get("confidence")
            return rows

    # --- Policies & Policy Evaluations ---
    def get_policies(self) -> List[Dict[str, Any]]:
        """Retrieves all adaptive policies with linked rule details and trigger statistics."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM policies ORDER BY priority ASC, code ASC, policy_id ASC")
            policies = [dict(row) for row in cursor.fetchall()]
            for p in policies:
                try:
                    p["condition"] = json.loads(p.get("condition_json") or "{}") if p.get("condition_json") else None
                except Exception:
                    p["condition"] = None

                # Fetch linked rule information
                if p.get("rule_id"):
                    r_row = conn.execute(
                        "SELECT code, name, severity, mitre_technique_id, mitre_tactic FROM rules WHERE rule_id = ? OR code = ?",
                        (p["rule_id"], p["rule_id"]),
                    ).fetchone()
                    if r_row:
                        p["linked_rule_code"] = r_row["code"]
                        p["linked_rule_name"] = r_row["name"]
                        p["linked_rule_severity"] = r_row["severity"]
                        p["linked_rule_mitre"] = r_row["mitre_technique_id"]
                    else:
                        p["linked_rule_code"] = p["rule_id"]
                        p["linked_rule_name"] = p["rule_id"]
                else:
                    p["linked_rule_code"] = None
                    p["linked_rule_name"] = None

                # Count triggers
                t_count = conn.execute(
                    "SELECT COUNT(*) FROM policy_evaluations WHERE (policy_id = ? OR policy_code = ?) AND evaluation_result = 'TRIGGERED'",
                    (p["policy_id"], p.get("code")),
                ).fetchone()[0]
                p["total_triggers"] = t_count

            return policies

    def get_policy_by_id(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single policy by ID or code with linked rule details, stats, and recent evaluations."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM policies WHERE policy_id = ? OR code = ?", (policy_id, policy_id))
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            try:
                res["condition"] = json.loads(res.get("condition_json") or "{}") if res.get("condition_json") else None
            except Exception:
                res["condition"] = None

            # Linked rule info
            if res.get("rule_id"):
                r_row = conn.execute(
                    "SELECT rule_id, code, name, severity, mitre_technique_id, mitre_tactic FROM rules WHERE rule_id = ? OR code = ?",
                    (res["rule_id"], res["rule_id"]),
                ).fetchone()
                if r_row:
                    res["linked_rule"] = dict(r_row)
                    res["linked_rule_code"] = r_row["code"]
                    res["linked_rule_name"] = r_row["name"]
                else:
                    res["linked_rule"] = {"code": res["rule_id"], "name": res["rule_id"]}
                    res["linked_rule_code"] = res["rule_id"]
                    res["linked_rule_name"] = res["rule_id"]

            # Successful and failed command responses
            succ_resp = conn.execute(
                "SELECT COUNT(*) FROM commands WHERE (policy_id = ? OR policy_code = ?) AND status = 'SUCCESS'",
                (res["policy_id"], res.get("code")),
            ).fetchone()[0]
            fail_resp = conn.execute(
                "SELECT COUNT(*) FROM commands WHERE (policy_id = ? OR policy_code = ?) AND status = 'FAILED'",
                (res["policy_id"], res.get("code")),
            ).fetchone()[0]
            res["successful_responses"] = succ_resp
            res["failed_responses"] = fail_resp

            # Recent evaluations
            e_rows = conn.execute(
                "SELECT * FROM policy_evaluations WHERE policy_id = ? OR policy_code = ? ORDER BY timestamp DESC LIMIT 20",
                (res["policy_id"], res.get("code")),
            ).fetchall()
            res["evaluations"] = [dict(e) for e in e_rows]
            res["recent_evaluations"] = res["evaluations"]
            return res

    def create_policy(self, policy_data: Dict[str, Any], actor: str = "admin", role: str = "admin") -> Dict[str, Any]:
        """Creates a new adaptive response policy in the database with audit trail."""
        candidate = dict(policy_data) if isinstance(policy_data, dict) else policy_data
        if isinstance(candidate, dict):
            candidate.setdefault("severity", "HIGH")
            candidate.setdefault("mode", "ENFORCE")
            candidate.setdefault("action", "MONITOR")
            candidate.setdefault("min_risk", 0)
            candidate.setdefault("max_risk", 100)
            candidate.setdefault("risk_threshold", 85)
            candidate.setdefault("priority", 1000)
            candidate.setdefault("enabled", True)
            candidate.setdefault("allow_offline", False)
        PolicyValidator().validate(candidate)
        policy_data = candidate
        code = str(policy_data.get("code", "")).strip()
        name = str(policy_data.get("name", "")).strip()
        if not code or not name:
            raise ValueError("Policy code and name are required")

        existing = self.get_policy_by_id(code)
        if existing:
            raise ValueError(f"Policy with code '{code}' already exists")

        policy_id = policy_data.get("policy_id") or code
        category = policy_data.get("category", "General")
        severity = policy_data.get("severity", "HIGH")
        rule_id = policy_data.get("rule_id")
        risk_threshold = int(policy_data.get("risk_threshold", 85))
        min_risk = int(policy_data.get("min_risk", 0))
        max_risk = int(policy_data.get("max_risk", 100))
        action = policy_data.get("action", "MONITOR")
        mode = policy_data.get("mode", "ENFORCE")
        cond = policy_data.get("condition") or policy_data.get("condition_json")
        cond_json = json.dumps(cond) if cond is not None and not isinstance(cond, str) else cond
        enabled = 1 if policy_data.get("enabled", True) else 0
        allow_offline = 1 if policy_data.get("allow_offline", False) else 0
        priority = policy_data.get("priority", 1000)
        now_iso = datetime.now(timezone.utc).isoformat()

        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO policies (
                    policy_id, code, name, category, severity, rule_id, risk_threshold,
                    min_risk, max_risk, action, mode, condition_json, enabled, allow_offline,
                    total_triggers, created_at, priority
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    policy_id, code, name, category, severity, rule_id, risk_threshold,
                    min_risk, max_risk, action, mode, cond_json, enabled, allow_offline,
                    now_iso, priority,
                ),
            )
            conn.commit()

        self.save_audit(
            event_type="POLICY_CREATED",
            action=f"Policy {code} ({name}) created [{mode} -> {action}]",
            user=f"{role}:{actor}",
            details={
                "actor": actor,
                "role": role,
                "policy_id": policy_id,
                "code": code,
                "name": name,
                "mode": mode,
                "action": action,
                "rule_id": rule_id,
                "changes": policy_data,
                "result": "SUCCESS",
            },
            execution_source="MANAGER",
        )

        if rule_id:
            self.save_audit(
                event_type="POLICY_RULE_LINKED",
                action=f"Policy {code} linked to Rule {rule_id}",
                user=f"{role}:{actor}",
                details={
                    "actor": actor,
                    "role": role,
                    "policy_id": policy_id,
                    "rule_id": rule_id,
                    "result": "SUCCESS",
                },
                execution_source="MANAGER",
            )

        return self.get_policy_by_id(policy_id)

    def update_policy(self, policy_id: str, update_data: Dict[str, Any], actor: str = "admin", role: str = "admin") -> Optional[Dict[str, Any]]:
        """Updates an existing policy in the database with audit trail."""
        policy = self.get_policy_by_id(policy_id)
        if not policy:
            return None

        if not isinstance(update_data, dict):
            raise ValueError("Policy update must be an object")
        candidate = {**policy, **update_data}
        if "condition" not in update_data:
            candidate["condition"] = policy.get("condition")
        PolicyValidator().validate(candidate)
        name = update_data.get("name", policy["name"])
        category = update_data.get("category", policy.get("category", "General"))
        severity = update_data.get("severity", policy.get("severity", "HIGH"))
        old_rule_id = policy.get("rule_id")
        rule_id = update_data.get("rule_id", old_rule_id)
        risk_threshold = int(update_data.get("risk_threshold", policy.get("risk_threshold", 85)))
        min_risk = int(update_data.get("min_risk", policy.get("min_risk", 0)))
        max_risk = int(update_data.get("max_risk", policy.get("max_risk", 100)))
        action = update_data.get("action", policy.get("action", "MONITOR"))
        mode = update_data.get("mode", policy.get("mode", "ENFORCE"))
        enabled = 1 if update_data.get("enabled", policy.get("enabled", 1)) else 0
        allow_offline = 1 if update_data.get("allow_offline", policy.get("allow_offline", 0)) else 0
        priority = update_data.get("priority", policy.get("priority", 1000))

        cond = update_data.get("condition")
        cond_json = json.dumps(cond) if cond is not None and not isinstance(cond, str) else (cond or policy.get("condition_json"))

        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE policies SET
                    name = ?, category = ?, severity = ?, rule_id = ?, risk_threshold = ?,
                    min_risk = ?, max_risk = ?, action = ?, mode = ?, condition_json = ?,
                    enabled = ?, allow_offline = ?, priority = ?
                WHERE policy_id = ? OR code = ?
                """,
                (
                    name, category, severity, rule_id, risk_threshold,
                    min_risk, max_risk, action, mode, cond_json,
                    enabled, allow_offline, priority, policy["policy_id"], policy.get("code"),
                ),
            )
            conn.commit()

        self.save_audit(
            event_type="POLICY_UPDATED",
            action=f"Policy {policy['code']} updated [{mode} -> {action}]",
            user=f"{role}:{actor}",
            details={
                "actor": actor,
                "role": role,
                "policy_id": policy["policy_id"],
                "code": policy.get("code"),
                "changes": update_data,
                "result": "SUCCESS",
            },
            execution_source="MANAGER",
        )

        if rule_id and rule_id != old_rule_id:
            self.save_audit(
                event_type="POLICY_RULE_LINKED",
                action=f"Policy {policy['code']} link changed to Rule {rule_id}",
                user=f"{role}:{actor}",
                details={
                    "actor": actor,
                    "role": role,
                    "policy_id": policy["policy_id"],
                    "old_rule_id": old_rule_id,
                    "new_rule_id": rule_id,
                    "result": "SUCCESS",
                },
                execution_source="MANAGER",
            )

        return self.get_policy_by_id(policy["policy_id"])

    def toggle_policy(self, policy_id: str, enabled: Optional[bool] = None, actor: str = "admin", role: str = "admin") -> Optional[Dict[str, Any]]:
        """Toggles or sets the enabled status of a policy."""
        policy = self.get_policy_by_id(policy_id)
        if not policy:
            return None

        new_status = (not bool(policy.get("enabled", 1))) if enabled is None else bool(enabled)
        if new_status:
            candidate = dict(policy)
            candidate["enabled"] = True
            PolicyValidator().validate(candidate)
        val = 1 if new_status else 0

        with self.db.get_connection() as conn:
            conn.execute(
                "UPDATE policies SET enabled = ? WHERE policy_id = ? OR code = ?",
                (val, policy["policy_id"], policy.get("code")),
            )
            conn.commit()

        audit_type = "POLICY_ENABLED" if new_status else "POLICY_DISABLED"
        self.save_audit(
            event_type=audit_type,
            action=f"Policy {policy['code']} {'enabled' if new_status else 'disabled'}",
            user=f"{role}:{actor}",
            details={
                "actor": actor,
                "role": role,
                "policy_id": policy["policy_id"],
                "code": policy.get("code"),
                "enabled": new_status,
                "result": "SUCCESS",
            },
            execution_source="MANAGER",
        )

        return self.get_policy_by_id(policy["policy_id"])

    def delete_policy(self, policy_id: str, actor: str = "admin", role: str = "admin") -> Dict[str, Any]:
        """Safely deletes a policy while preserving historical evaluations."""
        policy = self.get_policy_by_id(policy_id)
        if not policy:
            raise ValueError("Policy not found")

        with self.db.get_connection() as conn:
            e_count = conn.execute(
                "SELECT COUNT(*) FROM policy_evaluations WHERE policy_id = ? OR policy_code = ?",
                (policy["policy_id"], policy.get("code")),
            ).fetchone()[0]
            c_count = conn.execute(
                "SELECT COUNT(*) FROM commands WHERE policy_id = ? OR policy_code = ?",
                (policy["policy_id"], policy.get("code")),
            ).fetchone()[0]

            conn.execute("DELETE FROM policies WHERE policy_id = ? OR code = ?", (policy["policy_id"], policy.get("code")))
            conn.commit()

        self.save_audit(
            event_type="POLICY_DELETED",
            action=f"Policy {policy['code']} deleted (preserved {e_count} evaluations, {c_count} commands)",
            user=f"{role}:{actor}",
            details={
                "actor": actor,
                "role": role,
                "policy_id": policy["policy_id"],
                "code": policy.get("code"),
                "evaluations_preserved": e_count,
                "commands_preserved": c_count,
                "result": "SUCCESS",
            },
            execution_source="MANAGER",
        )

        return {
            "status": "DELETED",
            "policy_id": policy["policy_id"],
            "code": policy.get("code"),
            "name": policy["name"],
            "evaluations_count": e_count,
            "commands_count": c_count,
        }

    def save_policy_evaluation(self, eval_data: Dict[str, Any]):
        """Persists a policy evaluation record and increments triggers if TRIGGERED."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO policy_evaluations (
                    eval_id, policy_id, policy_code, policy_name, rule_id,
                    agent_id, alert_id, risk_score, trust_score, mode, action,
                    evaluation_result, reason, status, timestamp, execution_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    eval_data["eval_id"],
                    eval_data["policy_id"],
                    eval_data.get("policy_code", eval_data["policy_id"]),
                    eval_data.get("policy_name", "Adaptive Policy"),
                    eval_data.get("rule_id"),
                    eval_data["agent_id"],
                    eval_data.get("alert_id"),
                    eval_data.get("risk_score", 0),
                    eval_data.get("trust_score", 100),
                    eval_data.get("mode", "ENFORCE"),
                    eval_data.get("action", "MONITOR"),
                    eval_data.get("evaluation_result", "TRIGGERED"),
                    eval_data.get("reason", ""),
                    eval_data.get("status", "SUCCESS"),
                    eval_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    eval_data.get("execution_source", "AGENT_ONLINE"),
                ),
            )
            if eval_data.get("evaluation_result") == "TRIGGERED":
                conn.execute(
                    """
                    UPDATE policies SET total_triggers = total_triggers + 1, last_triggered = ?
                    WHERE policy_id = ? OR code = ?
                    """,
                    (eval_data.get("timestamp", datetime.now(timezone.utc).isoformat()), eval_data["policy_id"], eval_data.get("policy_code")),
                )
            conn.commit()

    def get_policy_evaluations(self, limit: int = 50, policy_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves policy evaluation history."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            if policy_id:
                cursor.execute(
                    "SELECT * FROM policy_evaluations WHERE policy_id = ? OR policy_code = ? ORDER BY timestamp DESC LIMIT ?",
                    (policy_id, policy_id, limit),
                )
            else:
                cursor.execute("SELECT * FROM policy_evaluations ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(r) for r in cursor.fetchall()]

    # --- Incidents / Alerts ---
    def save_incident(self, incident: Dict[str, Any]):
        """Persists an Incident/Alert to SQLite."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id, agent_id, agent_name, user_name, severity,
                    risk_score, trust_score, status, trigger_reason, action_taken,
                    rule_id, rule_code, rule_name, policy_id, policy_name,
                    response_action, response_status, detection_json,
                    created_at, updated_at, execution_source, is_demo, rule_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident["incident_id"],
                    incident["agent_id"],
                    incident.get("agent_name") or incident["agent_id"],
                    incident.get("user_name"),
                    incident.get("severity", "HIGH"),
                    incident.get("risk_score", 0),
                    incident.get("trust_score", 100),
                    incident.get("status", "OPEN"),
                    incident.get("trigger_reason", ""),
                    incident.get("action_taken", "MONITOR"),
                    incident.get("rule_id"),
                    incident.get("rule_code"),
                    incident.get("rule_name"),
                    incident.get("policy_id"),
                    incident.get("policy_name"),
                    incident.get("response_action"),
                    incident.get("response_status"),
                    json.dumps(incident.get("detection_json", {})) if isinstance(incident.get("detection_json"), dict) else incident.get("detection_json"),
                    incident.get("created_at", datetime.now(timezone.utc).isoformat()),
                    incident.get("updated_at", datetime.now(timezone.utc).isoformat()),
                    incident.get("execution_source", "AGENT_ONLINE"),
                    1 if incident.get("is_demo") or str(incident.get("rule_code", "")).startswith("DEMO-") else 0,
                    incident.get("rule_version"),
                ),
            )
            conn.commit()

    def get_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves all incidents/alerts."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            rows = [dict(row) for row in cursor.fetchall()]
            for r in rows:
                try:
                    r["detection"] = json.loads(r.get("detection_json") or "{}") if r.get("detection_json") else {}
                except Exception:
                    r["detection"] = {}
            return rows

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves full incident details including forensic chain."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            try:
                res["detection"] = json.loads(res.get("detection_json") or "{}") if res.get("detection_json") else {}
            except Exception:
                res["detection"] = {}
            # Fetch associated rule matches, policy evaluations, and commands
            res["rule_matches"] = [dict(r) for r in conn.execute("SELECT * FROM rule_matches WHERE alert_id=?", (incident_id,))]
            res["policy_evaluations"] = [dict(r) for r in conn.execute("SELECT * FROM policy_evaluations WHERE alert_id=?", (incident_id,))]
            event_id = res["detection"].get("event_id")
            res["rule_evaluations"] = [dict(r) for r in conn.execute("SELECT * FROM rule_evaluations WHERE event_id=?", (event_id,))]
            res["risk_history"] = [dict(r) for r in conn.execute("SELECT * FROM risk_history WHERE finding_id IN (SELECT match_id FROM rule_matches WHERE alert_id=?)", (incident_id,))]
            res["audit"] = [a for a in self.get_audit_logs(10000) if a["details"].get("alert_id") == incident_id]
            res["synced_at"] = conn.execute("SELECT synced_at FROM zta_events WHERE event_id=?", (event_id,)).fetchone()
            res["synced_at"] = res["synced_at"][0] if res["synced_at"] else None
            res["commands"] = self.get_commands_for_alert(incident_id)
            return res

    # --- Commands ---
    def save_command(self, cmd: Dict[str, Any]):
        """Persists or updates a command record."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO commands (
                    command_id, policy_id, policy_code, alert_id, agent_id,
                    action_type, params_json, status, executor, output,
                    error_code, error_message, verification, dry_run,
                    execution_source, created_at, dispatched_at, completed_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cmd["command_id"],
                    cmd.get("policy_id"),
                    cmd.get("policy_code"),
                    cmd.get("alert_id"),
                    cmd["agent_id"],
                    cmd["action_type"],
                    json.dumps(cmd.get("params", {})) if isinstance(cmd.get("params"), dict) else (cmd.get("params_json") or "{}"),
                    cmd.get("status", "PENDING"),
                    cmd.get("executor", "WINDOWS_POWERSHELL"),
                    cmd.get("output", ""),
                    cmd.get("error_code"),
                    cmd.get("error_message"),
                    cmd.get("verification"),
                    1 if cmd.get("dry_run") else 0,
                    cmd.get("execution_source", "MANAGER"),
                    cmd.get("created_at", datetime.now(timezone.utc).isoformat()),
                    cmd.get("dispatched_at"),
                    cmd.get("completed_at"),
                    cmd.get("expires_at"),
                ),
            )
            conn.commit()

    def get_commands(self, limit: int = 50, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves commands history."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            if agent_id:
                cursor.execute(
                    "SELECT * FROM commands WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?",
                    (agent_id, limit),
                )
            else:
                cursor.execute("SELECT * FROM commands ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            for r in rows:
                try:
                    r["params"] = json.loads(r.get("params_json") or "{}")
                except Exception:
                    r["params"] = {}
            return rows

    def get_commands_for_alert(self, alert_id: str) -> List[Dict[str, Any]]:
        """Retrieves commands dispatched for a specific alert."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM commands WHERE alert_id = ? ORDER BY created_at DESC", (alert_id,))
            rows = [dict(r) for r in cursor.fetchall()]
            for r in rows:
                try:
                    r["params"] = json.loads(r.get("params_json") or "{}")
                except Exception:
                    r["params"] = {}
            return rows

    def get_pending_commands(self, agent_id: str) -> List[Dict[str, Any]]:
        """Retrieves pending or queued commands for an agent."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM commands WHERE agent_id = ? AND status IN ('PENDING', 'AUTHORIZED', 'QUEUED') ORDER BY created_at ASC",
                (agent_id,),
            )
            rows = [dict(r) for r in cursor.fetchall()]
            for r in rows:
                try:
                    r["params"] = json.loads(r.get("params_json") or "{}")
                except Exception:
                    r["params"] = {}
            return rows

    def update_command_result(self, command_id: str, status: str, output: str = "", error: Optional[str] = None, verification: Optional[Any] = None):
        """Updates command status upon execution completion."""
        now = datetime.now(timezone.utc).isoformat()
        verif_str = json.dumps(verification) if isinstance(verification, (dict, list)) else (str(verification) if verification is not None else None)
        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE commands SET status = ?, output = ?, error_message = ?, verification = ?, completed_at = ?
                WHERE command_id = ?
                """,
                (status, output, error, verif_str, now, command_id),
            )
            conn.commit()

    # --- Audit Log ---
    def save_audit(self, event_type: str, action: str, agent_id: Optional[str] = None, user: Optional[str] = None, details: Optional[Dict[str, Any]] = None, execution_source: str = "MANAGER", status: str = "SUCCESS", timestamp: Optional[str] = None):
        """Persists an audit log entry."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (
                    event_type, action, agent_id, user, details_json,
                    execution_source, status, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_type,
                    action,
                    agent_id,
                    user,
                    json.dumps(details or {}),
                    execution_source,
                    status,
                    ts,
                ),
            )
            conn.commit()

    def get_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent audit logs."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_log ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            for r in rows:
                try:
                    r["details"] = json.loads(r.get("details_json") or "{}")
                except Exception:
                    r["details"] = {}
            return rows

    # --- Background Services Status ---
    def update_service_heartbeat(self, service_name: str, status: str = "RUNNING", details: Optional[Dict[str, Any]] = None, activity: bool = True):
        """Updates background service heartbeat and status."""
        now = datetime.now(timezone.utc).isoformat()
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO background_services (service_name, status, last_heartbeat, last_activity, details_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(service_name) DO UPDATE SET
                status = excluded.status,
                last_heartbeat = excluded.last_heartbeat,
                last_activity = CASE WHEN excluded.last_activity != '' THEN excluded.last_activity ELSE last_activity END,
                details_json = excluded.details_json
                """,
                (service_name, status, now, now if activity else "", json.dumps(details or {})),
            )
            conn.commit()

    def get_background_services(self) -> List[Dict[str, Any]]:
        """Retrieves operational status of all background services."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM background_services ORDER BY service_name ASC")
            rows = [dict(r) for r in cursor.fetchall()]
            for r in rows:
                try:
                    r["details"] = json.loads(r.get("details_json") or "{}")
                except Exception:
                    r["details"] = {}
                stamp = datetime.fromisoformat(r['last_heartbeat'])
                if (datetime.now(timezone.utc) - stamp).total_seconds() > 45:
                    r['status'] = 'STALE'
            return rows

    # --- Sync History ---
    def record_sync_batch(self, sync_data: Dict[str, Any]):
        """Records an offline synchronization batch."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sync_history (
                    sync_id, agent_id, batch_id, events_count, alerts_count,
                    rule_matches_count, policy_evals_count, responses_count,
                    status, synced_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sync_data["sync_id"],
                    sync_data["agent_id"],
                    sync_data.get("batch_id", sync_data["sync_id"]),
                    sync_data.get("events_count", 0),
                    sync_data.get("alerts_count", 0),
                    sync_data.get("rule_matches_count", 0),
                    sync_data.get("policy_evals_count", 0),
                    sync_data.get("responses_count", 0),
                    sync_data.get("status", "COMPLETED"),
                    sync_data.get("synced_at", datetime.now(timezone.utc).isoformat()),
                ),
            )
            conn.commit()

    def get_sync_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieves recent sync history records."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sync_history ORDER BY synced_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cursor.fetchall()]

    # --- Heartbeat & Agents ---
    def save_heartbeat(self, telemetry: Dict[str, Any]):
        """Saves or updates agent heartbeat and presence."""
        now = datetime.now(timezone.utc).isoformat()
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO agents (id, name, ip, os, last_seen, connection_state, sync_state, queue_depth,
                                    active_interface, interface_name, local_ipv4, local_ipv6, manager_observed_ip, interfaces_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                ip = excluded.ip,
                os = excluded.os,
                last_seen = excluded.last_seen,
                connection_state = excluded.connection_state,
                sync_state = excluded.sync_state,
                queue_depth = excluded.queue_depth,
                active_interface = COALESCE(excluded.active_interface, agents.active_interface),
                interface_name = COALESCE(excluded.interface_name, agents.interface_name),
                local_ipv4 = COALESCE(excluded.local_ipv4, agents.local_ipv4),
                local_ipv6 = COALESCE(excluded.local_ipv6, agents.local_ipv6),
                manager_observed_ip = COALESCE(excluded.manager_observed_ip, agents.manager_observed_ip),
                interfaces_json = COALESCE(excluded.interfaces_json, agents.interfaces_json)
                """,
                (
                    telemetry["agent_id"],
                    telemetry.get("hostname") or telemetry["agent_id"],
                    telemetry.get("ip") or telemetry.get("local_ipv4"),
                    telemetry.get("os"),
                    now,
                    telemetry.get("connection_state", "ONLINE"),
                    telemetry.get("sync_state", "IDLE"),
                    telemetry.get("queue_depth", 0),
                    telemetry.get("active_interface"),
                    telemetry.get("interface_name"),
                    telemetry.get("local_ipv4"),
                    telemetry.get("local_ipv6"),
                    telemetry.get("manager_observed_ip"),
                    json.dumps(telemetry.get("interfaces", [])) if telemetry.get("interfaces") else None,
                ),
            )
            conn.commit()

    def save_agent_log(self, log_entry: Dict[str, Any], execution_source: str = "AGENT_ONLINE", synced_at: Optional[str] = None):
        """Persists structured agent operational log."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO agent_logs (
                    log_id, timestamp, agent_id, hostname, level, component,
                    event_type, message, correlation_id, metadata_json, execution_source, synced_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    log_entry.get("log_id") or log_entry.get("id"),
                    log_entry.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    log_entry.get("agent_id"),
                    log_entry.get("hostname"),
                    log_entry.get("level", "INFO").upper(),
                    log_entry.get("component", "AGENT"),
                    log_entry.get("event_type", "OPERATIONAL"),
                    log_entry.get("message", ""),
                    log_entry.get("correlation_id"),
                    json.dumps(log_entry.get("metadata", {})) if isinstance(log_entry.get("metadata"), dict) else log_entry.get("metadata_json"),
                    execution_source,
                    synced_at,
                ),
            )
            conn.commit()

    def get_agent_logs(self, agent_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves structured agent operational logs."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            if agent_id:
                cursor.execute("SELECT * FROM agent_logs WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?", (agent_id, limit))
            else:
                cursor.execute("SELECT * FROM agent_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            for row in rows:
                try:
                    row["metadata"] = json.loads(row.get("metadata_json") or "{}")
                except Exception:
                    row["metadata"] = {}
            return rows

    def get_agents(self) -> List[Dict[str, Any]]:
        """Retrieves all registered endpoints with their evaluated connection and risk states."""
        now = datetime.now(timezone.utc)
        with self.db.get_connection() as conn:
            agents = [dict(row) for row in conn.execute("SELECT * FROM agents ORDER BY name")]
            for agent in agents:
                try:
                    last_seen_dt = datetime.fromisoformat(agent["last_seen"])
                    if last_seen_dt.tzinfo is None:
                        last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
                    age = (now - last_seen_dt).total_seconds()
                except Exception:
                    age = 999999

                # Determine status accurately
                if age >= 120:
                    agent["connection_state"] = "OFFLINE"
                    agent["status"] = "DISCONNECTED"
                elif agent.get("connection_state") in ("ISOLATED", "RECONNECTING", "SYNCING", "DEGRADED", "OFFLINE"):
                    agent["status"] = agent["connection_state"]
                elif age < 120:
                    agent["status"] = "ACTIVE"
                else:
                    agent["status"] = "DISCONNECTED"

                row = conn.execute(
                    "SELECT new_score FROM risk_history WHERE agent_id=? ORDER BY timestamp DESC, id DESC LIMIT 1",
                    (agent["id"],),
                ).fetchone()
                agent["risk_score"] = row[0] if row else None
                score = agent["risk_score"] or 0
                agent["risk_level"] = (
                    "CRITICAL" if score >= 85 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
                )

                if row is None:
                    agent["risk_level"] = "UNASSESSED"

                # Active incidents count
                inc_count = conn.execute(
                    "SELECT COUNT(*) FROM incidents WHERE agent_id=? AND status NOT IN ('CLOSED', 'RESOLVED')",
                    (agent["id"],),
                ).fetchone()[0]
                agent["active_alerts_count"] = inc_count

            return agents
