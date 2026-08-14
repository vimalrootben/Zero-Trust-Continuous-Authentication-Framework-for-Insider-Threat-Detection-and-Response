# This file registers all ORM models so that Base.metadata contains every table.
# Import order matters — mitre and policy_group must come before models that FK to them.

from manager.database.models.auth import Permission, Role, User, Session, role_permissions
from manager.database.models.mitre import MitreTactic, MitreTechnique
from manager.database.models.policy import PolicyGroup, Policy
from manager.database.models.rule import ResponseTemplate, Rule
from manager.database.models.agent import Agent, EnrollmentToken, Heartbeat, OfflineSyncLog
from manager.database.models.telemetry import TelemetryEvent
from manager.database.models.risk import RiskScore
from manager.database.models.command import Command
from manager.database.models.alert import Alert, AlertStatus
from manager.database.models.alert_response import AlertResponse, AlertResponseStatus, AlertResponseAction
from manager.database.models.incident import Incident, incident_alerts
from manager.database.models.timeline import TimelineEvent
from manager.database.models.threat_intel import ThreatIntelIndicator
from manager.database.models.audit import AuditLog

__all__ = [
    "Permission", "Role", "User", "Session", "role_permissions",
    "MitreTactic", "MitreTechnique",
    "PolicyGroup", "Policy",
    "ResponseTemplate", "Rule",
    "Agent", "EnrollmentToken", "Heartbeat", "OfflineSyncLog",
    "TelemetryEvent",
    "RiskScore",
    "Command",
    "Alert", "AlertStatus",
    "AlertResponse", "AlertResponseStatus", "AlertResponseAction",
    "Incident", "incident_alerts",
    "TimelineEvent",
    "ThreatIntelIndicator",
    "AuditLog",
]
