"""ZTA Declarative Policy & Adaptive Decision Engine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from zta.engine.events.conditions import ConditionEvaluator


POLICY_ACTIONS = {"MONITOR", "ALERT", "NOTIFY_SOC", "LOGOUT_USER", "LOGOFF_USER", "KILL_PROCESS", "ISOLATE_ENDPOINT"}
POLICY_MODES = {"ALERT_ONLY", "ENFORCE"}
POLICY_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class PolicyValidator:
    """Validates persisted policy definitions at every mutation boundary."""

    def __init__(self):
        self.evaluator = ConditionEvaluator()

    def validate(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(policy, dict):
            raise ValueError("Policy must be an object")
        for field, maximum in (("code", 64), ("name", 160)):
            value = policy.get(field)
            if not isinstance(value, str) or not value.strip() or len(value) > maximum:
                raise ValueError(f"{field} must be a non-empty string up to {maximum} characters")
        for field in ("category", "description", "rule_id"):
            value = policy.get(field)
            if value is not None and (not isinstance(value, str) or len(value) > 1000):
                raise ValueError(f"{field} must be a string up to 1000 characters")
        if policy.get("severity", "HIGH") not in POLICY_SEVERITIES:
            raise ValueError("Unknown policy severity")
        if policy.get("mode", "ENFORCE") not in POLICY_MODES:
            raise ValueError("Unknown policy mode")
        if policy.get("action", "MONITOR") not in POLICY_ACTIONS:
            raise ValueError("Unknown policy action")
        for field in ("min_risk", "max_risk", "risk_threshold"):
            value = policy.get(field, 0 if field == "min_risk" else 100)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
                raise ValueError(f"{field} must be an integer from 0 through 100")
        if policy.get("min_risk", 0) > policy.get("max_risk", 100):
            raise ValueError("min_risk cannot exceed max_risk")
        priority = policy.get("priority", 1000)
        if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 10000:
            raise ValueError("priority must be an integer from 0 through 10000")
        for field in ("enabled", "allow_offline"):
            if policy.get(field, False) not in (True, False, 0, 1):
                raise ValueError(f"{field} must be a boolean")
        condition = policy.get("condition")
        if condition is None and policy.get("condition_json"):
            condition = policy["condition_json"]
        if condition:
            self.evaluator.validate(condition)
        return policy


def policy_sort_key(policy: Union["ZTAPolicy", Dict[str, Any]]):
    value = lambda key, default=None: getattr(policy, key, default) if isinstance(policy, ZTAPolicy) else policy.get(key, default)
    return (int(value("priority", 1000)), str(value("code", "")).casefold(), str(value("policy_id", "")).casefold())


class PolicyEvaluationMode(str, Enum):
    """Execution mode for security policies."""
    ALERT_ONLY = "ALERT_ONLY"
    ENFORCE = "ENFORCE"


@dataclass
class PolicyDecision:
    """Represents a decision output from policy evaluation."""
    decision_id: str
    policy_name: str
    agent_id: str
    action: str  # MONITOR, ALERT, NOTIFY_SOC, CONTAIN, ISOLATE_ENDPOINT, LOGOUT_USER, KILL_PROCESS
    reason: str
    trigger_risk_score: int
    trigger_trust_score: int
    policy_id: Optional[str] = None
    policy_code: Optional[str] = None
    mode: str = "ENFORCE"  # ALERT_ONLY vs ENFORCE
    evaluation_result: str = "TRIGGERED"
    triggered: bool = True
    condition_trace: Optional[Dict[str, Any]] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ZTAPolicy:
    """Declarative security policy rule."""
    policy_id: str
    name: str
    min_risk: int
    max_risk: int
    action: str
    enabled: bool = True
    code: Optional[str] = None
    category: str = "general"
    severity: str = "HIGH"
    rule_id: Optional[str] = None
    risk_threshold: int = 85
    mode: str = "ENFORCE"  # ALERT_ONLY or ENFORCE
    condition: Optional[Dict[str, Any]] = None
    allow_offline: bool = False
    priority: int = 1000


class ZTAPolicyEngine:
    """Evaluates endpoint risk/trust metrics against policies to select adaptive response actions."""

    def __init__(self, policies: Optional[List[ZTAPolicy]] = None):
        self.evaluator = ConditionEvaluator()
        self.policies: List[ZTAPolicy] = policies if policies is not None else [
            ZTAPolicy("pol-001", "Baseline Monitoring", 0, 29, "MONITOR", True, code="POL-001", mode="ALERT_ONLY"),
            ZTAPolicy("pol-002", "Medium Risk Alert", 30, 59, "ALERT", True, code="POL-002", mode="ALERT_ONLY"),
            ZTAPolicy("pol-003", "High Risk SOC Escalation", 60, 84, "NOTIFY_SOC", True, code="POL-003", mode="ALERT_ONLY"),
            ZTAPolicy("pol-004", "Critical Risk Containment", 85, 100, "ISOLATE_ENDPOINT", True, code="POL-004", mode="ENFORCE"),
            ZTAPolicy("pol-005", "Critical Login & Session Protection", 85, 100, "LOGOUT_USER", True, code="POL-LOGOUT-001", mode="ENFORCE", allow_offline=True),
        ]

    def evaluate_single_policy(
        self,
        policy: Union[ZTAPolicy, Dict[str, Any]],
        context: Dict[str, Any],
    ) -> PolicyDecision:
        """Evaluates a single policy against a specific context dict."""
        def value(key, default=None):
            return getattr(policy, key, default) if isinstance(policy, ZTAPolicy) else policy.get(key, default)
        linked = value("rule_id")
        eligible = bool(value("enabled", True)) and (not linked or linked in (context.get("rule_id"), context.get("rule_code")))
        mode = value("mode", "ALERT_ONLY")
        eligible = eligible and mode in ("ALERT_ONLY", "ENFORCE")
        if context.get("execution_source") == "AGENT_OFFLINE":
            eligible = eligible and bool(value("allow_offline", False))
        condition = value("condition") or value("condition_tree")
        if condition is None:
            condition = {"all": [
                {"field": "risk_score", "op": "gte", "value": value("min_risk", 0)},
                {"field": "risk_score", "op": "lte", "value": value("max_risk", 100)}]}
        try:
            trace = self.evaluator.explain(condition, context)
            triggered = eligible and trace["result"]
            reason = "Condition matched" if triggered else "Conditions or policy eligibility not met"
        except (ValueError, TypeError) as exc:
            trace, triggered, reason = {"result": False, "error": str(exc)}, False, str(exc)
        trace = {"logic": "AND", "children": [{"field": "policy_eligibility", "actual": eligible, "result": eligible}, trace], "result": triggered}
        return PolicyDecision(
            decision_id=f"dec-{uuid4().hex}", policy_id=value("policy_id"),
            policy_code=value("code") or value("policy_id"), policy_name=value("name", ""),
            agent_id=str(context.get("agent_id", "")), action=value("action", "MONITOR"),
            reason=reason, trigger_risk_score=context.get("risk_score", 0),
            trigger_trust_score=context.get("trust_score", 100), mode=mode,
            evaluation_result="TRIGGERED" if triggered else "NOT_TRIGGERED",
            triggered=triggered, condition_trace=trace)

    def evaluate(self, agent_id: str, risk_score: int, trust_score: int, context: Optional[Dict[str, Any]] = None) -> Optional[PolicyDecision]:
        """Evaluates policies against agent risk/trust scores and context, returning a deterministic PolicyDecision."""
        eval_context = {**(context or {}), "agent_id": agent_id,
                        "risk_score": risk_score, "trust_score": trust_score}
        policies = sorted(self.policies, key=policy_sort_key)
        for policy in policies:
            decision = self.evaluate_single_policy(policy, eval_context)
            if decision.triggered:
                return decision
        return None
