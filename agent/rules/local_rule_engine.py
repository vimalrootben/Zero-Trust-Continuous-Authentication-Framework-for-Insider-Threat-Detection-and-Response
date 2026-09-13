"""ZTA Agent Local Rule Engine (Blueprint Module A13)."""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from zta.engine.events.models import ZTAEvent
from zta.engine.events.conditions import ConditionEvaluator
import logging


@dataclass
class LocalMatch:
    """Represents a local rule match on the agent."""
    rule_id: str
    rule_name: str
    severity: str
    description: str


class LocalRuleEngine:
    """Evaluates telemetry events against local rule definitions on the agent."""

    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None):
        self.rules = rules if rules is not None else self._get_default_local_rules()
        self.evaluator = ConditionEvaluator()
        for rule in self.rules:
            if isinstance(rule.get("condition"), dict):
                self.evaluator.validate(rule["condition"])

    def _get_default_local_rules(self) -> List[Dict[str, Any]]:
        """Returns baseline local high-confidence detection rules."""
        return [
            {
                "rule_id": "LOC-RULE-001",
                "name": "Encoded PowerShell Execution",
                "severity": "HIGH",
                "condition": {"all": [{"field": "process.name", "op": "contains_icase", "value": "powershell"}, {"any": [{"field": "process.command_line", "op": "contains_icase", "value": "-enc"}, {"field": "process.command_line", "op": "contains_icase", "value": "-encodedcommand"}]}]},
                "description": "Suspicious encoded PowerShell command line detected locally",
            },
            {
                "rule_id": "LOC-RULE-002",
                "name": "AV Process Termination Attempt",
                "severity": "CRITICAL",
                "condition": {"all": [{"field": "event_type", "op": "in", "value": ["PROCESS_TERMINATION", "PROCESS_TERMINATION_ATTEMPT"]}, {"any": [{"field": "process.name", "op": "contains_icase", "value": proc} for proc in ["MsMpEng.exe", "windefend", "zta-agent"]]}]},
                "description": "Attempt to terminate security or agent process",
            },
        ]

    def evaluate(self, event: ZTAEvent) -> Optional[LocalMatch]:
        """Evaluates a ZTAEvent against local rules safely.
        
        Returns:
            LocalMatch if a rule condition triggers, else None.
        """
        for rule in self.rules:
            try:
                condition_func = rule.get("condition")
                if not rule.get("enabled", True):
                    continue
                matched = (self.evaluator.evaluate(condition_func, asdict(event))
                           if isinstance(condition_func, dict) else callable(condition_func) and condition_func(event))
                if matched:
                    return LocalMatch(
                        rule_id=rule["rule_id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        description=rule.get("description", ""),
                    )
            except Exception:
                logging.getLogger(__name__).exception("local_rule.evaluation_failed", extra={"rule_id": rule.get("rule_id")})
                continue
        return None
