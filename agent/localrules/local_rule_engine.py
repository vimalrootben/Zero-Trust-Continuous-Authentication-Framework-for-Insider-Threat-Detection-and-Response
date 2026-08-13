"""
LocalRuleEngine (A13) — Agent-side lightweight evaluator for local severity annotation.

Design:
  - Evaluates local rules against TelemetryEventDTO instances.
  - Reuses the ConditionEvaluator tree matching logic.
  - Does NOT create alerts locally (alerts are managed by the server).
  - Annotates events with local severity tags or matches.
"""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from agent.storage.models import TelemetryEventDTO
from manager.rules.conditions import ConditionEvaluator


@dataclass
class LocalMatch:
    rule_code: str
    name: str
    severity: str
    score_impact: int


class LocalRuleEngine:
    """Agent-side lightweight rule evaluator."""

    def __init__(self, local_rules: Optional[List[dict]] = None) -> None:
        self.local_rules = local_rules or []
        self.evaluator = ConditionEvaluator()

    def load_rules(self, rules: List[dict]) -> None:
        self.local_rules = rules

    def evaluate(self, event: TelemetryEventDTO) -> Optional[LocalMatch]:
        """
        Evaluate an event against local rules and return the highest severity LocalMatch.
        """
        event_dict = event.to_dict()

        matched: List[LocalMatch] = []
        for rule in self.local_rules:
            if not rule.get("enabled", True):
                continue
            cond = rule.get("condition", {})
            try:
                if self.evaluator.evaluate(cond, event_dict):
                    matched.append(
                        LocalMatch(
                            rule_code=rule.get("rule_code", "LOCAL-000"),
                            name=rule.get("name", "Local Detection"),
                            severity=rule.get("severity", "medium"),
                            score_impact=rule.get("score_impact", 10),
                        )
                    )
            except Exception:
                continue

        if not matched:
            return None

        # Return match with highest score impact
        return max(matched, key=lambda m: m.score_impact)
