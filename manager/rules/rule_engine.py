"""
RuleEngine (M8) — Evaluates incoming telemetry events against dynamic, tree-structured rules.

Design:
  - Maintains an in-memory rule cache refreshed via reload_rule_cache().
  - Evaluates telemetry events using ConditionEvaluator.
  - On match: triggers alert creation, applies risk score deltas, attaches MITRE technique IDs.
"""
import logging
from typing import Any, Dict, List, Optional

from manager.rules.conditions import ConditionEvaluator
from manager.rules.rule_loader import RuleDTO, RuleLoader

logger = logging.getLogger(__name__)


class RuleMatchResult:
    """Represents a single rule match against a telemetry event."""

    def __init__(
        self,
        rule_code: str,
        name: str,
        severity: str,
        score_impact: int,
        mitre_technique_id: Optional[str] = None,
        response_action: Optional[str] = None,
    ) -> None:
        self.rule_code = rule_code
        self.name = name
        self.severity = severity
        self.score_impact = score_impact
        self.mitre_technique_id = mitre_technique_id
        self.response_action = response_action


class RuleEngine:
    """Core detection engine for processing telemetry events."""

    def __init__(
        self,
        rules_dir: Optional[str] = None,
        risk_engine: Optional[Any] = None,
        alert_service: Optional[Any] = None,
    ) -> None:
        self.rules_dir = rules_dir
        self.risk_engine = risk_engine
        self.alert_service = alert_service
        self.loader = RuleLoader()
        self.evaluator = ConditionEvaluator()
        self._rules_cache: List[RuleDTO] = []
        self.reload_rule_cache()

    def reload_rule_cache(self, rules_override: Optional[List[RuleDTO]] = None) -> None:
        """Reload in-memory rule cache from directory or explicit list."""
        if rules_override is not None:
            self._rules_cache = rules_override
        elif self.rules_dir:
            self._rules_cache = self.loader.load_rules_from_files(self.rules_dir)
        else:
            self._rules_cache = []
        logger.info(f"RuleEngine cache reloaded with {len(self._rules_cache)} rules.")

    def add_rule(self, rule: RuleDTO) -> None:
        """Add a rule to the active in-memory cache."""
        self._rules_cache.append(rule)

    def evaluate_event(self, event_data: dict, agent_id: Optional[str] = None) -> List[RuleMatchResult]:
        """
        Evaluate event_data against all active rules in cache.

        Args:
            event_data: Telemetry event dictionary.
            agent_id: UUID string of the agent that produced the event.

        Returns:
            List of RuleMatchResult for matching rules.
        """
        matches: List[RuleMatchResult] = []

        for rule in self._rules_cache:
            if not rule.enabled:
                continue

            try:
                if self.evaluator.evaluate(rule.condition, event_data):
                    match = RuleMatchResult(
                        rule_code=rule.rule_code,
                        name=rule.name,
                        severity=rule.severity,
                        score_impact=rule.score_impact,
                        mitre_technique_id=rule.mitre_technique_id,
                        response_action=rule.response_action,
                    )
                    matches.append(match)
                    logger.info(f"Rule match: {rule.rule_code} ('{rule.name}') on agent {agent_id}")

                    # Apply risk delta if risk engine provided
                    if self.risk_engine and agent_id and hasattr(self.risk_engine, "apply_delta"):
                        try:
                            self.risk_engine.apply_delta(
                                agent_id=agent_id,
                                delta=rule.score_impact,
                                reason=f"Matched {rule.rule_code}: {rule.name}",
                                rule_id=rule.rule_id,
                            )
                        except Exception as e:
                            logger.error(f"Error applying risk delta for rule {rule.rule_code}: {e}")

                    # Create alert if alert service provided
                    if self.alert_service and hasattr(self.alert_service, "create_alert"):
                        try:
                            self.alert_service.create_alert(
                                agent_id=agent_id,
                                title=rule.name,
                                description=f"Rule {rule.rule_code} matched telemetry event.",
                                severity=rule.severity,
                                mitre_technique_id=rule.mitre_technique_id,
                            )
                        except Exception as e:
                            logger.error(f"Error creating alert for rule {rule.rule_code}: {e}")

            except Exception as exc:
                logger.error(f"Error evaluating rule {rule.rule_code}: {exc}")
                continue

        return matches
