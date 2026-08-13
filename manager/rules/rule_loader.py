"""
RuleLoader — Loads, validates, and parses detection rules from DB and YAML rule files.
"""
import logging
import os
from typing import Any, Dict, List, Optional
import yaml

from manager.rules.conditions import ConditionEvaluator, InvalidConditionError

logger = logging.getLogger(__name__)


class InvalidRuleError(Exception):
    """Raised when a rule structure or condition is invalid."""
    pass


class RuleDTO:
    """In-memory representation of a validated detection rule."""

    def __init__(
        self,
        rule_code: str,
        name: str,
        category: str,
        severity: str,
        condition: dict,
        score_impact: int = 10,
        mitre_technique_id: Optional[str] = None,
        response_action: Optional[str] = None,
        enabled: bool = True,
        false_positive_notes: Optional[str] = None,
        references: Optional[List[str]] = None,
        rule_id: Optional[str] = None,
    ) -> None:
        self.rule_id = rule_id
        self.rule_code = rule_code
        self.name = name
        self.category = category
        self.severity = severity
        self.condition = condition
        self.score_impact = score_impact
        self.mitre_technique_id = mitre_technique_id
        self.response_action = response_action
        self.enabled = enabled
        self.false_positive_notes = false_positive_notes
        self.references = references or []


class RuleLoader:
    """Loads and validates detection rules."""

    def __init__(self) -> None:
        self.evaluator = ConditionEvaluator()

    def validate_rule(self, rule_dict: dict) -> None:
        """
        Validate rule fields and condition tree structure.
        Raises InvalidRuleError on invalid structures.
        """
        required_fields = ["rule_code", "name", "category", "severity", "condition"]
        for f in required_fields:
            if f not in rule_dict or not rule_dict[f]:
                raise InvalidRuleError(f"Missing required field '{f}' in rule definition.")

        valid_severities = {"low", "medium", "high", "critical"}
        if str(rule_dict["severity"]).lower() not in valid_severities:
            raise InvalidRuleError(f"Invalid severity '{rule_dict['severity']}'. Must be one of {valid_severities}")

        # Validate condition tree by dry-evaluating against an empty dict
        try:
            self.evaluator.evaluate(rule_dict["condition"], {})
        except InvalidConditionError as e:
            raise InvalidRuleError(f"Malformed condition tree in rule {rule_dict.get('rule_code')}: {e}")

    def load_rules_from_files(self, directory: str) -> List[RuleDTO]:
        """
        Load all .yaml / .yml rule definitions from directory.
        """
        rules: List[RuleDTO] = []
        if not os.path.exists(directory):
            logger.warning(f"Rules directory '{directory}' does not exist.")
            return rules

        for filename in sorted(os.listdir(directory)):
            if filename.endswith((".yaml", ".yml")):
                filepath = os.path.join(directory, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        self.validate_rule(data)
                        rules.append(
                            RuleDTO(
                                rule_code=data["rule_code"],
                                name=data["name"],
                                category=data["category"],
                                severity=data["severity"],
                                condition=data["condition"],
                                score_impact=data.get("score_impact", 10),
                                mitre_technique_id=data.get("mitre_technique_id"),
                                response_action=data.get("response_action"),
                                enabled=data.get("enabled", True),
                                false_positive_notes=data.get("false_positive_notes"),
                                references=data.get("references", []),
                            )
                        )
                except Exception as e:
                    logger.error(f"Error loading rule file '{filename}': {e}")
                    continue

        logger.info(f"Loaded {len(rules)} rules from YAML files in {directory}.")
        return rules
