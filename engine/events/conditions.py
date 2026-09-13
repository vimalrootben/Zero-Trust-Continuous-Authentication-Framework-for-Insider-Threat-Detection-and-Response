"""Shared, explainable condition trees from blueprint M8/M11/A13."""

import json
import regex
from typing import Any


class InvalidConditionError(ValueError):
    """A condition cannot be evaluated safely or has an invalid shape."""


class ConditionEvaluator:
    """Evaluate every branch so the trace contains actual AND/OR/NOT results."""

    OPERATORS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in",
                 "contains", "contains_icase", "regex", "exists", "not_exists"}

    MAX_DEPTH = 8
    MAX_NODES = 128
    MAX_GROUP_CHILDREN = 32
    MAX_MEMBERSHIP_VALUES = 100
    MAX_FIELD_LENGTH = 128
    MAX_REGEX_LENGTH = 512
    MAX_REGEX_INPUT_LENGTH = 4096
    REGEX_TIMEOUT_SECONDS = 0.025

    def validate(self, condition: dict) -> None:
        """Reject ambiguous, empty, unsupported, or malformed conditions."""
        counter = [0]
        self._validate(condition, 1, counter)

    def _validate(self, condition: dict, depth: int, counter: list) -> None:
        if depth > self.MAX_DEPTH:
            raise InvalidConditionError(f"Condition tree exceeds maximum depth {self.MAX_DEPTH}")
        counter[0] += 1
        if counter[0] > self.MAX_NODES:
            raise InvalidConditionError(f"Condition tree exceeds maximum {self.MAX_NODES} nodes")
        if not isinstance(condition, dict) or not condition:
            raise InvalidConditionError("Condition must be a nonempty object")
        groups = set(condition) & {"all", "any", "not"}
        if groups:
            if len(condition) != 1:
                raise InvalidConditionError("A combinator must be the only key")
            group = next(iter(groups))
            children = condition[group]
            if group == "not":
                self._validate(children, depth + 1, counter)
            else:
                if not isinstance(children, list) or not children:
                    raise InvalidConditionError("AND/OR requires a nonempty array")
                if len(children) > self.MAX_GROUP_CHILDREN:
                    raise InvalidConditionError(f"AND/OR supports at most {self.MAX_GROUP_CHILDREN} children")
                for child in children:
                    self._validate(child, depth + 1, counter)
            return
        if set(condition) - {"field", "op", "value"}:
            raise InvalidConditionError("Unknown condition keys")
        if not isinstance(condition.get("field"), str) or not condition["field"]:
            raise InvalidConditionError("A field path is required")
        if len(condition["field"]) > self.MAX_FIELD_LENGTH or any(not part for part in condition["field"].split(".")):
            raise InvalidConditionError("Invalid or overlong field path")
        op = condition.get("op")
        if not isinstance(op, str) or op not in self.OPERATORS:
            raise InvalidConditionError("Unsupported operator")
        if op not in {"exists", "not_exists"} and "value" not in condition:
            raise InvalidConditionError("A comparison value is required")
        value = condition.get("value")
        if op in {"in", "not_in"}:
            if not isinstance(value, list) or not value:
                raise InvalidConditionError("Membership requires a nonempty array")
            if len(value) > self.MAX_MEMBERSHIP_VALUES or any(isinstance(item, (dict, list)) for item in value):
                raise InvalidConditionError("Membership array is too large or contains structured values")
        elif op in {"gt", "gte", "lt", "lte"} and (isinstance(value, bool) or not isinstance(value, (int, float))):
            raise InvalidConditionError("Ordered comparison requires a number")
        elif op in {"contains", "contains_icase", "regex"} and not isinstance(value, str):
            raise InvalidConditionError(f"{op} requires a string")
        elif op not in {"exists", "not_exists"} and isinstance(value, (dict, list)):
            raise InvalidConditionError("Comparison value must be a scalar")
        if op == "regex":
            if len(value) > self.MAX_REGEX_LENGTH:
                raise InvalidConditionError(f"Regular expression exceeds {self.MAX_REGEX_LENGTH} characters")
            try:
                regex.compile(value)
            except (regex.error, TypeError) as exc:
                raise InvalidConditionError("Invalid regular expression") from exc


    def evaluate(self, condition: dict, event_data: dict) -> bool:
        """Return the real final result; use explain() for all branch results."""
        return self.explain(condition, event_data)["result"]

    def explain(self, condition: dict, event_data: dict) -> dict:
        """Evaluate against telemetry and return a serializable evidence tree."""
        self.validate(condition)
        return self._evaluate(condition, event_data)

    def _evaluate(self, condition: dict, data: dict) -> dict:
        for group in ("all", "any", "not"):
            if group in condition:
                nodes = [condition[group]] if group == "not" else condition[group]
                children = [self._evaluate(node, data) for node in nodes]
                values = [child["result"] for child in children]
                result = all(values) if group == "all" else any(values) if group == "any" else not values[0]
                return {"logic": {"all": "AND", "any": "OR", "not": "NOT"}[group],
                        "children": children, "result": result}
        actual: Any = data
        present = True
        for segment in condition["field"].split("."):
            if not isinstance(actual, dict) or segment not in actual:
                actual, present = None, False
                break
            actual = actual[segment]
        op, expected = condition["op"], condition.get("value")
        evaluation_error = None
        if op == "exists":
            result = present and actual is not None
        elif op == "not_exists":
            result = not present or actual is None
        elif not present or actual is None:
            result = False
        else:
            try:
                if op == "eq": result = actual == expected
                elif op == "ne": result = actual != expected
                elif op == "gt": result = actual > expected
                elif op == "gte": result = actual >= expected
                elif op == "lt": result = actual < expected
                elif op == "lte": result = actual <= expected
                elif op == "in": result = actual in expected
                elif op == "not_in": result = actual not in expected
                elif op == "contains": result = expected in actual
                elif op == "contains_icase": result = expected.casefold() in actual.casefold()
                else:
                    if not isinstance(actual, str):
                        result = False
                    elif len(actual) > self.MAX_REGEX_INPUT_LENGTH:
                        result, evaluation_error = False, "REGEX_INPUT_LIMIT"
                    else:
                        try:
                            result = regex.search(expected, actual, timeout=self.REGEX_TIMEOUT_SECONDS) is not None
                        except TimeoutError:
                            result, evaluation_error = False, "REGEX_TIMEOUT"
            except (TypeError, AttributeError):
                result = False
        trace = {"field": condition["field"], "op": op, "expected": expected,
                 "actual": actual, "present": present, "result": bool(result)}
        if evaluation_error: trace["evaluation_error"] = evaluation_error
        return trace


class RuleValidator:
    """Validate complete rule definitions before persistence or activation."""

    SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    CATEGORIES = {"Authentication", "Execution", "Persistence", "Privilege Escalation",
                  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                  "Collection", "Exfiltration", "Command and Control", "General", "DEMO"}
    RESPONSE_ACTIONS = {"MONITOR", "ALERT", "NOTIFY_SOC", "LOGOUT_USER", "LOGOFF_USER",
                        "KILL_PROCESS", "ISOLATE_ENDPOINT"}
    LOGIC_TYPES = {"CONDITION_TREE"}

    def __init__(self):
        self.conditions = ConditionEvaluator()

    @staticmethod
    def _required_text(rule, field, maximum):
        value = rule.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise ValueError(f"{field} must be a nonempty string up to {maximum} characters")

    @staticmethod
    def _flag(rule, field):
        value = rule.get(field)
        if not isinstance(value, bool) and not (isinstance(value, int) and value in (0, 1)):
            raise ValueError(f"{field} must be boolean or 0/1")

    def validate(self, rule):
        if not isinstance(rule, dict):
            raise ValueError("Rule must be an object")
        self._required_text(rule, "code", 64)
        self._required_text(rule, "name", 160)
        for field in ("description", "mitre_tactic", "mitre_technique_id"):
            value = rule.get(field)
            if value is not None and (not isinstance(value, str) or len(value) > 1000):
                raise ValueError(f"{field} must be a string")
        for field, allowed in (("category", self.CATEGORIES), ("severity", self.SEVERITIES),
                               ("response_action", self.RESPONSE_ACTIONS), ("logic_type", self.LOGIC_TYPES)):
            if rule.get(field) not in allowed:
                raise ValueError(f"Invalid {field}: {rule.get(field)!r}")
        risk = rule.get("risk_delta")
        if isinstance(risk, bool) or not isinstance(risk, int) or not 0 <= risk <= 100:
            raise ValueError("risk_delta must be an integer between 0 and 100")
        self._flag(rule, "enabled")
        self._flag(rule, "allow_offline")
        condition = rule.get("condition")
        if condition is None and isinstance(rule.get("condition_json"), str):
            try:
                condition = json.loads(rule["condition_json"])
            except Exception as exc:
                raise ValueError("condition_json must contain valid JSON") from exc
        self.conditions.validate(condition)
        return rule
