"""Shared, explainable condition trees from blueprint M8/M11/A13."""

import re
from typing import Any


class InvalidConditionError(ValueError):
    """A condition cannot be evaluated safely or has an invalid shape."""


class ConditionEvaluator:
    """Evaluate every branch so the trace contains actual AND/OR/NOT results."""

    OPERATORS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in",
                 "contains", "contains_icase", "regex", "exists", "not_exists"}

    def validate(self, condition: dict) -> None:
        """Reject ambiguous, empty, unsupported, or malformed conditions."""
        if not isinstance(condition, dict) or not condition:
            raise InvalidConditionError("Condition must be a nonempty object")
        groups = set(condition) & {"all", "any", "not"}
        if groups:
            if len(condition) != 1:
                raise InvalidConditionError("A combinator must be the only key")
            group = next(iter(groups))
            children = condition[group]
            if group == "not":
                self.validate(children)
            else:
                if not isinstance(children, list) or not children:
                    raise InvalidConditionError("AND/OR requires a nonempty array")
                for child in children:
                    self.validate(child)
            return
        if set(condition) - {"field", "op", "value"}:
            raise InvalidConditionError("Unknown condition keys")
        if not isinstance(condition.get("field"), str) or not condition["field"]:
            raise InvalidConditionError("A field path is required")
        op = condition.get("op")
        if not isinstance(op, str) or op not in self.OPERATORS:
            raise InvalidConditionError("Unsupported operator")
        if op not in {"exists", "not_exists"} and "value" not in condition:
            raise InvalidConditionError("A comparison value is required")
        if op in {"in", "not_in"} and not isinstance(condition["value"], list):
            raise InvalidConditionError("Membership requires an array")
        if op == "regex":
            try:
                re.compile(condition["value"])
            except (re.error, TypeError) as exc:
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
                else: result = re.search(expected, actual) is not None
            except (TypeError, AttributeError):
                result = False
        return {"field": condition["field"], "op": op, "expected": expected,
                "actual": actual, "present": present, "result": bool(result)}
