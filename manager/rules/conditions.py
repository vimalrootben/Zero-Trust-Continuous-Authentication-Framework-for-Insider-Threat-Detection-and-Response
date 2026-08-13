"""
ConditionEvaluator — Evaluates nested, tree-structured boolean condition dictionaries against flattened telemetry event data.

Supported Operators:
  eq, ne, gt, gte, lt, lte, in, not_in, contains, contains_icase, regex, exists, not_exists, ioc_match

Supported Combinators:
  all (AND list), any (OR list), not (negation dict/list)
"""
import fnmatch
import re
from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from manager.threatintel.cache import ThreatIntelCache


class InvalidConditionError(Exception):
    """Raised when a condition tree is malformed or uses an unknown operator/combinator."""
    pass


class ConditionEvaluator:
    """Evaluates rule condition trees against event dictionary objects."""

    OPERATORS = {
        "eq", "ne", "gt", "gte", "lt", "lte",
        "==", "!=", ">", ">=", "<", "<=",
        "in", "not_in", "contains", "contains_icase",
        "startswith", "startswith_icase", "endswith", "endswith_icase", "wildcard",
        "regex", "exists", "not_exists", "ioc_match"
    }

    def __init__(self, threat_intel_cache: Optional["ThreatIntelCache"] = None):
        self._threat_intel_cache = threat_intel_cache

    def set_threat_intel_cache(self, cache: "ThreatIntelCache") -> None:
        """Inject ThreatIntelCache after construction (avoids circular deps)."""
        self._threat_intel_cache = cache

    def evaluate(self, condition: dict, event_data: dict) -> bool:
        """
        Recursively evaluate condition tree against event_data.

        Args:
            condition: Dictionary representing condition node or leaf.
            event_data: Flattened or nested dict representing event attributes.

        Returns:
            bool: True if condition matches event_data, False otherwise.
        """
        if not isinstance(condition, dict):
            raise InvalidConditionError(f"Condition node must be a dict, got {type(condition)}")

        if not condition:
            return True

        # Check combinators first
        if "all" in condition:
            items = condition["all"]
            if not isinstance(items, list):
                raise InvalidConditionError("'all' combinator must contain a list of conditions")
            return all(self.evaluate(sub_cond, event_data) for sub_cond in items)

        if "any" in condition:
            items = condition["any"]
            if not isinstance(items, list):
                raise InvalidConditionError("'any' combinator must contain a list of conditions")
            return any(self.evaluate(sub_cond, event_data) for sub_cond in items)

        if "not" in condition:
            sub = condition["not"]
            if isinstance(sub, list):
                return not all(self.evaluate(s, event_data) for s in sub)
            elif isinstance(sub, dict):
                return not self.evaluate(sub, event_data)
            else:
                raise InvalidConditionError("'not' combinator must contain a dict or list")

        # Leaf condition evaluation
        field_path = condition.get("field")
        op = condition.get("op") or condition.get("operator")
        target_val = condition.get("value")

        if not field_path or not op:
            raise InvalidConditionError("Leaf condition missing required 'field' or 'op' keys")

        if op not in self.OPERATORS:
            raise InvalidConditionError(f"Unsupported operator '{op}'. Supported: {self.OPERATORS}")

        actual_val = self._resolve_field(field_path, event_data)
        return self._compare(op, actual_val, target_val)

    def _resolve_field(self, field_path: str, data: dict) -> Any:
        """Resolve dot-notated field path in data (e.g. 'data.process_name')."""
        curr = data
        for part in field_path.split("."):
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return None
        return curr

    def _compare(self, op: str, actual: Any, target: Any) -> bool:
        if op == "exists":
            return actual is not None
        if op == "not_exists":
            return actual is None

        if actual is None:
            return False

        if op in ("eq", "=="):
            return actual == target
        if op in ("ne", "!="):
            return actual != target
        if op in ("gt", ">"):
            return actual > target
        if op in ("gte", ">="):
            return actual >= target
        if op in ("lt", "<"):
            return actual < target
        if op in ("lte", "<="):
            return actual <= target
        if op == "in":
            if isinstance(target, (list, tuple, set)):
                return actual in target
            return str(actual) in str(target)
        if op == "not_in":
            if isinstance(target, (list, tuple, set)):
                return actual not in target
            return str(actual) not in str(target)
        if op == "contains":
            if isinstance(actual, (list, tuple, set)):
                return target in actual
            return str(target) in str(actual)
        if op == "contains_icase":
            if isinstance(actual, (list, tuple, set)):
                target_str = str(target).lower()
                return any(target_str in str(item).lower() for item in actual)
            return str(target).lower() in str(actual).lower()
        if op == "startswith":
            return str(actual).startswith(str(target))
        if op == "startswith_icase":
            return str(actual).lower().startswith(str(target).lower())
        if op == "endswith":
            return str(actual).endswith(str(target))
        if op == "endswith_icase":
            return str(actual).lower().endswith(str(target).lower())
        if op == "wildcard":
            return fnmatch.fnmatch(str(actual).lower(), str(target).lower())
        if op == "regex":
            try:
                return bool(re.search(str(target), str(actual), re.IGNORECASE))
            except Exception as e:
                raise InvalidConditionError(f"Invalid regex pattern '{target}': {e}")
        if op == "ioc_match":
            # target = ioc_type (e.g. "ip", "domain", "hash_sha256")
            if self._threat_intel_cache is None:
                return False
            result = self._threat_intel_cache.is_known_bad(str(target), str(actual))
            return result is not None

        return False
