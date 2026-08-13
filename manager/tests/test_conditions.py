"""
Unit tests for ConditionEvaluator.
"""
import pytest
from manager.rules.conditions import ConditionEvaluator, InvalidConditionError


def test_condition_evaluator_operators():
    evaluator = ConditionEvaluator()
    data = {
        "collector_type": "process",
        "data": {
            "process_name": "powershell.exe",
            "pid": 1234,
            "command_line": "powershell.exe -enc AAAAA==",
            "signed": False,
            "tags": ["admin", "script"],
        }
    }

    # eq / ne
    assert evaluator.evaluate({"field": "collector_type", "op": "eq", "value": "process"}, data)
    assert evaluator.evaluate({"field": "collector_type", "op": "ne", "value": "network"}, data)

    # gt / lte
    assert evaluator.evaluate({"field": "data.pid", "op": "gt", "value": 1000}, data)
    assert evaluator.evaluate({"field": "data.pid", "op": "lte", "value": 1234}, data)

    # in / not_in
    assert evaluator.evaluate({"field": "data.process_name", "op": "in", "value": ["powershell.exe", "cmd.exe"]}, data)
    assert evaluator.evaluate({"field": "data.process_name", "op": "not_in", "value": ["explorer.exe"]}, data)

    # contains / contains_icase
    assert evaluator.evaluate({"field": "data.command_line", "op": "contains", "value": "-enc"}, data)
    assert evaluator.evaluate({"field": "data.command_line", "op": "contains_icase", "value": "-ENC"}, data)
    assert evaluator.evaluate({"field": "data.tags", "op": "contains", "value": "admin"}, data)

    # regex
    assert evaluator.evaluate({"field": "data.command_line", "op": "regex", "value": r"-enc\s+[A-Za-z0-9+/=]+"}, data)

    # exists / not_exists
    assert evaluator.evaluate({"field": "data.signed", "op": "exists"}, data)
    assert evaluator.evaluate({"field": "data.missing_field", "op": "not_exists"}, data)


def test_condition_evaluator_combinators():
    evaluator = ConditionEvaluator()
    data = {
        "collector_type": "process",
        "data": {
            "process_name": "powershell.exe",
            "command_line": "-enc AAAA",
        }
    }

    # all (AND)
    cond_all = {
        "all": [
            {"field": "collector_type", "op": "eq", "value": "process"},
            {"field": "data.process_name", "op": "eq", "value": "powershell.exe"},
        ]
    }
    assert evaluator.evaluate(cond_all, data)

    # any (OR)
    cond_any = {
        "any": [
            {"field": "data.process_name", "op": "eq", "value": "cmd.exe"},
            {"field": "data.process_name", "op": "eq", "value": "powershell.exe"},
        ]
    }
    assert evaluator.evaluate(cond_any, data)

    # not
    cond_not = {
        "not": {"field": "data.process_name", "op": "eq", "value": "explorer.exe"}
    }
    assert evaluator.evaluate(cond_not, data)


def test_condition_evaluator_invalid_tree():
    evaluator = ConditionEvaluator()
    with pytest.raises(InvalidConditionError):
        evaluator.evaluate({"field": "process_name"}, {})  # missing op

    with pytest.raises(InvalidConditionError):
        evaluator.evaluate({"field": "process_name", "op": "invalid_op", "value": "test"}, {})
