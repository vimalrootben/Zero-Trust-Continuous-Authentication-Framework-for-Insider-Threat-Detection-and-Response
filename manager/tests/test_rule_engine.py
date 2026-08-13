"""
Unit tests for RuleLoader and RuleEngine (M8).
"""
import os
import tempfile
import yaml
from manager.rules.rule_engine import RuleEngine
from manager.rules.rule_loader import InvalidRuleError, RuleDTO, RuleLoader


def test_rule_loader_validation():
    loader = RuleLoader()

    valid_rule = {
        "rule_code": "TEST-001",
        "name": "Test Rule",
        "category": "execution",
        "severity": "high",
        "condition": {"field": "collector_type", "op": "eq", "value": "process"},
    }
    loader.validate_rule(valid_rule)  # Should not raise

    invalid_rule = {
        "rule_code": "TEST-002",
        "name": "Invalid Severity Rule",
        "category": "execution",
        "severity": "ultra-critical",  # Invalid severity
        "condition": {"field": "collector_type", "op": "eq", "value": "process"},
    }
    try:
        loader.validate_rule(invalid_rule)
        assert False, "Should have raised InvalidRuleError"
    except InvalidRuleError:
        pass


def test_rule_engine_evaluation_and_yaml_loading():
    rules_dir = os.path.join(os.path.dirname(__file__), "..", "rules", "rules")
    engine = RuleEngine(rules_dir=rules_dir)

    assert len(engine._rules_cache) >= 5

    # Test event matching RULE-0002 (PowerShell encoded command)
    powershell_event = {
        "collector_type": "process",
        "data": {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAAA==",
        }
    }

    matches = engine.evaluate_event(powershell_event, agent_id="agent-uuid-123")
    assert len(matches) >= 1
    match_codes = [m.rule_code for m in matches]
    assert "RULE-0002" in match_codes


def test_rule_engine_hot_reload():
    engine = RuleEngine()
    assert len(engine._rules_cache) == 0

    custom_rule = RuleDTO(
        rule_code="CUSTOM-001",
        name="Custom Event Log Rule",
        category="defense_evasion",
        severity="critical",
        score_impact=40,
        condition={"field": "data.event_id", "op": "eq", "value": 1102},
    )
    engine.add_rule(custom_rule)

    log_event = {"collector_type": "log", "data": {"event_id": 1102}}
    matches = engine.evaluate_event(log_event)
    assert len(matches) == 1
    assert matches[0].rule_code == "CUSTOM-001"
