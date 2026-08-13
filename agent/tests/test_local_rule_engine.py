"""
Unit tests for LocalRuleEngine (A13).
"""
from agent.localrules.local_rule_engine import LocalRuleEngine
from agent.storage.models import TelemetryEventDTO


def test_local_rule_engine_matching():
    local_rules = [
        {
            "rule_code": "LOCAL-001",
            "name": "Encoded PowerShell",
            "severity": "high",
            "score_impact": 20,
            "condition": {
                "all": [
                    {"field": "collector_type", "op": "eq", "value": "process"},
                    {"field": "data.process_name", "op": "eq", "value": "powershell.exe"},
                ]
            },
        }
    ]

    engine = LocalRuleEngine(local_rules=local_rules)

    event = TelemetryEventDTO(
        collector_type="process",
        event_type="process_start",
        data={"process_name": "powershell.exe", "command_line": "-enc AAA="},
    )

    match = engine.evaluate(event)
    assert match is not None
    assert match.rule_code == "LOCAL-001"
    assert match.score_impact == 20


def test_local_rule_engine_no_match():
    local_rules = [
        {
            "rule_code": "LOCAL-001",
            "name": "Encoded PowerShell",
            "severity": "high",
            "score_impact": 20,
            "condition": {"field": "data.process_name", "op": "eq", "value": "powershell.exe"},
        }
    ]
    engine = LocalRuleEngine(local_rules=local_rules)

    event = TelemetryEventDTO(
        collector_type="process",
        event_type="process_start",
        data={"process_name": "notepad.exe"},
    )

    match = engine.evaluate(event)
    assert match is None
