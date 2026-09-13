"""Unit tests for ZTAEventAdapter."""

from datetime import datetime
import pytest

from zta.engine.events.models import ZTAEvent
from zta.engine.events.wazuh_adapter import ZTAEventAdapter


def test_sysmon_process_creation_adapter():
    """Test converting a raw Sysmon Process Creation alert into a normalized ZTAEvent."""
    alert_payload = {
        "id": "1692837182.10239",
        "timestamp": "2026-08-29T22:00:00.000+0000",
        "agent": {
            "id": "001",
            "name": "WIN-TEST-01",
            "ip": "192.168.1.100",
        },
        "rule": {
            "id": 184666,
            "level": 10,
            "description": "PowerShell with encoded command line",
            "groups": ["sysmon", "powershell"],
            "mitre": {
                "tactic": ["Execution"],
                "technique": ["Command and Scripting Interpreter"],
                "id": ["T1059.001"],
            },
        },
        "data": {
            "win": {
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -EncodedCommand aW52b2tl...",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "subjectUserName": "testuser",
                    "processId": "0x1a4",
                }
            }
        },
    }

    event = ZTAEventAdapter.from_dict(alert_payload)

    assert isinstance(event, ZTAEvent)
    assert event.event_id == "1692837182.10239"
    assert event.agent.id == "001"
    assert event.agent.name == "WIN-TEST-01"
    assert event.user.name == "testuser"
    assert event.process.name == "powershell.exe"
    assert event.process.parent_name == "cmd.exe"
    assert event.process.pid == 420  # 0x1a4 hex to dec
    assert event.wazuh_rule.id == 184666
    assert event.mitre.tactic == "Execution"
    assert event.mitre.technique_id == "T1059.001"
    assert event.severity == "HIGH"
    assert event.event_type == "PROCESS_CREATION"


def test_missing_optional_fields():
    """Test adapter resilience when optional telemetry fields are omitted."""
    alert_payload = {
        "agent": {"id": "002", "name": "LINUX-AGENT"},
        "rule": {"id": 1002, "level": 2, "description": "User logged in"},
    }

    event = ZTAEventAdapter.from_dict(alert_payload)

    assert event.agent.id == "002"
    assert event.wazuh_rule.id == 1002
    assert event.user.name is None
    assert event.process.name is None
    assert event.severity == "LOW"


def test_invalid_alert_payload():
    """Test adapter raises ValueError when non-dictionary input is supplied."""
    with pytest.raises(ValueError):
        ZTAEventAdapter.from_dict("not-a-dict")
