"""Regression tests for non-disruptive defaults and realtime fallback wiring."""

from pathlib import Path

from zta.engine.policy.engine import PolicyDecision, ZTAPolicy
from zta.storage.database import ZTADatabase, ZTARepository


def test_policy_defaults_remain_alert_only(tmp_path):
    policy = ZTAPolicy("safe", "Safe", 0, 100, "MONITOR")
    decision = PolicyDecision("decision", "Safe", "agent", "MONITOR", "test", 0, 100)
    assert policy.mode == "ALERT_ONLY"
    assert decision.mode == "ALERT_ONLY"

    repo = ZTARepository(ZTADatabase(tmp_path / "safe-default.db", seed_defaults=False))
    created = repo.create_policy({"code": "SAFE-DEFAULT", "name": "Safe default"})
    assert created["mode"] == "ALERT_ONLY"


def test_dashboard_has_websocket_guard_and_polling_fallback():
    script = (Path(__file__).parents[1] / "dashboard" / "assets" / "dashboard.js").read_text(encoding="utf-8")
    assert "WebSocket.CONNECTING" in script
    assert "state.ws.readyState !== WebSocket.OPEN" in script
    assert "setInterval" in script
