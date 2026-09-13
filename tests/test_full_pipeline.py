"""End-to-end pipeline test for ZTA Engine components."""

from datetime import datetime
from zta.engine.events.wazuh_adapter import ZTAEventAdapter
from zta.engine.correlation.engine import ZTACorrelationEngine
from zta.engine.risk.engine import ZTARiskEngine
from zta.engine.trust.engine import ZTATrustEngine
from zta.engine.policy.engine import ZTAPolicyEngine


def test_full_zta_pipeline_end_to_end():
    """Test full pipeline: alert ingest -> correlation -> risk -> trust -> policy decision."""
    # 1. Instantiate ZTA Subsystems
    correlation_engine = ZTACorrelationEngine(window_seconds=300)
    risk_engine = ZTARiskEngine(decay_rate_per_min=1.0)
    trust_engine = ZTATrustEngine(risk_engine)
    policy_engine = ZTAPolicyEngine()

    agent_id = "001"

    # Verify initial baseline
    assert risk_engine.get_score(agent_id) == 0
    init_trust = trust_engine.evaluate_trust(agent_id)
    assert init_trust.trust_score == 100
    assert init_trust.status == "TRUSTED"

    # 2. Simulate Alert 1: Encoded PowerShell
    ps_alert = {
        "id": "evt-001",
        "timestamp": "2026-08-29T22:10:00.000+0000",
        "agent": {"id": agent_id, "name": "WIN-TEST-01"},
        "rule": {"id": 184666, "level": 10, "description": "PowerShell with encoded command", "groups": ["powershell"]},
        "data": {"win": {"eventdata": {"image": "C:\\Windows\\powershell.exe", "commandLine": "powershell -e abc"}}},
    }
    event1 = ZTAEventAdapter.from_dict(ps_alert)
    correlation_engine.process_event(event1)
    
    # Apply risk delta for high-severity PowerShell alert (+25)
    risk_engine.apply_delta(agent_id, 25, reason="PowerShell encoded command execution")

    # Check intermediate state
    assert risk_engine.get_score(agent_id) == 25
    trust_state = trust_engine.evaluate_trust(agent_id)
    assert trust_state.trust_score == 75
    assert trust_state.status == "GUARDED"

    # 3. Simulate Alert 2: Outbound Network Connection to suspicious endpoint
    net_alert = {
        "id": "evt-002",
        "timestamp": "2026-08-29T22:11:00.000+0000",
        "agent": {"id": agent_id, "name": "WIN-TEST-01"},
        "rule": {"id": 184667, "level": 12, "description": "Connection to known IOC", "groups": ["network"]},
        "data": {"win": {"eventdata": {"destinationIp": "198.51.100.45", "destinationPort": "443"}}},
    }
    event2 = ZTAEventAdapter.from_dict(net_alert)
    findings = correlation_engine.process_event(event2)

    # Process correlation finding delta (+35) + IOC direct delta (+35)
    risk_engine.apply_delta(agent_id, 65, reason="IOC network connection after PowerShell execution")

    # 4. Evaluate Final Risk & Continuous Trust State
    final_risk = risk_engine.get_score(agent_id)
    assert final_risk == 90  # 25 + 65 = 90 (CRITICAL)

    final_trust = trust_engine.evaluate_trust(agent_id)
    assert final_trust.trust_score == 10  # 100 - 90 = 10
    assert final_trust.status == "UNTRUSTED"
    assert len(final_trust.reasons) > 0

    # 5. Evaluate Adaptive Policy Decision
    decision = policy_engine.evaluate(agent_id, final_risk, final_trust.trust_score)
    assert decision.action == "ISOLATE_ENDPOINT"
    assert decision.policy_name == "Critical Risk Containment"
