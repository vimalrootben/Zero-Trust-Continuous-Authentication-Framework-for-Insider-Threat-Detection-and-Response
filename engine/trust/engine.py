"""ZTA Continuous Trust Engine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from zta.engine.risk.engine import ZTARiskEngine


@dataclass
class TrustState:
    """Represents the continuous trust state of an endpoint."""
    agent_id: str
    trust_score: int  # 0 to 100
    status: str       # TRUSTED, GUARDED, DEGRADED, UNTRUSTED
    reasons: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ZTATrustEngine:
    """Calculates continuous trust posture based on risk score, alert context, and containment."""

    def __init__(self, risk_engine: Optional[ZTARiskEngine] = None):
        self.risk_engine = risk_engine

    def evaluate_trust(
        self,
        agent_id: str,
        active_incidents: Optional[List[str]] = None,
        risk_score: Optional[int] = None,
        critical_alerts_count: int = 0,
        active_containment: bool = False,
    ) -> TrustState:
        """Evaluate trust state according to NIST SP 800-207 continuous evaluation principles."""
        if risk_score is None:
            if self.risk_engine is not None:
                risk_score = self.risk_engine.get_score(agent_id)
            else:
                risk_score = 0

        # Base dynamic trust calculation
        trust_score = max(0, min(100, 100 - risk_score))
        reasons: List[str] = []

        if self.risk_engine is not None:
            history = self.risk_engine.get_history(agent_id)
            recent_events = history[-3:] if history else []
            for evt in recent_events:
                if evt.delta > 0:
                    reasons.append(f"Risk increase (+{evt.delta}): {evt.reason}")

        if active_incidents:
            active_containment = True
            trust_score = max(0, trust_score - (15 * len(active_incidents)))
            reasons.append(f"Active containment incidents: {len(active_incidents)}")

        if active_containment:
            trust_score = min(trust_score, 10)
            status = "UNTRUSTED"
            reasons.append("Endpoint is under active security containment")
        elif critical_alerts_count > 0:
            trust_score = min(trust_score, 30)
            status = "DEGRADED"
            reasons.append(f"{critical_alerts_count} active critical security alert(s)")
        elif trust_score >= 80:
            status = "TRUSTED"
        elif trust_score >= 50:
            status = "GUARDED"
        elif trust_score >= 20:
            status = "DEGRADED"
        else:
            status = "UNTRUSTED"

        if not reasons:
            reasons.append("Normal endpoint activity and baseline posture")

        return TrustState(
            agent_id=agent_id,
            trust_score=trust_score,
            status=status,
            reasons=reasons,
            timestamp=datetime.now(timezone.utc),
        )

