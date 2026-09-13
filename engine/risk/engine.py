"""ZTA Dynamic Risk Engine with Decay and History."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional


@dataclass
class RiskEvent:
    """Audit record for every risk score change."""
    timestamp: datetime
    agent_id: str
    previous_score: int
    delta: int
    new_score: int
    reason: str
    finding_id: Optional[str] = None


class ZTARiskEngine:
    """Manages endpoint risk scores (0-100), applies score adjustments, decay, and records history."""

    def __init__(self, decay_rate_per_min: float = 1.0, min_score: int = 0, max_score: int = 100):
        self.decay_rate_per_min = decay_rate_per_min
        self.min_score = min_score
        self.max_score = max_score

        # agent_id -> current score
        self._scores: Dict[str, int] = {}
        # agent_id -> datetime of last update
        self._last_update: Dict[str, datetime] = {}
        # agent_id -> list of RiskEvent history
        self._history: Dict[str, List[RiskEvent]] = {}

    def get_score(self, agent_id: str) -> int:
        """Returns the current risk score for an agent."""
        return self._scores.get(agent_id, 0)

    def get_risk_level(self, agent_id: str) -> str:
        """Categorizes agent risk score into qualitative bands."""
        score = self.get_score(agent_id)
        if score >= 85:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        return "LOW"

    def get_history(self, agent_id: str) -> List[RiskEvent]:
        """Returns risk history for an agent."""
        return self._history.get(agent_id, [])

    def apply_delta(self, agent_id: str, delta: int, reason: str, finding_id: Optional[str] = None, timestamp: Optional[datetime] = None) -> RiskEvent:
        """Applies a risk score adjustment (positive or negative) to an agent."""
        ts = timestamp or datetime.now(timezone.utc)
        prev_score = self.get_score(agent_id)

        new_score = max(self.min_score, min(self.max_score, prev_score + delta))
        self._scores[agent_id] = new_score
        self._last_update[agent_id] = ts

        event = RiskEvent(
            timestamp=ts,
            agent_id=agent_id,
            previous_score=prev_score,
            delta=delta,
            new_score=new_score,
            reason=reason,
            finding_id=finding_id,
        )

        if agent_id not in self._history:
            self._history[agent_id] = []
        self._history[agent_id].append(event)

        return event

    def apply_decay(self, agent_id: str, current_time: Optional[datetime] = None) -> Optional[RiskEvent]:
        """Applies time-based risk decay if no new events occurred recently."""
        now = current_time or datetime.now(timezone.utc)
        last_ts = self._last_update.get(agent_id)
        if not last_ts:
            return None

        elapsed_minutes = (now - last_ts).total_seconds() / 60.0
        if elapsed_minutes < 1.0:
            return None

        decay_amount = int(elapsed_minutes * self.decay_rate_per_min)
        if decay_amount <= 0:
            return None

        prev_score = self.get_score(agent_id)
        if prev_score <= self.min_score:
            return None

        new_score = max(self.min_score, prev_score - decay_amount)
        delta = new_score - prev_score
        self._scores[agent_id] = new_score
        self._last_update[agent_id] = now

        event = RiskEvent(
            timestamp=now,
            agent_id=agent_id,
            previous_score=prev_score,
            delta=delta,
            new_score=new_score,
            reason=f"Risk decay after {int(elapsed_minutes)} minutes of inactivity",
        )
        self._history[agent_id].append(event)
        return event
