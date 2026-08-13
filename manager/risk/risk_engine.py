"""
RiskEngine (M7) — Manages dynamic agent risk scores, score history, clamping, and policy evaluation triggers.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from manager.risk.scoring_rules import SCORE_MAX, SCORE_MIN, RiskLevel, get_risk_level

logger = logging.getLogger(__name__)


@dataclass
class RiskScoreEntry:
    """Represents a single score change event for an agent."""
    agent_id: str
    score: int
    delta: int
    reason: str
    rule_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RiskEngine:
    """Core Zero Trust Risk Engine for agent trust scoring."""

    def __init__(self, policy_engine: Optional[Any] = None) -> None:
        self.policy_engine = policy_engine
        # In-memory storage for agents and score histories (interfaced with DB in full deploy)
        self._agent_scores: Dict[str, int] = {}
        self._score_histories: Dict[str, List[RiskScoreEntry]] = {}

    def apply_delta(
        self,
        agent_id: str,
        delta: int,
        reason: str,
        rule_id: Optional[str] = None,
    ) -> int:
        """
        Apply a score delta to agent_id, clamp between 0 and 100, log history,
        and trigger policy evaluation if risk level changes.

        Returns:
            int: The new clamped risk score.
        """
        old_score = self._agent_scores.get(agent_id, 0)
        old_level = get_risk_level(old_score)

        new_score = max(SCORE_MIN, min(SCORE_MAX, old_score + delta))
        new_level = get_risk_level(new_score)

        self._agent_scores[agent_id] = new_score

        entry = RiskScoreEntry(
            agent_id=agent_id,
            score=new_score,
            delta=delta,
            reason=reason,
            rule_id=rule_id,
        )

        if agent_id not in self._score_histories:
            self._score_histories[agent_id] = []
        self._score_histories[agent_id].append(entry)

        logger.info(
            f"Risk score updated for agent '{agent_id}': {old_score} -> {new_score} "
            f"({old_level.value} -> {new_level.value}, delta={delta:+d}, reason='{reason}')"
        )

        # Trigger Policy Engine evaluation if risk level changed or threshold crossed
        if self.policy_engine and hasattr(self.policy_engine, "evaluate") and old_level != new_level:
            try:
                logger.info(f"Triggering policy engine evaluation for agent '{agent_id}' due to risk level change.")
                self.policy_engine.evaluate(agent_id)
            except Exception as e:
                logger.error(f"Error executing policy engine evaluation for agent '{agent_id}': {e}")

        return new_score

    def get_current_score(self, agent_id: str) -> Dict[str, Any]:
        """Get current risk score and risk level for an agent."""
        score = self._agent_scores.get(agent_id, 0)
        level = get_risk_level(score)
        return {
            "agent_id": agent_id,
            "score": score,
            "level": level.value,
        }

    def get_score_history(self, agent_id: str, since: Optional[str] = None) -> List[RiskScoreEntry]:
        """Get score history entries for an agent, optionally filtered by timestamp."""
        history = self._score_histories.get(agent_id, [])
        if not since:
            return history

        filtered: List[RiskScoreEntry] = []
        for entry in history:
            if entry.timestamp >= since:
                filtered.append(entry)
        return filtered
