"""
DecayWorker (M7) — Periodically decays agent risk scores for good behavior.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

from manager.risk.risk_engine import RiskEngine
from manager.risk.scoring_rules import DEFAULT_DECAY_AMOUNT, DEFAULT_DECAY_GRACE_HOURS

logger = logging.getLogger(__name__)


class DecayWorker:
    """Worker job that runs periodic decay passes over agent risk scores."""

    def __init__(
        self,
        risk_engine: RiskEngine,
        decay_grace_hours: int = DEFAULT_DECAY_GRACE_HOURS,
        decay_amount: int = DEFAULT_DECAY_AMOUNT,
    ) -> None:
        self.risk_engine = risk_engine
        self.decay_grace_hours = decay_grace_hours
        self.decay_amount = decay_amount

    def run_decay_pass(self, agent_ids: Optional[List[str]] = None) -> List[str]:
        """
        Run decay pass for all agents or specified agent_ids.
        Decays score by decay_amount if current score > 0 and no recent negative event.

        Returns:
            List[str]: List of agent_ids that were decayed.
        """
        target_agents = agent_ids or list(self.risk_engine._agent_scores.keys())
        decayed_agents: List[str] = []

        now = datetime.now(timezone.utc)
        cutoff_dt = now - timedelta(hours=self.decay_grace_hours)
        cutoff_iso = cutoff_dt.isoformat()

        for agent_id in target_agents:
            current = self.risk_engine.get_current_score(agent_id)
            score = current["score"]

            if score <= 0:
                continue

            history = self.risk_engine.get_score_history(agent_id)
            recent_events = [
                e for e in history
                if e.timestamp >= cutoff_iso and e.reason != "baseline_decay"
            ]

            if not recent_events:
                self.risk_engine.apply_delta(
                    agent_id=agent_id,
                    delta=self.decay_amount,
                    reason="baseline_decay",
                )
                decayed_agents.append(agent_id)

        logger.info(f"DecayWorker pass completed. Decayed risk scores for {len(decayed_agents)} agents.")
        return decayed_agents
