"""
HeartbeatMonitor — Background scheduler job that detects and flags stale agents as offline.

Runs every MONITOR_CHECK_INTERVAL_SECONDS (default 15s).
An agent is considered offline when:
    last_seen_at < now - OFFLINE_THRESHOLD_SECONDS (default 90s = 3 missed heartbeats)

On transition active -> offline:
  - Sets agents.status = 'offline'
  - Creates exactly ONE low-severity alert (avoids alert storms on repeat checks)

On recovery (heartbeat received): HeartbeatService flips status back to 'active'.
"""
import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from manager.database.models.agent import Agent, AgentStatus

logger = logging.getLogger(__name__)


class HeartbeatMonitor:
    """
    Scheduler job: detect agents that have missed heartbeats and mark them offline.

    alert_service is intentionally typed as Any here to avoid a circular import —
    it will be the AlertService instance injected at startup.
    """

    def __init__(
        self,
        session_maker: async_sessionmaker,
        offline_threshold_seconds: int,
        alert_service=None,
    ) -> None:
        self.session_maker = session_maker
        self.offline_threshold_seconds = offline_threshold_seconds
        self.alert_service = alert_service
        self._running = False

    async def check_stale_agents(self) -> list[uuid.UUID]:
        """
        Find agents that are ACTIVE but have not heartbeated within the threshold.

        For each such agent:
          1. Set status = 'offline'.
          2. Create exactly one low-severity alert (only on transition, not every check).

        Returns:
            List of agent IDs that were transitioned to offline in this pass.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.offline_threshold_seconds)
        transitioned: list[uuid.UUID] = []

        async with self.session_maker() as db:
            result = await db.execute(
                select(Agent).where(
                    Agent.status == AgentStatus.ACTIVE,
                    Agent.last_seen_at < cutoff,
                )
            )
            stale_agents = result.scalars().all()

            for agent in stale_agents:
                agent.status = AgentStatus.OFFLINE
                transitioned.append(agent.id)
                logger.warning(
                    f"agent.status.offline: agent={agent.id} hostname={agent.hostname} "
                    f"last_seen={agent.last_seen_at}"
                )

                # Create alert on transition (alert_service is optional during tests)
                if self.alert_service:
                    try:
                        await self.alert_service.create_alert(
                            db=db,
                            agent_id=agent.id,
                            title=f"Agent went offline: {agent.hostname}",
                            description=(
                                f"Agent '{agent.hostname}' (id={agent.id}) has not sent a heartbeat "
                                f"for more than {self.offline_threshold_seconds}s."
                            ),
                            severity="low",
                            rule_id=None,
                            telemetry_event_id=None,
                            mitre_technique_id=None,
                        )
                    except Exception as exc:
                        logger.error(f"Failed to create offline alert for agent {agent.id}: {exc}")

            await db.commit()

        if transitioned:
            logger.info(f"HeartbeatMonitor: {len(transitioned)} agent(s) marked offline.")

        return transitioned

    async def run_forever(self, interval_seconds: int = 15) -> None:
        """
        Continuous loop: check for stale agents every `interval_seconds`.
        Does NOT crash the process on any single check failure — logs and continues.
        """
        self._running = True
        logger.info(f"HeartbeatMonitor started. Check interval: {interval_seconds}s, "
                    f"offline threshold: {self.offline_threshold_seconds}s.")
        while self._running:
            try:
                await self.check_stale_agents()
            except Exception as exc:
                logger.error(f"HeartbeatMonitor check failed: {exc}", exc_info=True)
            await asyncio.sleep(interval_seconds)

    def stop(self) -> None:
        self._running = False
