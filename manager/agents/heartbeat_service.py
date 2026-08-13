"""
HeartbeatService — Records incoming agent heartbeats and updates agent liveness state.
"""
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from manager.database.models.agent import Agent, AgentStatus, Heartbeat

logger = logging.getLogger(__name__)


class HeartbeatService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def record_heartbeat(
        self,
        agent_id: uuid.UUID,
        cpu: float,
        memory: float,
        disk: float,
        status: str = "active",
    ) -> Heartbeat:
        """
        Persist a heartbeat record and update agent liveness fields.

        - Inserts into heartbeats table.
        - Updates agents.last_seen_at and agents.status = 'active'.

        Raises:
            ValueError: If agent_id does not correspond to an existing agent.
        """
        now = datetime.now(timezone.utc)

        # Verify agent exists
        result = await self.db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()
        if not agent:
            raise ValueError(f"Agent {agent_id} not found.")

        # Insert heartbeat row
        hb = Heartbeat(
            agent_id=agent_id,
            timestamp=now,
            cpu_usage=cpu,
            memory_usage=memory,
            disk_usage=disk,
            agent_status=status,
        )
        self.db.add(hb)

        # Update agent liveness
        prev_status = agent.status
        agent.last_seen_at = now
        agent.status = AgentStatus.ACTIVE

        await self.db.flush()

        if prev_status != AgentStatus.ACTIVE:
            logger.info(
                f"agent.status.active: agent={agent_id} recovered from {prev_status.value}"
            )
        else:
            logger.debug(f"heartbeat.received: agent={agent_id}, cpu={cpu}%, mem={memory}%, disk={disk}%")

        return hb
