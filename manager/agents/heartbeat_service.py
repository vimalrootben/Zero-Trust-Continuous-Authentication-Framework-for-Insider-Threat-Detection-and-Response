"""
HeartbeatService — Records incoming agent heartbeats and updates agent liveness state.
"""
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from typing import Optional, Dict, Any
from manager.database.models.agent import Agent, AgentStatus, Heartbeat

logger = logging.getLogger(__name__)


class HeartbeatService:
    def __init__(self, db: AsyncSession, ws_manager: Optional[Any] = None) -> None:
        self.db = db
        self.ws_manager = ws_manager

    async def record_heartbeat(
        self,
        agent_id: uuid.UUID,
        cpu: float,
        memory: float,
        disk: float,
        status: str = "active",
        hostname: Optional[str] = None,
        os_version: Optional[str] = None,
        agent_version: Optional[str] = None,
        ip_address: Optional[str] = None,
        isolation_status: Optional[str] = None,
    ) -> Heartbeat:
        """
        Persist a heartbeat record and update agent liveness fields.

        - Inserts into heartbeats table.
        - Updates agents.last_seen_at and agents.status.
        - Broadcasts WebSocket events to active dashboards.

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

        # Update agent liveness and metadata
        prev_status = agent.status
        agent.last_seen_at = now
        
        # Determine status: preserve ISOLATED if active isolation is reported or flag is set
        if status.lower() == "isolated" or isolation_status == "ISOLATED":
            target_status = AgentStatus.QUARANTINED
        else:
            target_status = AgentStatus.ACTIVE

        agent.status = target_status

        if hostname:
            agent.hostname = hostname
        if os_version:
            agent.os_version = os_version
        if agent_version:
            agent.agent_version = agent_version
        if ip_address:
            agent.ip_address = ip_address

        await self.db.flush()

        # Trigger WebSocket broadcasts
        if self.ws_manager:
            try:
                stats = {"cpu": cpu, "memory": memory, "disk": disk, "status": target_status.value}
                await self.ws_manager.broadcast_heartbeat(agent_id, stats)
                if prev_status != target_status:
                    await self.ws_manager.broadcast_agent_status_change(
                        agent_id, target_status.value, now.isoformat()
                    )
            except Exception as e:
                logger.debug(f"WS broadcast error during heartbeat: {e}")

        if prev_status != target_status:
            logger.info(
                f"agent.status.transition: agent={agent_id} transitioned from {prev_status.value} to {target_status.value}"
            )
        else:
            logger.debug(f"heartbeat.received: agent={agent_id}, cpu={cpu}%, mem={memory}%, disk={disk}%")

        return hb
