import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from manager.database.models.timeline import TimelineEvent

logger = logging.getLogger(__name__)

class TimelineService:
    """Service for managing chronological timeline events across agents and incidents."""

    def __init__(self, db_session: Optional[AsyncSession] = None):
        self.db_session = db_session

    async def record_event(
        self,
        event_source: str,
        description: str,
        agent_id: Optional[uuid.UUID] = None,
        incident_id: Optional[uuid.UUID] = None,
        event_ref_id: Optional[uuid.UUID] = None,
        timestamp: Optional[datetime] = None,
        db_session: Optional[AsyncSession] = None
    ) -> TimelineEvent:
        session = db_session or self.db_session
        if session is None:
            raise ValueError("Database session required to record timeline event")

        ts = timestamp or datetime.now(timezone.utc)

        event = TimelineEvent(
            agent_id=agent_id,
            incident_id=incident_id,
            event_source=event_source,
            event_ref_id=event_ref_id,
            description=description,
            timestamp=ts
        )

        session.add(event)
        await session.flush()
        logger.debug(f"Recorded timeline event: {description} (source: {event_source})")
        return event

    async def get_agent_timeline(
        self,
        agent_id: uuid.UUID,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
        db_session: Optional[AsyncSession] = None
    ) -> List[TimelineEvent]:
        session = db_session or self.db_session
        if session is None:
            return []

        stmt = select(TimelineEvent).where(TimelineEvent.agent_id == agent_id)

        if since:
            stmt = stmt.where(TimelineEvent.timestamp >= since)
        if until:
            stmt = stmt.where(TimelineEvent.timestamp <= until)

        stmt = stmt.order_by(desc(TimelineEvent.timestamp)).limit(limit)

        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def get_incident_timeline(
        self,
        incident_id: uuid.UUID,
        limit: int = 100,
        db_session: Optional[AsyncSession] = None
    ) -> List[TimelineEvent]:
        session = db_session or self.db_session
        if session is None:
            return []

        stmt = (
            select(TimelineEvent)
            .where(TimelineEvent.incident_id == incident_id)
            .order_by(desc(TimelineEvent.timestamp))
            .limit(limit)
        )

        result = await session.execute(stmt)
        return list(result.scalars().all())
