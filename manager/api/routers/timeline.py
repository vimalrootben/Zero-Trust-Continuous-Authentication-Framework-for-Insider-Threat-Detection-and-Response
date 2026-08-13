import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.dependencies import get_db, require_permission
from manager.timeline.timeline_service import TimelineService

router = APIRouter(tags=["timeline"])

@router.get("/agents/{agent_id}/timeline")
async def get_agent_timeline(
    agent_id: uuid.UUID,
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("agents:read"))
):
    service = TimelineService(db)
    events = await service.get_agent_timeline(agent_id, since=since, until=until, limit=limit)
    return [
        {
            "id": str(e.id),
            "agent_id": str(e.agent_id) if e.agent_id else None,
            "event_source": e.event_source,
            "description": e.description,
            "timestamp": e.timestamp.isoformat()
        }
        for e in events
    ]

@router.get("/incidents/{incident_id}/timeline")
async def get_incident_timeline(
    incident_id: uuid.UUID,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("incidents:read"))
):
    service = TimelineService(db)
    events = await service.get_incident_timeline(incident_id, limit=limit)
    return [
        {
            "id": str(e.id),
            "incident_id": str(e.incident_id) if e.incident_id else None,
            "event_source": e.event_source,
            "description": e.description,
            "timestamp": e.timestamp.isoformat()
        }
        for e in events
    ]
