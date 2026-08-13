"""
Telemetry API Router — Manager endpoints for receiving agent telemetry batches and querying telemetry.

POST /agent/telemetry: Agent-facing batch submission (mTLS in prod).
  - Deduplicates events by event_id (idempotency).
  - Records batch sync log in offline_sync_log table.
  - Persists events to telemetry_events table.
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from manager.database.session import get_db
from manager.database.models.agent import Agent, OfflineSyncLog, SyncStatus
from manager.database.models.telemetry import TelemetryEvent
from manager.api.dependencies import require_permission
from manager.api.schemas.telemetry import (
    TelemetryBatchPayload,
    TelemetryResponse,
    TelemetryEventPayload,
)

logger = logging.getLogger(__name__)

# Agent-facing router (/agent/telemetry)
agent_telemetry_router = APIRouter(tags=["Agent-Facing Telemetry"])

# Manager dashboard router (/api/v1/telemetry)
telemetry_router = APIRouter(tags=["Telemetry"])


@agent_telemetry_router.post(
    "/telemetry",
    response_model=TelemetryResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive agent telemetry batch (agent-facing, mTLS in prod)",
)
async def receive_telemetry_batch(
    payload: TelemetryBatchPayload,
    db: AsyncSession = Depends(get_db),
) -> TelemetryResponse:
    """
    Accept a batch of telemetry events from an agent.

    1. Verify agent existence.
    2. Deduplicate events by event_id.
    3. Persist new events.
    4. Write an OfflineSyncLog entry.
    """
    # 1. Verify agent exists
    result = await db.execute(select(Agent).where(Agent.id == payload.agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {payload.agent_id} not found."
        )

    accepted_count = 0
    now = datetime.now(timezone.utc)

    for event_dto in payload.events:
        # 2. Check for duplicate event_id
        existing = await db.execute(
            select(TelemetryEvent).where(TelemetryEvent.id == event_dto.event_id)
        )
        if existing.scalar_one_or_none():
            logger.debug(f"Duplicate telemetry event skipped: {event_dto.event_id}")
            continue

        # 3. Persist telemetry event
        event = TelemetryEvent(
            id=event_dto.event_id,
            agent_id=payload.agent_id,
            collector_type=event_dto.collector_type,
            event_type=event_dto.event_type,
            raw_data=event_dto.data,
            timestamp=event_dto.timestamp,
            processed=False,
        )
        db.add(event)
        accepted_count += 1

    # 4. Record sync log entry
    sync_log = OfflineSyncLog(
        agent_id=payload.agent_id,
        batch_id=payload.batch_id,
        events_count=len(payload.events),
        synced_at=now,
        status=SyncStatus.SUCCESS,
    )
    db.add(sync_log)

    await db.commit()

    logger.info(
        f"Telemetry batch accepted: agent={payload.agent_id}, batch={payload.batch_id}, "
        f"accepted={accepted_count}/{len(payload.events)}"
    )

    return TelemetryResponse(
        accepted=accepted_count,
        rejected=0,
        batch_id=payload.batch_id,
    )


@telemetry_router.get(
    "/telemetry",
    summary="List/search telemetry events across all agents",
    dependencies=[Depends(require_permission("telemetry:read"))],
)
async def list_telemetry_events(
    agent_id: Optional[uuid.UUID] = Query(None),
    collector_type: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    query = select(TelemetryEvent)

    if agent_id:
        query = query.where(TelemetryEvent.agent_id == agent_id)
    if collector_type:
        query = query.where(TelemetryEvent.collector_type == collector_type)
    if event_type:
        query = query.where(TelemetryEvent.event_type == event_type)

    query = query.order_by(TelemetryEvent.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    events = result.scalars().all()

    return [
        {
            "id": str(e.id),
            "agent_id": str(e.agent_id),
            "collector_type": e.collector_type,
            "event_type": e.event_type,
            "raw_data": e.raw_data,
            "timestamp": e.timestamp.isoformat(),
            "processed": e.processed,
        }
        for e in events
    ]


@telemetry_router.get(
    "/agents/{agent_id}/telemetry",
    summary="Get telemetry events for a specific agent",
    dependencies=[Depends(require_permission("telemetry:read"))],
)
async def get_agent_telemetry(
    agent_id: uuid.UUID,
    collector_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    query = select(TelemetryEvent).where(TelemetryEvent.agent_id == agent_id)
    if collector_type:
        query = query.where(TelemetryEvent.collector_type == collector_type)

    query = query.order_by(TelemetryEvent.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    events = result.scalars().all()

    return [
        {
            "id": str(e.id),
            "agent_id": str(e.agent_id),
            "collector_type": e.collector_type,
            "event_type": e.event_type,
            "raw_data": e.raw_data,
            "timestamp": e.timestamp.isoformat(),
            "processed": e.processed,
        }
        for e in events
    ]
