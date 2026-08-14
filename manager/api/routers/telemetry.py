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

        # 4. Evaluate event through Policy Engine
        try:
            import os
            from manager.policy.policy_engine import PolicyEngine
            rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rules", "rules")
            engine = PolicyEngine(rules_dir=rules_dir, db_session=db)
            event_data = {
                "collector_type": event_dto.collector_type,
                "event_type": event_dto.event_type,
                "data": event_dto.data,
            }
            policy_results = engine.evaluate_event(event_data=event_data, agent_id=str(payload.agent_id), db_session=db)
            if policy_results:
                event.processed = True
        except Exception as eval_err:
            logger.error(f"Error evaluating policy for event {event_dto.event_id}: {eval_err}")

        # Broadcast live network events over WebSocket
        if event_dto.collector_type == "network":
            try:
                from manager.api.routers.websocket import ws_manager
                await ws_manager.broadcast_network_event(
                    agent_id=payload.agent_id,
                    event_type=event_dto.event_type,
                    event_data=event_dto.data,
                )
            except Exception as ws_err:
                logger.debug(f"Failed broadcasting network event: {ws_err}")

    # 5. Record sync log entry
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


@telemetry_router.get(
    "/agents/{agent_id}/network/ports",
    summary="Get real-time listening ports for a specific agent",
    dependencies=[Depends(require_permission("agents:read"))],
)
async def get_agent_listening_ports(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns active listening ports gathered by the NetworkCollector on the Windows host.
    Extracts the latest state from telemetry_events where collector_type='network'.
    """
    # Fetch recent network events that capture listening sockets
    query = select(TelemetryEvent).where(
        TelemetryEvent.agent_id == agent_id,
        TelemetryEvent.collector_type == "network"
    ).order_by(TelemetryEvent.timestamp.desc()).limit(300)

    result = await db.execute(query)
    events = result.scalars().all()

    # Aggregate latest state per (protocol, local_addr, local_port)
    ports_map = {}
    for ev in reversed(events):  # chronological order to apply latest state
        raw = ev.raw_data or {}
        is_listening = raw.get("is_listening") or ev.event_type in ("LISTEN_STARTED", "listen_baseline")
        is_stopped = ev.event_type == "LISTEN_STOPPED"

        lport = raw.get("local_port")
        if lport and (is_listening or is_stopped):
            laddr = raw.get("local_addr") or raw.get("local_ip") or "0.0.0.0"
            proto = raw.get("protocol", "TCP")
            key = f"{proto}:{laddr}:{lport}"
            if is_stopped:
                ports_map.pop(key, None)
            else:
                ports_map[key] = {
                    "id": str(ev.id),
                    "agent_id": str(agent_id),
                    "protocol": proto,
                    "local_address": laddr,
                    "local_port": lport,
                    "pid": raw.get("pid") or 0,
                    "process_name": raw.get("process_name") or "Unknown",
                    "process_path": raw.get("process_path") or "",
                    "username": raw.get("username") or raw.get("process_user") or "",
                    "state": raw.get("state") or raw.get("status") or "LISTENING",
                    "last_seen_at": ev.timestamp.isoformat(),
                }

    return list(ports_map.values())


@telemetry_router.get(
    "/agents/{agent_id}/network/events",
    summary="Get recent network connection events for a specific agent",
    dependencies=[Depends(require_permission("telemetry:read"))],
)
async def get_agent_network_events(
    agent_id: uuid.UUID,
    event_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns real historical network events (CONNECTION_OPENED, CONNECTION_CLOSED, LISTEN_STARTED) for the agent.
    """
    query = select(TelemetryEvent).where(
        TelemetryEvent.agent_id == agent_id,
        TelemetryEvent.collector_type == "network"
    )
    if event_type:
        query = query.where(TelemetryEvent.event_type == event_type)

    query = query.order_by(TelemetryEvent.timestamp.desc()).limit(limit)
    result = await db.execute(query)
    events = result.scalars().all()

    items = []
    for ev in events:
        raw = ev.raw_data or {}
        items.append({
            "id": str(ev.id),
            "agent_id": str(ev.agent_id),
            "event_type": ev.event_type,
            "protocol": raw.get("protocol", "TCP"),
            "local_address": raw.get("local_addr") or raw.get("local_ip") or "",
            "local_port": raw.get("local_port", 0),
            "remote_address": raw.get("remote_addr") or raw.get("remote_ip") or "",
            "remote_port": raw.get("remote_port", 0),
            "pid": raw.get("pid", 0),
            "process_name": raw.get("process_name", ""),
            "process_path": raw.get("process_path", ""),
            "username": raw.get("username") or raw.get("process_user") or "",
            "direction": raw.get("direction", "outbound"),
            "severity": getattr(ev, "severity", "low"),
            "timestamp": ev.timestamp.isoformat(),
        })
    return items
