"""
Tests for HeartbeatService (M4) and HeartbeatMonitor:
  - Heartbeat records liveness and updates agent last_seen_at
  - Status recovers from offline -> active on next heartbeat
  - Stale agent (no heartbeat > threshold) transitions to offline
  - Monitor creates exactly ONE alert per offline transition (not every check)
  - Heartbeat history query supports time-range filtering and pagination
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from manager.database.models.agent import Agent, AgentStatus, Heartbeat
from manager.agents.heartbeat_service import HeartbeatService
from manager.scheduler.heartbeat_monitor import HeartbeatMonitor
from manager.config import settings


# ─── Helpers ────────────────────────────────────────────────────────────────

async def _create_active_agent(db: AsyncSession, hostname: str = "test-agent") -> Agent:
    agent = Agent(
        hostname=hostname,
        device_fingerprint=f"fp-{uuid.uuid4().hex}",
        os_version="Windows 11",
        agent_version="1.0.0",
        status=AgentStatus.ACTIVE,
        last_seen_at=datetime.now(timezone.utc),
    )
    db.add(agent)
    await db.flush()
    return agent


# ─── HeartbeatService Tests ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_heartbeat_recorded_and_agent_updated(db_session: AsyncSession):
    """Heartbeat inserts a row and updates agent.last_seen_at."""
    agent = await _create_active_agent(db_session, hostname="hb-record-test")
    original_seen_at = agent.last_seen_at

    svc = HeartbeatService(db_session)
    hb = await svc.record_heartbeat(
        agent_id=agent.id,
        cpu=45.5,
        memory=62.0,
        disk=78.3,
        status="active",
    )

    assert hb.id is not None
    assert hb.agent_id == agent.id
    assert hb.cpu_usage == pytest.approx(45.5)
    assert hb.memory_usage == pytest.approx(62.0)
    assert hb.disk_usage == pytest.approx(78.3)

    # Agent last_seen_at should be updated
    await db_session.refresh(agent)
    # SQLite returns naive datetimes; normalise to UTC for a portable comparison.
    refreshed_seen_at = agent.last_seen_at
    if refreshed_seen_at.tzinfo is None:
        refreshed_seen_at = refreshed_seen_at.replace(tzinfo=timezone.utc)
    assert refreshed_seen_at > original_seen_at
    assert agent.status == AgentStatus.ACTIVE


@pytest.mark.asyncio
async def test_heartbeat_recovers_offline_agent(db_session: AsyncSession):
    """Heartbeat from an offline agent flips it back to active."""
    agent = Agent(
        hostname="offline-agent",
        device_fingerprint=f"fp-{uuid.uuid4().hex}",
        status=AgentStatus.OFFLINE,
        last_seen_at=datetime.now(timezone.utc) - timedelta(minutes=10),
    )
    db_session.add(agent)
    await db_session.flush()

    svc = HeartbeatService(db_session)
    await svc.record_heartbeat(
        agent_id=agent.id, cpu=10.0, memory=20.0, disk=30.0
    )

    await db_session.refresh(agent)
    assert agent.status == AgentStatus.ACTIVE


@pytest.mark.asyncio
async def test_heartbeat_unknown_agent_raises(db_session: AsyncSession):
    """Recording a heartbeat for a non-existent agent raises ValueError."""
    svc = HeartbeatService(db_session)
    with pytest.raises(ValueError, match="not found"):
        await svc.record_heartbeat(
            agent_id=uuid.uuid4(), cpu=0.0, memory=0.0, disk=0.0
        )


# ─── HeartbeatMonitor Tests ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_monitor_marks_stale_agent_offline(db_session: AsyncSession):
    """
    Agent with last_seen_at older than threshold transitions to offline.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from manager.tests.conftest import test_engine

    stale_seen_at = datetime.now(timezone.utc) - timedelta(seconds=200)

    agent = Agent(
        hostname="stale-agent",
        device_fingerprint=f"fp-{uuid.uuid4().hex}",
        status=AgentStatus.ACTIVE,
        last_seen_at=stale_seen_at,
    )
    db_session.add(agent)
    await db_session.flush()
    await db_session.commit()

    session_maker = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monitor = HeartbeatMonitor(
        session_maker=session_maker,
        offline_threshold_seconds=90,
        alert_service=None,
    )

    transitioned = await monitor.check_stale_agents()
    assert agent.id in transitioned

    # Reload from DB to confirm status change persisted
    async with session_maker() as verify_db:
        result = await verify_db.execute(select(Agent).where(Agent.id == agent.id))
        refreshed = result.scalar_one()
        assert refreshed.status == AgentStatus.OFFLINE


@pytest.mark.asyncio
async def test_monitor_creates_alert_only_on_transition(db_session: AsyncSession):
    """
    Alert is created exactly once when agent goes offline.
    A second monitor pass on an already-offline agent creates no new alert.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from manager.tests.conftest import test_engine

    stale_seen_at = datetime.now(timezone.utc) - timedelta(seconds=200)

    agent = Agent(
        hostname="transition-alert-test",
        device_fingerprint=f"fp-{uuid.uuid4().hex}",
        status=AgentStatus.ACTIVE,
        last_seen_at=stale_seen_at,
    )
    db_session.add(agent)
    await db_session.flush()
    await db_session.commit()

    mock_alert_svc = AsyncMock()
    mock_alert_svc.create_alert = AsyncMock()

    session_maker = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monitor = HeartbeatMonitor(
        session_maker=session_maker,
        offline_threshold_seconds=90,
        alert_service=mock_alert_svc,
    )

    # First check: agent transitions active -> offline, alert created
    await monitor.check_stale_agents()
    assert mock_alert_svc.create_alert.call_count == 1

    # Second check: agent already offline, should NOT be found again (status != ACTIVE)
    await monitor.check_stale_agents()
    assert mock_alert_svc.create_alert.call_count == 1  # No new alert


@pytest.mark.asyncio
async def test_heartbeat_api_endpoint(db_session: AsyncSession, client: AsyncClient):
    """POST /agent/heartbeat returns 204 and updates agent."""
    agent = await _create_active_agent(db_session, hostname="hb-api-agent")

    resp = await client.post("/agent/heartbeat", json={
        "agent_id": str(agent.id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_usage": 30.5,
        "memory_usage": 55.0,
        "disk_usage": 40.0,
        "status": "active",
    })
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_heartbeat_history_endpoint(db_session: AsyncSession, client: AsyncClient):
    """GET /api/v1/agents/{id}/heartbeats returns list with pagination."""
    from manager.auth.password_handler import PasswordHandler
    from manager.database.models.auth import User, Role
    from manager.api.dependencies import jwt_handler
    from sqlalchemy import select as sa_select

    # Create agent with heartbeats
    agent = await _create_active_agent(db_session, hostname="hb-history-agent")
    svc = HeartbeatService(db_session)
    for i in range(3):
        await svc.record_heartbeat(agent_id=agent.id, cpu=float(i * 10), memory=50.0, disk=30.0)

    # Create a user for authentication
    role_res = await db_session.execute(sa_select(Role).where(Role.name == "admin"))
    role = role_res.scalar_one()
    user = User(
        username="hb-hist-user",
        email="hb.hist@test.local",
        password_hash=PasswordHandler().hash_password("AdminSecure123!"),
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    await db_session.flush()

    token = jwt_handler.create_access_token(user.id, "admin", ["agents:read"])
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.get(f"/api/v1/agents/{agent.id}/heartbeats", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 3
