"""
Integration tests for Manager Telemetry API endpoints:
  - POST /agent/telemetry batch receipt, deduplication, and persistence
  - GET /api/v1/telemetry querying
"""
import uuid
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from manager.database.models.agent import Agent, AgentStatus
from manager.database.models.auth import User, Role
from manager.database.models.telemetry import TelemetryEvent
from manager.auth.password_handler import PasswordHandler
from manager.api.dependencies import jwt_handler


@pytest.mark.asyncio
async def test_telemetry_batch_receipt_and_deduplication(db_session: AsyncSession, client: AsyncClient):
    """POST /agent/telemetry accepts batch, persists events, and ignores duplicate event_id."""
    # 1. Create an active agent
    agent = Agent(
        hostname="telemetry-test-host",
        device_fingerprint=f"fp-tel-{uuid.uuid4().hex[:8]}",
        status=AgentStatus.ACTIVE,
    )
    db_session.add(agent)
    await db_session.flush()

    event_id1 = str(uuid.uuid4())
    event_id2 = str(uuid.uuid4())

    batch_payload = {
        "agent_id": str(agent.id),
        "batch_id": str(uuid.uuid4()),
        "events": [
            {
                "event_id": event_id1,
                "collector_type": "process",
                "event_type": "process_start",
                "severity": "medium",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": {"process_name": "cmd.exe", "pid": 1234},
            },
            {
                "event_id": event_id2,
                "collector_type": "network",
                "event_type": "connection_outbound",
                "severity": "low",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": {"remote_ip": "1.1.1.1", "port": 443},
            },
        ],
    }

    # First POST — should accept both events
    resp = await client.post("/agent/telemetry", json=batch_payload)
    assert resp.status_code == 202
    data = resp.json()
    assert data["accepted"] == 2
    assert data["batch_id"] == batch_payload["batch_id"]

    # Second POST with exact same payload (duplicate event_ids) — accepted should be 0
    resp2 = await client.post("/agent/telemetry", json=batch_payload)
    assert resp2.status_code == 202
    data2 = resp2.json()
    # The second submission is a retry — all event_ids were already stored, so none are new
    assert data2["accepted"] == 0


@pytest.mark.asyncio
async def test_get_telemetry_endpoint(db_session: AsyncSession, client: AsyncClient):
    """GET /api/v1/telemetry returns list of telemetry events for authenticated user."""
    # Create agent & event
    agent = Agent(
        hostname="telemetry-query-host",
        device_fingerprint=f"fp-qtel-{uuid.uuid4().hex[:8]}",
        status=AgentStatus.ACTIVE,
    )
    db_session.add(agent)
    await db_session.flush()

    evt = TelemetryEvent(
        id=uuid.uuid4(),
        agent_id=agent.id,
        collector_type="file",
        event_type="file_created",
        raw_data={"file_path": "C:\\temp\\malicious.exe"},
        timestamp=datetime.now(timezone.utc),
        processed=False,
    )
    db_session.add(evt)

    # Query admin user & token
    role_res = await db_session.execute(select(Role).where(Role.name == "admin"))
    role = role_res.scalar_one()
    user = User(
        username="tel-query-user",
        email="tel.query@test.local",
        password_hash=PasswordHandler().hash_password("AdminSecure123!"),
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    await db_session.flush()

    token = jwt_handler.create_access_token(user.id, "admin", ["telemetry:read"])
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.get(f"/api/v1/telemetry?agent_id={agent.id}", headers=headers)
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) >= 1
    assert events[0]["collector_type"] == "file"


@pytest.mark.asyncio
async def test_get_agent_network_ports_and_events(db_session: AsyncSession, client: AsyncClient):
    """GET /api/v1/agents/{agent_id}/network/ports and network/events return real telemetry data."""
    agent = Agent(
        hostname="network-test-host",
        device_fingerprint=f"fp-net-{uuid.uuid4().hex[:8]}",
        status=AgentStatus.ACTIVE,
    )
    db_session.add(agent)
    await db_session.flush()

    # Add a listening port event
    port_event = TelemetryEvent(
        id=uuid.uuid4(),
        agent_id=agent.id,
        collector_type="network",
        event_type="LISTEN_STARTED",
        raw_data={
            "local_addr": "0.0.0.0",
            "local_port": 8080,
            "protocol": "TCP",
            "status": "LISTENING",
            "is_listening": True,
            "pid": 9999,
            "process_name": "app.exe",
            "process_path": "C:\\App\\app.exe",
            "process_user": "SYSTEM",
        },
        timestamp=datetime.now(timezone.utc),
        processed=False,
    )
    db_session.add(port_event)

    # Add a connection opened event
    conn_event = TelemetryEvent(
        id=uuid.uuid4(),
        agent_id=agent.id,
        collector_type="network",
        event_type="CONNECTION_OPENED",
        raw_data={
            "local_addr": "192.168.1.50",
            "local_port": 50555,
            "remote_addr": "8.8.8.8",
            "remote_port": 53,
            "protocol": "UDP",
            "pid": 9999,
            "process_name": "app.exe",
            "direction": "outbound",
        },
        timestamp=datetime.now(timezone.utc),
        processed=False,
    )
    db_session.add(conn_event)
    await db_session.flush()

    role_res = await db_session.execute(select(Role).where(Role.name == "admin"))
    role = role_res.scalar_one()
    user = User(
        username="net-query-user",
        email="net.query@test.local",
        password_hash=PasswordHandler().hash_password("AdminSecure123!"),
        is_active=True,
        role_id=role.id,
    )
    db_session.add(user)
    await db_session.flush()

    token = jwt_handler.create_access_token(user.id, "admin", ["agents:read", "telemetry:read"])
    headers = {"Authorization": f"Bearer {token}"}

    # Test ports endpoint
    resp_ports = await client.get(f"/api/v1/agents/{agent.id}/network/ports", headers=headers)
    assert resp_ports.status_code == 200
    ports = resp_ports.json()
    assert len(ports) == 1
    assert ports[0]["local_port"] == 8080
    assert ports[0]["process_name"] == "app.exe"

    # Test events endpoint
    resp_events = await client.get(f"/api/v1/agents/{agent.id}/network/events", headers=headers)
    assert resp_events.status_code == 200
    events = resp_events.json()
    assert len(events) == 2
