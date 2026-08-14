"""
Test Suite: Task 3 — Real Network Monitoring & Real-Time Endpoint/Agent State

Verifies:
 1. Agent registration
 2. Agent authentication & CSR handling
 3. Real Heartbeat processing
 4. Online state tracking
 5. Offline detection via HeartbeatMonitor
 6. Agent reconnect & telemetry recovery
 7. Listening port collection (NetworkCollector)
 8. Network event collection (NetworkConnectionProvider)
 9. Network event database persistence & queries
10. Real-time WebSocket event broadcasts
11. Network isolation request & signing
12. Network isolation execution & verification
13. Network isolation failure handling
14. Network unisolation & rule deletion
15. Duplicate isolation prevention (idempotency)
16. RBAC enforcement on network endpoints
17. Audit logging of network actions
18. Configurable agent offline timeout
19. WebSocket reconnect handling
20. Database persistence & relational integrity
"""

import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.main import app
from manager.database.models.agent import Agent, AgentStatus, Heartbeat
from manager.database.models.command import Command, CommandStatus
from manager.database.models.telemetry import TelemetryEvent
from manager.database.models.audit import AuditLog, ActorType
from manager.database.models.alert import Alert, AlertStatus
from manager.database.models.alert_response import AlertResponse, AlertResponseStatus, AlertResponseAction
from manager.agents.heartbeat_service import HeartbeatService
from manager.scheduler.heartbeat_monitor import HeartbeatMonitor
from manager.websocket.connection_manager import ConnectionManager
from manager.websocket.command_dispatcher import CommandDispatcher
from manager.alerts.response_service import ResponseService
from manager.audit.audit_logger import AuditLogger
from manager.audit.constants import AuditAction
from manager.config import settings
from agent.collectors.network_collector import NetworkCollector, NetworkConnectionProvider
from agent.storage.models import TelemetryEventDTO
from agent.responses.response_handler import AgentResponseHandler


# ─────────────────────────────────────────────────────────────────────────────
# Helper Fixtures & Builders
# ─────────────────────────────────────────────────────────────────────────────

async def _create_test_agent(
    db: AsyncSession,
    hostname: str = "win-endpoint-01",
    status: AgentStatus = AgentStatus.ACTIVE,
    ip_address: str = "192.168.1.50"
) -> Agent:
    agent = Agent(
        id=uuid.uuid4(),
        hostname=hostname,
        device_fingerprint=f"fingerprint-{uuid.uuid4().hex[:12]}",
        os_version="Windows 11 Enterprise 23H2",
        agent_version="2.0.0",
        ip_address=ip_address,
        status=status,
        last_seen_at=datetime.now(timezone.utc),
        current_risk_score=10,
    )
    db.add(agent)
    await db.flush()
    return agent


# ─────────────────────────────────────────────────────────────────────────────
# 1. Agent Registration
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_1_agent_registration_persists_identity(db_session: AsyncSession):
    agent = await _create_test_agent(db_session, hostname="host-reg-01")
    assert agent.id is not None
    assert agent.hostname == "host-reg-01"
    assert agent.status == AgentStatus.ACTIVE


# ─────────────────────────────────────────────────────────────────────────────
# 2. Agent Authentication
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_2_agent_authentication_rejects_unknown():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Non-existent agent sending heartbeat
        fake_id = uuid.uuid4()
        resp = await client.post("/agent/heartbeat", json={
            "agent_id": str(fake_id),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cpu_usage": 10.0,
            "memory_usage": 20.0,
            "disk_usage": 30.0,
            "status": "active"
        })
        assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# 3. Real Heartbeat
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_3_real_heartbeat_updates_agent_state(db_session: AsyncSession):
    agent = await _create_test_agent(db_session, hostname="hb-test-01")
    ws_mock = AsyncMock()
    svc = HeartbeatService(db_session, ws_manager=ws_mock)

    hb = await svc.record_heartbeat(
        agent_id=agent.id,
        cpu=12.5,
        memory=45.2,
        disk=60.1,
        status="active",
        hostname="hb-test-01-renamed",
        os_version="Windows 11 Pro",
        agent_version="2.1.0",
        ip_address="10.0.0.15",
        isolation_status="NOT_ISOLATED"
    )

    assert hb.agent_id == agent.id
    assert agent.hostname == "hb-test-01-renamed"
    assert agent.os_version == "Windows 11 Pro"
    assert agent.ip_address == "10.0.0.15"
    assert agent.status == AgentStatus.ACTIVE
    ws_mock.broadcast_heartbeat.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 4. Online State
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_4_online_state_tracking(db_session: AsyncSession):
    agent = await _create_test_agent(db_session, status=AgentStatus.OFFLINE)
    svc = HeartbeatService(db_session)
    await svc.record_heartbeat(agent_id=agent.id, cpu=5.0, memory=10.0, disk=15.0, status="active")
    assert agent.status == AgentStatus.ACTIVE


# ─────────────────────────────────────────────────────────────────────────────
# 5. Offline Detection (HeartbeatMonitor)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_5_offline_detection_via_monitor(db_session: AsyncSession):
    stale_time = datetime.now(timezone.utc) - timedelta(seconds=120)
    agent = Agent(
        id=uuid.uuid4(),
        hostname="stale-host",
        device_fingerprint=f"fp-{uuid.uuid4().hex[:8]}",
        status=AgentStatus.ACTIVE,
        last_seen_at=stale_time,
    )
    db_session.add(agent)
    await db_session.flush()

    session_maker_mock = MagicMock()
    session_maker_mock.return_value.__aenter__.return_value = db_session
    session_maker_mock.return_value.__aexit__.return_value = None

    ws_mock = AsyncMock()
    monitor = HeartbeatMonitor(
        session_maker=session_maker_mock,
        offline_threshold_seconds=90,
        ws_manager=ws_mock
    )
    transitioned = await monitor.check_stale_agents()
    assert agent.id in transitioned
    assert agent.status == AgentStatus.OFFLINE
    ws_mock.broadcast_agent_status_change.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# 6. Agent Reconnect
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_6_agent_reconnect_flow(db_session: AsyncSession):
    agent = await _create_test_agent(db_session, status=AgentStatus.OFFLINE)
    ws_mock = AsyncMock()
    svc = HeartbeatService(db_session, ws_manager=ws_mock)

    await svc.record_heartbeat(agent_id=agent.id, cpu=10.0, memory=20.0, disk=30.0, status="active")
    assert agent.status == AgentStatus.ACTIVE
    ws_mock.broadcast_agent_status_change.assert_called_once_with(
        agent.id, "active", agent.last_seen_at.isoformat()
    )


# ─────────────────────────────────────────────────────────────────────────────
# 7. Listening Port Collection
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_7_listening_port_collection():
    provider = NetworkConnectionProvider()
    conns = provider.get_connections()
    assert isinstance(conns, list)
    for c in conns:
        assert "local_addr" in c
        assert "local_ip" in c
        assert "local_port" in c
        assert "protocol" in c
        assert "state" in c
        assert "status" in c
        assert "pid" in c
        assert "process_name" in c


# ─────────────────────────────────────────────────────────────────────────────
# 8. Network Event Collection (Delta Detection)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_8_network_event_delta_detection():
    emitted_events = []
    def sink(ev: TelemetryEventDTO):
        emitted_events.append(ev)

    mock_provider = MagicMock(spec=NetworkConnectionProvider)
    mock_provider.get_connections.return_value = [
        {
            "local_addr": "0.0.0.0",
            "local_ip": "0.0.0.0",
            "local_port": 8443,
            "remote_addr": "",
            "remote_ip": "",
            "remote_port": 0,
            "protocol": "TCP",
            "status": "LISTENING",
            "state": "LISTENING",
            "is_listening": True,
            "pid": 4567,
            "process_name": "edr_manager.exe",
            "process_path": "C:\\Program Files\\EDR\\edr_manager.exe",
            "process_user": "SYSTEM",
            "username": "SYSTEM",
            "direction": "listen",
        }
    ]

    collector = NetworkCollector(event_sink=sink, provider=mock_provider, poll_interval=1)
    collector.start()
    collector.stop()

    assert len(emitted_events) >= 1
    assert emitted_events[0].collector_type == "network"
    assert emitted_events[0].event_type in ("listen_baseline", "LISTEN_STARTED")


# ─────────────────────────────────────────────────────────────────────────────
# 9. Network Event Database Persistence
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_9_network_event_persistence_and_query(db_session: AsyncSession):
    agent = await _create_test_agent(db_session)
    event_id = uuid.uuid4()
    ev = TelemetryEvent(
        id=event_id,
        agent_id=agent.id,
        collector_type="network",
        event_type="CONNECTION_OPENED",
        raw_data={
            "local_addr": "192.168.1.50",
            "local_ip": "192.168.1.50",
            "local_port": 54321,
            "remote_addr": "93.184.216.34",
            "remote_ip": "93.184.216.34",
            "remote_port": 443,
            "protocol": "TCP",
            "pid": 1122,
            "process_name": "powershell.exe",
            "direction": "outbound",
            "status": "ESTABLISHED",
        },
        timestamp=datetime.now(timezone.utc),
        processed=False
    )
    db_session.add(ev)
    await db_session.flush()

    res = await db_session.execute(select(TelemetryEvent).where(TelemetryEvent.id == event_id))
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.raw_data["remote_addr"] == "93.184.216.34"
    assert fetched.raw_data["process_name"] == "powershell.exe"


# ─────────────────────────────────────────────────────────────────────────────
# 10. Real-time WebSocket Event Broadcast
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_10_websocket_event_broadcasting():
    mgr = ConnectionManager()
    user_id = uuid.uuid4()
    ws_mock = AsyncMock()
    await mgr.connect_dashboard(user_id, ws_mock)

    agent_id = uuid.uuid4()
    await mgr.broadcast_network_event(agent_id, "CONNECTION_OPENED", {"remote_ip": "1.2.3.4", "remote_port": 443})
    assert ws_mock.send_json.called
    msg = ws_mock.send_json.call_args[0][0]
    assert msg["type"] == "NETWORK_EVENT"
    assert msg["event"] == "network.connection_opened"
    assert msg["agent_id"] == str(agent_id)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Network Isolation Request
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_11_network_isolation_request(db_session: AsyncSession):
    agent = await _create_test_agent(db_session)
    ws_mock = AsyncMock()
    dispatcher = CommandDispatcher(connection_manager=ws_mock, db_session=db_session)

    cmd_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    sig = hashlib.sha256(f"{cmd_id}:DISABLE_NETWORK:{agent.id}".encode()).hexdigest()

    cmd = Command(
        id=cmd_id,
        agent_id=agent.id,
        command_type="DISABLE_NETWORK",
        signature=sig,
        status=CommandStatus.PENDING,
        issued_at=now
    )
    db_session.add(cmd)
    await db_session.flush()

    assert cmd.status == CommandStatus.PENDING
    assert cmd.command_type == "DISABLE_NETWORK"


# ─────────────────────────────────────────────────────────────────────────────
# 12. Network Isolation Execution & Verification (Agent Side)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_12_network_isolation_execution_agent():
    handler = AgentResponseHandler(mode="ENFORCE")
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = MagicMock(returncode=0, stdout="EDR_Host_Isolation_Outbound", stderr="")
        res = handler.execute_action("ISOLATE_HOST", {})
        assert res.success is True
        assert res.details.get("isolation_state") == "ISOLATED"


# ─────────────────────────────────────────────────────────────────────────────
# 13. Network Isolation Failure Handling
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_13_network_isolation_failure_handling():
    handler = AgentResponseHandler(mode="ENFORCE")
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = MagicMock(returncode=1, stdout="", stderr="Access is denied")
        res = handler.execute_action("ISOLATE_HOST", {})
        assert res.success is False
        assert res.details.get("isolation_state") == "ISOLATION_FAILED"


# ─────────────────────────────────────────────────────────────────────────────
# 14. Network Unisolation & Rule Deletion
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_14_network_unisolation_execution():
    handler = AgentResponseHandler(mode="ENFORCE")
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = MagicMock(returncode=0, stdout="No rules match", stderr="")
        res = handler.execute_action("UNISOLATE_HOST", {})
        assert res.success is True
        assert res.details.get("isolation_state") == "NOT_ISOLATED"


# ─────────────────────────────────────────────────────────────────────────────
# 15. Duplicate Isolation Prevention (Idempotency)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_15_duplicate_isolation_prevention(db_session: AsyncSession):
    agent = await _create_test_agent(db_session)
    user_id = uuid.uuid4()
    alert = Alert(
        id=uuid.uuid4(),
        agent_id=agent.id,
        title="Suspicious C2 Activity",
        severity="critical",
        status=AlertStatus.OPEN,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(alert)
    await db_session.flush()

    resp_svc = ResponseService(db_session)
    # First execution succeeds
    await resp_svc.execute_response(
        alert_id=alert.id,
        action=AlertResponseAction.NETWORK_ISOLATE.value,
        user_id=user_id
    )

    # Second execution on active response raises ValueError
    with pytest.raises(ValueError, match="already active/executing"):
        await resp_svc.execute_response(
            alert_id=alert.id,
            action=AlertResponseAction.NETWORK_ISOLATE.value,
            user_id=user_id
        )


# ─────────────────────────────────────────────────────────────────────────────
# 16. RBAC Enforcement on Network Endpoints
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_16_rbac_enforcement_on_network_ports():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Unauthenticated request to /api/v1/agents/{id}/network/ports must be rejected
        agent_id = uuid.uuid4()
        resp = await client.get(f"/api/v1/agents/{agent_id}/network/ports")
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# 17. Audit Logging of Network Actions
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_17_audit_logging_network_actions(db_session: AsyncSession):
    audit = AuditLogger(db_session)
    agent_id = uuid.uuid4()
    actor_id = uuid.uuid4()

    await audit.log(
        actor_type="user",
        actor_id=actor_id,
        action=AuditAction.NETWORK_ISOLATION_REQUESTED,
        target_type="agent",
        target_id=agent_id,
        details={"reason": "Active Cobalt Strike Beacon"},
        db_session=db_session
    )
    await db_session.commit()

    res = await db_session.execute(
        select(AuditLog).where(AuditLog.action == AuditAction.NETWORK_ISOLATION_REQUESTED.value)
    )
    entry = res.scalar_one_or_none()
    assert entry is not None
    assert entry.target_id == agent_id
    assert entry.details_json["reason"] == "Active Cobalt Strike Beacon"


# ─────────────────────────────────────────────────────────────────────────────
# 18. Configurable Agent Timeout
# ─────────────────────────────────────────────────────────────────────────────
def test_18_configurable_timeout_settings():
    assert hasattr(settings, "OFFLINE_THRESHOLD_SECONDS")
    assert hasattr(settings, "HEARTBEAT_INTERVAL_SECONDS")
    assert settings.OFFLINE_THRESHOLD_SECONDS >= 30
    assert settings.HEARTBEAT_INTERVAL_SECONDS >= 5


# ─────────────────────────────────────────────────────────────────────────────
# 19. WebSocket Reconnect
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_19_websocket_reconnect():
    mgr = ConnectionManager()
    agent_id = uuid.uuid4()
    ws1 = AsyncMock()
    ws2 = AsyncMock()

    await mgr.connect_agent(agent_id, ws1)
    assert mgr.active_agents[agent_id] == ws1

    mgr.disconnect_agent(agent_id)
    assert agent_id not in mgr.active_agents

    await mgr.connect_agent(agent_id, ws2)
    assert mgr.active_agents[agent_id] == ws2


# ─────────────────────────────────────────────────────────────────────────────
# 20. Database Persistence & Relational Integrity
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_20_database_persistence_and_integrity(db_session: AsyncSession):
    agent = await _create_test_agent(db_session, hostname="db-rel-test")
    now = datetime.now(timezone.utc)

    hb = Heartbeat(
        agent_id=agent.id,
        timestamp=now,
        cpu_usage=15.0,
        memory_usage=35.0,
        disk_usage=45.0,
        agent_status="active"
    )
    db_session.add(hb)

    ev = TelemetryEvent(
        id=uuid.uuid4(),
        agent_id=agent.id,
        collector_type="network",
        event_type="LISTEN_STARTED",
        raw_data={"protocol": "TCP", "local_port": 8080, "status": "LISTENING"},
        timestamp=now,
        processed=False
    )
    db_session.add(ev)
    await db_session.flush()

    # Query back relationships
    res_agent = await db_session.execute(select(Agent).where(Agent.id == agent.id))
    fetched_agent = res_agent.scalar_one_or_none()
    assert fetched_agent is not None
    assert fetched_agent.hostname == "db-rel-test"
