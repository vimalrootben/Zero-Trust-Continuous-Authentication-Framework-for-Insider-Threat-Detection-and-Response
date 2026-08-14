import uuid
import pytest
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from manager.database.models.agent import Agent, AgentStatus
from manager.database.models.alert import Alert, AlertStatus
from manager.database.models.alert_response import AlertResponse, AlertResponseStatus, AlertResponseAction
from manager.database.models.rule import Severity
from manager.database.models.auth import User
from manager.alerts.alert_service import AlertService, AlertFilters
from manager.alerts.response_service import ResponseService
from manager.audit.audit_logger import AuditLogger
from manager.audit.constants import AuditAction

@pytest.mark.asyncio
async def test_alert_creation_with_full_metadata(db_session: AsyncSession):
    # 1. Setup Agent
    agent = Agent(
        hostname="test-win-host",
        device_fingerprint="fp_test_win_host",
        ip_address="192.168.1.100",
        status=AgentStatus.ACTIVE,
        os_version="Windows 11 Enterprise"
    )
    db_session.add(agent)
    await db_session.flush()

    service = AlertService(db_session)
    alert = await service.create_alert(
        agent_id=agent.id,
        title="Suspicious Process Execution",
        description="powershell.exe spawned encoded command line",
        severity="high",
        risk_score=85.0,
        risk_level="HIGH",
        source="endpoint_telemetry",
        event_type="PROCESS_START",
        process_name="powershell.exe",
        process_id=4128,
        file_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        remote_ip="198.51.100.45",
        remote_port=443,
        username="DOMAIN\\malware_user",
        mitre_tactic="Execution",
        mitre_technique_id="T1059.001"
    )

    assert alert.id is not None
    assert alert.alert_id.startswith("ALT-")
    assert alert.process_name == "powershell.exe"
    assert alert.process_id == 4128
    assert alert.risk_score == 85.0
    assert alert.status == AlertStatus.OPEN

@pytest.mark.asyncio
async def test_alert_lifecycle_state_machine(db_session: AsyncSession):
    agent = Agent(hostname="host-lifecycle", device_fingerprint="fp_lifecycle", status=AgentStatus.ACTIVE)
    db_session.add(agent)
    await db_session.flush()

    service = AlertService(db_session)
    alert = await service.create_alert(
        agent_id=agent.id,
        title="Test Lifecycle Alert",
        description="Testing state transitions",
        severity="medium"
    )

    # Valid transitions: OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED
    alert = await service.update_status(alert.id, AlertStatus.ACKNOWLEDGED)
    assert alert.status == AlertStatus.ACKNOWLEDGED

    alert = await service.update_status(alert.id, AlertStatus.INVESTIGATING)
    assert alert.status == AlertStatus.INVESTIGATING

    alert = await service.update_status(alert.id, AlertStatus.RESOLVED)
    assert alert.status == AlertStatus.RESOLVED
    assert alert.resolved_at is not None

    # Reopen: RESOLVED -> OPEN
    alert = await service.update_status(alert.id, AlertStatus.OPEN)
    assert alert.status == AlertStatus.OPEN

    # Illegal transition: OPEN -> RESPONDING (must be RESPONSE_PENDING)
    with pytest.raises(ValueError, match="Illegal status transition"):
        await service.update_status(alert.id, AlertStatus.RESPONDING)

@pytest.mark.asyncio
async def test_response_service_process_terminate(db_session: AsyncSession):
    # Setup Agent & User
    user = User(username="analyst_test", password_hash="hash", email="analyst@test.local")
    agent = Agent(hostname="host-response", device_fingerprint="fp_response", status=AgentStatus.ACTIVE)
    db_session.add_all([user, agent])
    await db_session.flush()

    service = AlertService(db_session)
    alert = await service.create_alert(
        agent_id=agent.id,
        title="Malicious Process",
        description="Terminable process alert",
        severity="critical",
        process_name="mimikatz.exe",
        process_id=9988
    )

    resp_service = ResponseService(db_session)
    resp = await resp_service.execute_response(
        alert_id=alert.id,
        action=AlertResponseAction.PROCESS_TERMINATE.value,
        user_id=user.id
    )

    assert resp.id is not None
    assert resp.action == AlertResponseAction.PROCESS_TERMINATE.value
    assert resp.status == AlertResponseStatus.DISPATCHED
    assert resp.command_id is not None

    # Check alert state updated to RESPONSE_PENDING
    updated_alert = await service.get_alert(alert.id)
    assert updated_alert.status == AlertStatus.RESPONSE_PENDING
    assert updated_alert.response_action == AlertResponseAction.PROCESS_TERMINATE.value

    # Simulate Agent execution result
    await resp_service.handle_agent_result(
        command_id=resp.command_id,
        success=True,
        output={"message": "Process mimikatz.exe (PID 9988) terminated successfully", "terminated_pids": [9988]}
    )

    # Verify Alert & Response completed as SUCCESS & RESOLVED
    final_alert = await service.get_alert(alert.id)
    assert final_alert.status == AlertStatus.RESOLVED
    assert final_alert.response_status == AlertResponseStatus.SUCCESS.value

    responses = await resp_service.list_alert_responses(alert.id)
    assert len(responses) == 1
    assert responses[0].status == AlertResponseStatus.SUCCESS

@pytest.mark.asyncio
async def test_response_service_idempotency_duplicate_prevention(db_session: AsyncSession):
    user = User(username="admin_idemp", password_hash="hash", email="admin@test.local")
    agent = Agent(hostname="host-idemp", device_fingerprint="fp_idemp", status=AgentStatus.ACTIVE)
    db_session.add_all([user, agent])
    await db_session.flush()

    service = AlertService(db_session)
    alert = await service.create_alert(
        agent_id=agent.id,
        title="Network Isolation Test",
        description="Isolate host alert",
        severity="high"
    )

    resp_service = ResponseService(db_session)

    # First isolation request
    resp1 = await resp_service.execute_response(
        alert_id=alert.id,
        action=AlertResponseAction.NETWORK_ISOLATE.value,
        user_id=user.id
    )
    assert resp1.status == AlertResponseStatus.DISPATCHED

    # Second duplicate request while active should fail
    with pytest.raises(ValueError, match="already active/executing"):
        await resp_service.execute_response(
            alert_id=alert.id,
            action=AlertResponseAction.NETWORK_ISOLATE.value,
            user_id=user.id
        )

@pytest.mark.asyncio
async def test_response_service_parameter_validation_failure(db_session: AsyncSession):
    user = User(username="admin_val", password_hash="hash", email="val@test.local")
    agent = Agent(hostname="host-val", device_fingerprint="fp_val", status=AgentStatus.ACTIVE)
    db_session.add_all([user, agent])
    await db_session.flush()

    service = AlertService(db_session)
    # Alert missing process_id or process_name
    alert = await service.create_alert(
        agent_id=agent.id,
        title="Missing Params Alert",
        description="No process details",
        severity="low"
    )

    resp_service = ResponseService(db_session)

    with pytest.raises(ValueError, match="requires target 'pid' or 'process_name'"):
        await resp_service.execute_response(
            alert_id=alert.id,
            action=AlertResponseAction.PROCESS_TERMINATE.value,
            user_id=user.id
        )

@pytest.mark.asyncio
async def test_response_failure_path(db_session: AsyncSession):
    user = User(username="admin_fail", password_hash="hash", email="fail@test.local")
    agent = Agent(hostname="host-fail", device_fingerprint="fp_fail", status=AgentStatus.ACTIVE)
    db_session.add_all([user, agent])
    await db_session.flush()

    service = AlertService(db_session)
    alert = await service.create_alert(
        agent_id=agent.id,
        title="File Quarantine Alert",
        description="Quarantine target file",
        severity="high",
        file_path="C:\\non_existent_file.exe"
    )

    resp_service = ResponseService(db_session)
    resp = await resp_service.execute_response(
        alert_id=alert.id,
        action=AlertResponseAction.FILE_QUARANTINE.value,
        user_id=user.id
    )

    # Agent returns failure result
    await resp_service.handle_agent_result(
        command_id=resp.command_id,
        success=False,
        error_msg="Quarantine target file does not exist: C:\\non_existent_file.exe"
    )

    failed_alert = await service.get_alert(alert.id)
    assert failed_alert.status == AlertStatus.RESPONSE_FAILED
    assert failed_alert.response_status == AlertResponseStatus.FAILED.value
    assert "does not exist" in failed_alert.response_error
