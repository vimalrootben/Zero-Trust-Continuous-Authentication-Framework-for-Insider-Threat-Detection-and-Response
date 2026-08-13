import uuid
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock

from manager.database.models.alert import Alert, AlertStatus
from manager.database.models.rule import Severity
from manager.alerts.alert_service import AlertService, AlertFilters

@pytest.mark.asyncio
async def test_alert_creation_and_timeline_recording(db_session):
    agent_id = uuid.uuid4()
    service = AlertService(db_session)

    alert = await service.create_alert(
        agent_id=agent_id,
        title="Suspicious Process Execution",
        description="powershell.exe executed encoded command",
        severity="high",
        db_session=db_session
    )

    assert alert.id is not None
    assert alert.title == "Suspicious Process Execution"
    assert alert.status == AlertStatus.OPEN
    assert alert.severity == Severity.HIGH

@pytest.mark.asyncio
async def test_alert_status_transition_valid_and_invalid(db_session):
    agent_id = uuid.uuid4()
    service = AlertService(db_session)

    alert = await service.create_alert(
        agent_id=agent_id,
        title="Test Alert",
        description="Test",
        severity="medium",
        db_session=db_session
    )

    # Open -> Acknowledged
    updated = await service.update_status(alert.id, "acknowledged", db_session=db_session)
    assert updated.status == AlertStatus.ACKNOWLEDGED

    # Acknowledged -> Resolved
    resolved = await service.update_status(alert.id, "resolved", db_session=db_session)
    assert resolved.status == AlertStatus.RESOLVED
    assert resolved.resolved_at is not None

    # Illegal transition: Resolved -> Acknowledged (must go through Open)
    with pytest.raises(ValueError, match="Illegal status transition"):
        await service.update_status(alert.id, "acknowledged", db_session=db_session)

@pytest.mark.asyncio
async def test_alert_assignment(db_session):
    agent_id = uuid.uuid4()
    user_id = uuid.uuid4()
    service = AlertService(db_session)

    alert = await service.create_alert(
        agent_id=agent_id,
        title="Test Assignment",
        description="Test",
        severity="low",
        db_session=db_session
    )

    assigned = await service.assign(alert.id, user_id, db_session=db_session)
    assert assigned.assigned_to == user_id
