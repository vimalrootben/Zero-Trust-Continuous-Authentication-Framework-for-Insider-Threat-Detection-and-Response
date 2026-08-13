import uuid
import pytest
from unittest.mock import MagicMock, AsyncMock

from manager.audit.audit_logger import AuditLogger, AuditFilters
from manager.audit.constants import AuditAction

@pytest.mark.asyncio
async def test_audit_logger_db_and_query(db_session):
    logger_service = AuditLogger(db_session)
    actor_id = uuid.uuid4()

    await logger_service.log(
        actor_type="user",
        actor_id=actor_id,
        action=AuditAction.LOGIN_SUCCESS,
        target_type="user",
        target_id=actor_id,
        details={"ip": "127.0.0.1"},
        db_session=db_session
    )

    result = await logger_service.query(
        filters=AuditFilters(actor_id=actor_id, action=AuditAction.LOGIN_SUCCESS),
        db_session=db_session
    )

    assert result.total == 1
    assert result.items[0].action == AuditAction.LOGIN_SUCCESS
    assert result.items[0].actor_id == actor_id

@pytest.mark.asyncio
async def test_audit_logger_fallback_on_db_error():
    failing_session = AsyncMock()
    failing_session.add.side_effect = Exception("DB Connection Error")
    
    logger_service = AuditLogger(failing_session)

    # Should not raise exception, falls back gracefully
    await logger_service.log(
        actor_type="system",
        actor_id=None,
        action=AuditAction.SELF_PROTECTION_EVENT,
        details={"guard": "service_guard"},
        db_session=failing_session
    )
