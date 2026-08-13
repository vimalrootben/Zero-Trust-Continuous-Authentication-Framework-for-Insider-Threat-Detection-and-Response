import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.dependencies import get_db, require_permission
from manager.audit.audit_logger import AuditLogger, AuditFilters

router = APIRouter(prefix="/audit-logs", tags=["audit"])

@router.get("")
async def list_audit_logs(
    actor_id: Optional[uuid.UUID] = Query(None),
    action: Optional[str] = Query(None),
    actor_type: Optional[str] = Query(None),
    target_type: Optional[str] = Query(None),
    target_id: Optional[uuid.UUID] = Query(None),
    start_time: Optional[datetime] = Query(None, alias="from"),
    end_time: Optional[datetime] = Query(None, alias="to"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("audit:read"))
):
    audit_logger = AuditLogger(db)
    filters = AuditFilters(
        actor_id=actor_id,
        action=action,
        actor_type=actor_type,
        target_type=target_type,
        target_id=target_id,
        start_time=start_time,
        end_time=end_time
    )
    result = await audit_logger.query(filters, page=page, page_size=page_size)
    return {
        "items": [
            {
                "id": str(item.id),
                "actor_type": item.actor_type.value,
                "actor_id": str(item.actor_id) if item.actor_id else None,
                "action": item.action,
                "target_type": item.target_type,
                "target_id": str(item.target_id) if item.target_id else None,
                "details": item.details_json,
                "ip_address": item.ip_address,
                "timestamp": item.timestamp.isoformat()
            }
            for item in result.items
        ],
        "total": result.total,
        "page": result.page,
        "page_size": result.page_size
    }
