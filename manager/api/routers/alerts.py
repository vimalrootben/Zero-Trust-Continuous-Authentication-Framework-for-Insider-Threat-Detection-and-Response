import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.dependencies import get_db, get_current_user, require_permission
from manager.alerts.alert_service import AlertService, AlertFilters

router = APIRouter(prefix="/alerts", tags=["alerts"])

@router.get("")
async def list_alerts(
    agent_id: Optional[uuid.UUID] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    rule_id: Optional[uuid.UUID] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:read"))
):
    service = AlertService(db)
    filters = AlertFilters(agent_id=agent_id, status=status_filter, severity=severity, rule_id=rule_id)
    result = await service.list_alerts(filters, page=page, page_size=page_size)
    return {
        "items": [
            {
                "id": str(a.id),
                "agent_id": str(a.agent_id),
                "title": a.title,
                "description": a.description,
                "severity": a.severity.value,
                "status": a.status.value,
                "assigned_to": str(a.assigned_to) if a.assigned_to else None,
                "created_at": a.created_at.isoformat() if a.created_at else None
            }
            for a in result.items
        ],
        "total": result.total,
        "page": result.page,
        "page_size": result.page_size
    }

@router.put("/{alert_id}")
async def update_alert(
    alert_id: uuid.UUID,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:write"))
):
    service = AlertService(db)
    actor_id = uuid.UUID(str(user.id)) if hasattr(user, "id") and user.id else None
    alert = None

    if "status" in payload:
        try:
            alert = await service.update_status(alert_id, payload["status"], actor_id=actor_id)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    if "assigned_to" in payload:
        assignee = uuid.UUID(payload["assigned_to"]) if payload["assigned_to"] else None
        try:
            alert = await service.assign(alert_id, assignee, actor_id=actor_id)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    if not alert:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid update field provided")

    return {
        "id": str(alert.id),
        "status": alert.status.value,
        "assigned_to": str(alert.assigned_to) if alert.assigned_to else None
    }
