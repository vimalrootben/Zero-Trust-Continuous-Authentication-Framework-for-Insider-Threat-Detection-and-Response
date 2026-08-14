import uuid
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.dependencies import get_db, get_current_user, require_permission
from manager.alerts.alert_service import AlertService, AlertFilters
from manager.alerts.response_service import ResponseService
from manager.database.models.alert import AlertStatus
from manager.database.models.alert_response import AlertResponseAction
from manager.api.routers.websocket import ws_manager

router = APIRouter(prefix="/alerts", tags=["alerts"])

class ResponseActionRequest(BaseModel):
    params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Action specific parameters e.g. pid, file_path")

def serialize_alert(a) -> dict:
    return {
        "id": str(a.id),
        "alert_id": a.alert_id,
        "agent_id": str(a.agent_id),
        "policy_id": str(a.policy_id) if a.policy_id else None,
        "rule_id": str(a.rule_id) if a.rule_id else None,
        "correlation_id": a.correlation_id,
        "telemetry_event_id": str(a.telemetry_event_id) if a.telemetry_event_id else None,
        "title": a.title,
        "description": a.description,
        "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
        "risk_score": a.risk_score,
        "risk_level": a.risk_level,
        "source": a.source,
        "event_type": a.event_type,
        "process_name": a.process_name,
        "process_id": a.process_id,
        "file_path": a.file_path,
        "remote_ip": a.remote_ip,
        "remote_port": a.remote_port,
        "username": a.username,
        "mitre_tactic": a.mitre_tactic,
        "mitre_technique_id": a.mitre_technique_id,
        "status": a.status.value if hasattr(a.status, "value") else str(a.status),
        "assigned_to": str(a.assigned_to) if a.assigned_to else None,
        "detected_at": a.detected_at.isoformat() if a.detected_at else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
        "response_status": a.response_status,
        "response_action": a.response_action,
        "response_requested_at": a.response_requested_at.isoformat() if a.response_requested_at else None,
        "response_started_at": a.response_started_at.isoformat() if a.response_started_at else None,
        "response_completed_at": a.response_completed_at.isoformat() if a.response_completed_at else None,
        "response_result": a.response_result,
        "response_error": a.response_error,
    }

def serialize_response(r) -> dict:
    return {
        "id": str(r.id),
        "alert_id": str(r.alert_id),
        "agent_id": str(r.agent_id),
        "action": r.action,
        "status": r.status.value if hasattr(r.status, "value") else str(r.status),
        "requested_by": str(r.requested_by) if r.requested_by else None,
        "authorized_by": str(r.authorized_by) if r.authorized_by else None,
        "command_id": str(r.command_id) if r.command_id else None,
        "correlation_id": r.correlation_id,
        "requested_at": r.requested_at.isoformat() if r.requested_at else None,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "result_json": r.result_json,
        "error_message": r.error_message,
    }

@router.get("")
async def list_alerts(
    agent_id: Optional[uuid.UUID] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    rule_id: Optional[uuid.UUID] = Query(None),
    policy_id: Optional[uuid.UUID] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:read"))
):
    service = AlertService(db, ws_connection_manager=ws_manager)
    filters = AlertFilters(agent_id=agent_id, status=status_filter, severity=severity, rule_id=rule_id, policy_id=policy_id)
    result = await service.list_alerts(filters, page=page, page_size=page_size)
    return {
        "items": [serialize_alert(a) for a in result.items],
        "total": result.total,
        "page": result.page,
        "page_size": result.page_size
    }

@router.get("/{alert_id}")
async def get_alert_detail(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:read"))
):
    service = AlertService(db)
    alert = await service.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {alert_id} not found")

    resp_service = ResponseService(db)
    responses = await resp_service.list_alert_responses(alert_id)

    data = serialize_alert(alert)
    data["responses"] = [serialize_response(r) for r in responses]
    return data

@router.put("/{alert_id}")
async def update_alert(
    alert_id: uuid.UUID,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:write"))
):
    service = AlertService(db, ws_connection_manager=ws_manager)
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

    return serialize_alert(alert)

# Lifecycle Action Endpoints
@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:write"))
):
    service = AlertService(db, ws_connection_manager=ws_manager)
    actor_id = uuid.UUID(str(user.id)) if hasattr(user, "id") and user.id else None
    try:
        alert = await service.update_status(alert_id, AlertStatus.ACKNOWLEDGED, actor_id=actor_id)
        return serialize_alert(alert)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@router.post("/{alert_id}/investigate")
async def investigate_alert(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:write"))
):
    service = AlertService(db, ws_connection_manager=ws_manager)
    actor_id = uuid.UUID(str(user.id)) if hasattr(user, "id") and user.id else None
    try:
        alert = await service.update_status(alert_id, AlertStatus.INVESTIGATING, actor_id=actor_id)
        return serialize_alert(alert)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:write"))
):
    service = AlertService(db, ws_connection_manager=ws_manager)
    actor_id = uuid.UUID(str(user.id)) if hasattr(user, "id") and user.id else None
    try:
        alert = await service.update_status(alert_id, AlertStatus.RESOLVED, actor_id=actor_id)
        return serialize_alert(alert)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

# Response Control Endpoints
@router.post("/{alert_id}/responses/process-terminate")
async def response_process_terminate(
    alert_id: uuid.UUID,
    req: Optional[ResponseActionRequest] = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:write"))
):
    params = req.params if req else {}
    resp_service = ResponseService(db, ws_manager=ws_manager)
    try:
        resp = await resp_service.execute_response(alert_id, AlertResponseAction.PROCESS_TERMINATE.value, user.id, params)
        return serialize_response(resp)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@router.post("/{alert_id}/responses/network-isolate")
async def response_network_isolate(
    alert_id: uuid.UUID,
    req: Optional[ResponseActionRequest] = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:write"))
):
    params = req.params if req else {}
    resp_service = ResponseService(db, ws_manager=ws_manager)
    try:
        resp = await resp_service.execute_response(alert_id, AlertResponseAction.NETWORK_ISOLATE.value, user.id, params)
        return serialize_response(resp)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@router.post("/{alert_id}/responses/network-unisolate")
async def response_network_unisolate(
    alert_id: uuid.UUID,
    req: Optional[ResponseActionRequest] = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:write"))
):
    params = req.params if req else {}
    resp_service = ResponseService(db, ws_manager=ws_manager)
    try:
        resp = await resp_service.execute_response(alert_id, AlertResponseAction.NETWORK_UNISOLATE.value, user.id, params)
        return serialize_response(resp)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@router.post("/{alert_id}/responses/logout")
async def response_logout(
    alert_id: uuid.UUID,
    req: Optional[ResponseActionRequest] = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:write"))
):
    params = req.params if req else {}
    resp_service = ResponseService(db, ws_manager=ws_manager)
    try:
        resp = await resp_service.execute_response(alert_id, AlertResponseAction.USER_LOGOUT.value, user.id, params)
        return serialize_response(resp)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@router.post("/{alert_id}/responses/lock")
async def response_lock(
    alert_id: uuid.UUID,
    req: Optional[ResponseActionRequest] = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:write"))
):
    params = req.params if req else {}
    resp_service = ResponseService(db, ws_manager=ws_manager)
    try:
        resp = await resp_service.execute_response(alert_id, AlertResponseAction.WORKSTATION_LOCK.value, user.id, params)
        return serialize_response(resp)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@router.post("/{alert_id}/responses/quarantine")
async def response_quarantine(
    alert_id: uuid.UUID,
    req: Optional[ResponseActionRequest] = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:write"))
):
    params = req.params if req else {}
    resp_service = ResponseService(db, ws_manager=ws_manager)
    try:
        resp = await resp_service.execute_response(alert_id, AlertResponseAction.FILE_QUARANTINE.value, user.id, params)
        return serialize_response(resp)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@router.get("/{alert_id}/responses")
async def list_alert_responses(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_permission("alerts:read"))
):
    resp_service = ResponseService(db)
    responses = await resp_service.list_alert_responses(alert_id)
    return [serialize_response(r) for r in responses]
