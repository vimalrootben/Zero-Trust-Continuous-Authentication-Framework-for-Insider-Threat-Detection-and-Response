import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Any
from dataclasses import dataclass
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from manager.database.models.alert import Alert, AlertStatus
from manager.database.models.rule import Severity
from manager.timeline.timeline_service import TimelineService
from manager.audit.audit_logger import AuditLogger
from manager.audit.constants import AuditAction

logger = logging.getLogger(__name__)

# Valid state machine transitions
ALLOWED_TRANSITIONS = {
    AlertStatus.OPEN: {AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE},
    AlertStatus.ACKNOWLEDGED: {AlertStatus.INVESTIGATING, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE},
    AlertStatus.INVESTIGATING: {AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE, AlertStatus.OPEN},
    AlertStatus.RESOLVED: {AlertStatus.OPEN},
    AlertStatus.FALSE_POSITIVE: {AlertStatus.OPEN},
}

@dataclass
class AlertFilters:
    agent_id: Optional[uuid.UUID] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    rule_id: Optional[uuid.UUID] = None

@dataclass
class PaginatedAlerts:
    items: List[Alert]
    total: int
    page: int
    page_size: int

class AlertService:
    """Service for managing alerts, lifecycle state transitions, timeline recording, and notifications."""

    def __init__(
        self,
        db_session: Optional[AsyncSession] = None,
        timeline_service: Optional[TimelineService] = None,
        audit_logger: Optional[AuditLogger] = None,
        ws_connection_manager: Optional[Any] = None,
        notification_worker: Optional[Any] = None
    ):
        self.db_session = db_session
        self.timeline_service = timeline_service or TimelineService(db_session)
        self.audit_logger = audit_logger or AuditLogger(db_session)
        self.ws_connection_manager = ws_connection_manager
        self.notification_worker = notification_worker

    async def create_alert(
        self,
        agent_id: uuid.UUID,
        title: str,
        description: str,
        severity: str,
        rule_id: Optional[uuid.UUID] = None,
        telemetry_event_id: Optional[uuid.UUID] = None,
        mitre_technique_id: Optional[str] = None,
        db_session: Optional[AsyncSession] = None
    ) -> Alert:
        session = db_session or self.db_session
        if session is None:
            raise ValueError("Database session required to create alert")

        sev_enum = Severity(severity) if isinstance(severity, str) else severity

        alert = Alert(
            agent_id=agent_id,
            title=title,
            description=description,
            severity=sev_enum,
            rule_id=rule_id,
            telemetry_event_id=telemetry_event_id,
            mitre_technique_id=mitre_technique_id,
            status=AlertStatus.OPEN
        )

        session.add(alert)
        await session.flush()

        # Record timeline event
        await self.timeline_service.record_event(
            agent_id=agent_id,
            event_source="alert",
            event_ref_id=alert.id,
            description=f"Alert created: {title} ({severity.upper()})",
            db_session=session
        )

        # Audit Log
        await self.audit_logger.log(
            actor_type="system",
            actor_id=None,
            action=AuditAction.ALERT_CREATED,
            target_type="alert",
            target_id=alert.id,
            details={"title": title, "severity": str(severity), "agent_id": str(agent_id)},
            db_session=session
        )

        # WebSocket push if available
        if self.ws_connection_manager:
            try:
                await self.ws_connection_manager.broadcast({
                    "type": "ALERT_CREATED",
                    "alert_id": str(alert.id),
                    "title": title,
                    "severity": str(severity),
                    "agent_id": str(agent_id)
                })
            except Exception as exc:
                logger.error(f"Failed to push alert WebSocket notification: {exc}")

        # Worker job enqueue for HIGH/CRITICAL severity alerts
        if str(severity).lower() in ("high", "critical") and self.notification_worker:
            try:
                await self.notification_worker.enqueue("send_alert_notification", {"alert_id": str(alert.id)})
            except Exception as exc:
                logger.error(f"Failed to enqueue notification worker job: {exc}")

        return alert

    async def update_status(
        self,
        alert_id: uuid.UUID,
        new_status: str,
        actor_id: Optional[uuid.UUID] = None,
        db_session: Optional[AsyncSession] = None
    ) -> Alert:
        session = db_session or self.db_session
        if session is None:
            raise ValueError("Database session required")

        result = await session.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise ValueError(f"Alert {alert_id} not found")

        target_status = AlertStatus(new_status) if isinstance(new_status, str) else new_status
        current_status = alert.status

        if target_status not in ALLOWED_TRANSITIONS.get(current_status, set()):
            raise ValueError(f"Illegal status transition from '{current_status.value}' to '{target_status.value}'")

        alert.status = target_status
        if target_status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
            alert.resolved_at = datetime.now(timezone.utc)
        elif current_status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE) and target_status == AlertStatus.OPEN:
            alert.resolved_at = None

        await session.flush()

        # Audit Log
        await self.audit_logger.log(
            actor_type="user" if actor_id else "system",
            actor_id=actor_id,
            action=AuditAction.ALERT_STATUS_UPDATED,
            target_type="alert",
            target_id=alert.id,
            details={"old_status": current_status.value, "new_status": target_status.value},
            db_session=session
        )

        return alert

    async def assign(
        self,
        alert_id: uuid.UUID,
        user_id: Optional[uuid.UUID],
        actor_id: Optional[uuid.UUID] = None,
        db_session: Optional[AsyncSession] = None
    ) -> Alert:
        session = db_session or self.db_session
        if session is None:
            raise ValueError("Database session required")

        result = await session.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise ValueError(f"Alert {alert_id} not found")

        alert.assigned_to = user_id
        await session.flush()

        await self.audit_logger.log(
            actor_type="user" if actor_id else "system",
            actor_id=actor_id,
            action=AuditAction.ALERT_ASSIGNED,
            target_type="alert",
            target_id=alert.id,
            details={"assigned_to": str(user_id) if user_id else None},
            db_session=session
        )

        return alert

    async def list_alerts(
        self,
        filters: AlertFilters,
        page: int = 1,
        page_size: int = 50,
        db_session: Optional[AsyncSession] = None
    ) -> PaginatedAlerts:
        session = db_session or self.db_session
        if session is None:
            return PaginatedAlerts(items=[], total=0, page=page, page_size=page_size)

        stmt = select(Alert)
        count_stmt = select(func.count(Alert.id))

        if filters.agent_id:
            stmt = stmt.where(Alert.agent_id == filters.agent_id)
            count_stmt = count_stmt.where(Alert.agent_id == filters.agent_id)
        if filters.status:
            stmt = stmt.where(Alert.status == filters.status)
            count_stmt = count_stmt.where(Alert.status == filters.status)
        if filters.severity:
            stmt = stmt.where(Alert.severity == filters.severity)
            count_stmt = count_stmt.where(Alert.severity == filters.severity)
        if filters.rule_id:
            stmt = stmt.where(Alert.rule_id == filters.rule_id)
            count_stmt = count_stmt.where(Alert.rule_id == filters.rule_id)

        total_res = await session.execute(count_stmt)
        total = total_res.scalar() or 0

        offset = (page - 1) * page_size
        stmt = stmt.order_by(desc(Alert.created_at)).offset(offset).limit(page_size)

        result = await session.execute(stmt)
        items = list(result.scalars().all())

        return PaginatedAlerts(items=items, total=total, page=page, page_size=page_size)
