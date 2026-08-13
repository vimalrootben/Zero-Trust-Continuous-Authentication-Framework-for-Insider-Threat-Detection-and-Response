import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, Any, Dict, List
from dataclasses import dataclass
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from manager.database.models.audit import AuditLog, ActorType
from manager.audit.constants import AuditAction

logger = logging.getLogger(__name__)

FALLBACK_LOG_DIR = "logs"
FALLBACK_LOG_FILE = os.path.join(FALLBACK_LOG_DIR, "audit_fallback.log")

@dataclass
class AuditFilters:
    actor_id: Optional[uuid.UUID] = None
    action: Optional[str] = None
    actor_type: Optional[str] = None
    target_type: Optional[str] = None
    target_id: Optional[uuid.UUID] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

@dataclass
class PaginatedAuditLogs:
    items: List[AuditLog]
    total: int
    page: int
    page_size: int

class AuditLogger:
    """Manager Audit Logger supporting async DB persistence with file fallback."""

    def __init__(self, db_session: Optional[AsyncSession] = None):
        self.db_session = db_session

    async def log(
        self,
        actor_type: str,
        actor_id: Optional[uuid.UUID],
        action: str,
        target_type: Optional[str] = None,
        target_id: Optional[uuid.UUID] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        db_session: Optional[AsyncSession] = None
    ) -> None:
        session = db_session or self.db_session
        ts = datetime.now(timezone.utc)
        
        try:
            parsed_actor_type = ActorType(actor_type) if isinstance(actor_type, str) else actor_type
        except ValueError:
            parsed_actor_type = ActorType.SYSTEM

        audit_entry = AuditLog(
            actor_type=parsed_actor_type,
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details_json=details or {},
            ip_address=ip_address,
            timestamp=ts
        )

        if session is not None:
            try:
                session.add(audit_entry)
                await session.flush()
                return
            except Exception as exc:
                logger.error(f"Failed writing audit log to DB: {exc}. Falling back to file logging.")

        # Fallback to local file logging
        self._log_to_file(audit_entry)

    def log_self_protection_event(self, event: str, details: Dict[str, Any]):
        """Synchronous wrapper for agent-side self-protection logging fallback."""
        logger.info(f"[AUDIT] SelfProtection Event: {event} | Details: {details}")

    def _log_to_file(self, entry: AuditLog):
        try:
            os.makedirs(FALLBACK_LOG_DIR, exist_ok=True)
            with open(FALLBACK_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(
                    f"{entry.timestamp.isoformat()} | {entry.actor_type} | {entry.actor_id} | "
                    f"{entry.action} | {entry.target_type}:{entry.target_id} | {entry.details_json} | {entry.ip_address}\n"
                )
        except Exception as file_exc:
            logger.critical(f"Critical failure: Audit file logging also failed: {file_exc}")

    async def query(
        self,
        filters: AuditFilters,
        page: int = 1,
        page_size: int = 50,
        db_session: Optional[AsyncSession] = None
    ) -> PaginatedAuditLogs:
        session = db_session or self.db_session
        if session is None:
            return PaginatedAuditLogs(items=[], total=0, page=page, page_size=page_size)

        stmt = select(AuditLog)
        count_stmt = select(func.count(AuditLog.id))

        if filters.actor_id:
            stmt = stmt.where(AuditLog.actor_id == filters.actor_id)
            count_stmt = count_stmt.where(AuditLog.actor_id == filters.actor_id)
        if filters.action:
            stmt = stmt.where(AuditLog.action == filters.action)
            count_stmt = count_stmt.where(AuditLog.action == filters.action)
        if filters.actor_type:
            stmt = stmt.where(AuditLog.actor_type == filters.actor_type)
            count_stmt = count_stmt.where(AuditLog.actor_type == filters.actor_type)
        if filters.target_type:
            stmt = stmt.where(AuditLog.target_type == filters.target_type)
            count_stmt = count_stmt.where(AuditLog.target_type == filters.target_type)
        if filters.target_id:
            stmt = stmt.where(AuditLog.target_id == filters.target_id)
            count_stmt = count_stmt.where(AuditLog.target_id == filters.target_id)
        if filters.start_time:
            stmt = stmt.where(AuditLog.timestamp >= filters.start_time)
            count_stmt = count_stmt.where(AuditLog.timestamp >= filters.start_time)
        if filters.end_time:
            stmt = stmt.where(AuditLog.timestamp <= filters.end_time)
            count_stmt = count_stmt.where(AuditLog.timestamp <= filters.end_time)

        total_res = await session.execute(count_stmt)
        total = total_res.scalar() or 0

        offset = (page - 1) * page_size
        stmt = stmt.order_by(desc(AuditLog.timestamp)).offset(offset).limit(page_size)

        result = await session.execute(stmt)
        items = list(result.scalars().all())

        return PaginatedAuditLogs(items=items, total=total, page=page, page_size=page_size)
