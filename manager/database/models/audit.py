import enum
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Enum, DateTime, Index, JSON, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from manager.database.base import Base, TimestampUUIDMixin

class ActorType(str, enum.Enum):
    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"

class AuditLog(Base, TimestampUUIDMixin):
    __tablename__ = "audit_logs"

    actor_type: Mapped[ActorType] = mapped_column(
        Enum(ActorType, name="actor_type_enum"),
        nullable=False,
        index=True
    )
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(as_uuid=True), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(as_uuid=True), nullable=True, index=True)
    details_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    __table_args__ = (
        Index("idx_audit_logs_actor_id_timestamp", "actor_id", "timestamp"),
    )
