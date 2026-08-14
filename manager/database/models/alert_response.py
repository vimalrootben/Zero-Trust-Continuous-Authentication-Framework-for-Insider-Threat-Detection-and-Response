import enum
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, ForeignKey, DateTime, Enum, Index, JSON, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base, TimestampUUIDMixin

class AlertResponseStatus(str, enum.Enum):
    PENDING = "pending"
    AUTHORIZED = "authorized"
    DISPATCHED = "dispatched"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    REJECTED = "rejected"

class AlertResponseAction(str, enum.Enum):
    PROCESS_TERMINATE = "process_terminate"
    NETWORK_ISOLATE = "network_isolate"
    NETWORK_UNISOLATE = "network_unisolate"
    USER_LOGOUT = "user_logout"
    WORKSTATION_LOCK = "workstation_lock"
    FILE_QUARANTINE = "file_quarantine"

class AlertResponse(Base, TimestampUUIDMixin):
    __tablename__ = "alert_responses"

    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[AlertResponseStatus] = mapped_column(
        Enum(AlertResponseStatus, name="alert_response_status_type"),
        default=AlertResponseStatus.PENDING,
        nullable=False,
        index=True
    )
    requested_by: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    authorized_by: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    command_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("commands.id", ondelete="SET NULL"), nullable=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    result_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    alert: Mapped["Alert"] = relationship("Alert", back_populates="responses")
    agent: Mapped["Agent"] = relationship("Agent")
    requester: Mapped[Optional["User"]] = relationship("User", foreign_keys=[requested_by])
    authorizer: Mapped[Optional["User"]] = relationship("User", foreign_keys=[authorized_by])
    command: Mapped[Optional["Command"]] = relationship("Command")

    __table_args__ = (
        Index("idx_alert_responses_alert_status", "alert_id", "status"),
    )
