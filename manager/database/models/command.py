import enum
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, ForeignKey, DateTime, Enum, Index, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base, TimestampUUIDMixin

class CommandStatus(str, enum.Enum):
    PENDING = "pending"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    EXPIRED = "expired"

class Command(Base, TimestampUUIDMixin):
    __tablename__ = "commands"

    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    command_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    issued_by: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    policy_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("policies.id", ondelete="SET NULL"), nullable=True)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[CommandStatus] = mapped_column(
        Enum(CommandStatus, name="command_status_type"),
        default=CommandStatus.PENDING,
        nullable=False,
        index=True
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    result_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Relationships
    agent: Mapped["Agent"] = relationship("Agent", back_populates="commands")
    issuer: Mapped[Optional["User"]] = relationship("User")
    policy: Mapped[Optional["Policy"]] = relationship("Policy", back_populates="commands")

    __table_args__ = (
        Index("idx_commands_agent_status", "agent_id", "status"),
    )
