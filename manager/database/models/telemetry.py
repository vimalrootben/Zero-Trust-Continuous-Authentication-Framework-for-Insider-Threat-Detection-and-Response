import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Index, JSON, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base, TimestampUUIDMixin

class TelemetryEvent(Base, TimestampUUIDMixin):
    __tablename__ = "telemetry_events"

    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    collector_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    raw_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    processed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    correlation_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(as_uuid=True), nullable=True, index=True)

    # Relationships
    agent: Mapped["Agent"] = relationship("Agent", back_populates="telemetry_events")
    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="telemetry_event")

    __table_args__ = (
        Index("idx_telemetry_agent_timestamp", "agent_id", "timestamp"),
    )

