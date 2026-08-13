import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, ForeignKey, DateTime, Index, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base, TimestampUUIDMixin

class TimelineEvent(Base, TimestampUUIDMixin):
    __tablename__ = "timeline_events"

    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=True, index=True)
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    event_source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # 'telemetry','alert', etc.
    event_ref_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(as_uuid=True), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    # Relationships
    agent: Mapped[Optional["Agent"]] = relationship("Agent")
    incident: Mapped[Optional["Incident"]] = relationship("Incident")

    __table_args__ = (
        Index("idx_timeline_agent_timestamp", "agent_id", "timestamp"),
        Index("idx_timeline_incident_timestamp", "incident_id", "timestamp"),
    )
