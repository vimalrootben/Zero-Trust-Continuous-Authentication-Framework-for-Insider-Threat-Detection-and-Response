import enum
import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Text, ForeignKey, DateTime, Enum, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base, TimestampUUIDMixin
from manager.database.models.rule import Severity

class AlertStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class Alert(Base, TimestampUUIDMixin):
    __tablename__ = "alerts"

    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("rules.id", ondelete="SET NULL"), nullable=True)
    telemetry_event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("telemetry_events.id", ondelete="SET NULL"),
        nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="alert_severity_type"),
        nullable=False,
        index=True
    )
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("mitre_techniques.technique_id", ondelete="SET NULL"),
        nullable=True
    )
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status_type"),
        default=AlertStatus.OPEN,
        nullable=False,
        index=True
    )
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    agent: Mapped["Agent"] = relationship("Agent", back_populates="alerts")
    rule: Mapped[Optional["Rule"]] = relationship("Rule", back_populates="alerts")
    telemetry_event: Mapped[Optional["TelemetryEvent"]] = relationship("TelemetryEvent", back_populates="alerts")
    mitre_technique: Mapped[Optional["MitreTechnique"]] = relationship("MitreTechnique", back_populates="alerts")
    assignee: Mapped[Optional["User"]] = relationship("User")
    incidents: Mapped[List["Incident"]] = relationship(
        "Incident",
        secondary="incident_alerts",
        back_populates="alerts"
    )

    __table_args__ = (
        Index("idx_alerts_agent_status_severity", "agent_id", "status", "severity"),
    )
