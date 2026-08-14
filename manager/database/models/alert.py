import enum
import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Text, ForeignKey, DateTime, Enum, Index, Float, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base, TimestampUUIDMixin
from manager.database.models.rule import Severity

class AlertStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESPONSE_PENDING = "response_pending"
    RESPONDING = "responding"
    RESOLVED = "resolved"
    RESPONSE_FAILED = "response_failed"
    CANCELLED = "cancelled"
    FALSE_POSITIVE = "false_positive"

class Alert(Base, TimestampUUIDMixin):
    __tablename__ = "alerts"

    alert_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    policy_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("policies.id", ondelete="SET NULL"), nullable=True)
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("rules.id", ondelete="SET NULL"), nullable=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
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
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_level: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(64), default="endpoint_telemetry", nullable=True)
    event_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    process_id: Mapped[Optional[int]] = mapped_column(nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remote_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    remote_port: Mapped[Optional[int]] = mapped_column(nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
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
    detected_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Response tracking columns
    response_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    response_action: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    response_requested_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    response_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    response_completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    response_result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    response_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    agent: Mapped["Agent"] = relationship("Agent", back_populates="alerts")
    policy: Mapped[Optional["Policy"]] = relationship("Policy")
    rule: Mapped[Optional["Rule"]] = relationship("Rule", back_populates="alerts")
    telemetry_event: Mapped[Optional["TelemetryEvent"]] = relationship("TelemetryEvent", back_populates="alerts")
    mitre_technique: Mapped[Optional["MitreTechnique"]] = relationship("MitreTechnique", back_populates="alerts")
    assignee: Mapped[Optional["User"]] = relationship("User")
    responses: Mapped[List["AlertResponse"]] = relationship("AlertResponse", back_populates="alert", cascade="all, delete-orphan")
    incidents: Mapped[List["Incident"]] = relationship(
        "Incident",
        secondary="incident_alerts",
        back_populates="alerts"
    )

    __table_args__ = (
        Index("idx_alerts_agent_status_severity", "agent_id", "status", "severity"),
    )
