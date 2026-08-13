import enum
import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Text, ForeignKey, DateTime, Enum, Table, Column, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base, TimestampUUIDMixin
from manager.database.models.rule import Severity

class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"

# Association table for Incident <-> Alert Many-to-Many
incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
)

class Incident(Base, TimestampUUIDMixin):
    __tablename__ = "incidents"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="incident_severity_type"),
        nullable=False,
        index=True
    )
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, name="incident_status_type"),
        default=IncidentStatus.OPEN,
        nullable=False,
        index=True
    )
    agent_ids: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_by: Mapped[str] = mapped_column(String(32), default="system", nullable=False)
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    assignee: Mapped[Optional["User"]] = relationship("User")
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert",
        secondary=incident_alerts,
        back_populates="incidents"
    )
