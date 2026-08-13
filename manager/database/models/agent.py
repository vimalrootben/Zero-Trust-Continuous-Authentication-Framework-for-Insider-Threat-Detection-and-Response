import enum
import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Integer, Float, DateTime, Boolean, ForeignKey, Enum, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base, TimestampUUIDMixin

class AgentStatus(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    OFFLINE = "offline"
    QUARANTINED = "quarantined"
    DECOMMISSIONED = "decommissioned"

class SyncStatus(str, enum.Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"

class Agent(Base, TimestampUUIDMixin):
    __tablename__ = "agents"

    hostname: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    device_fingerprint: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    agent_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus, name="agent_status_type"),
        default=AgentStatus.PENDING,
        nullable=False,
        index=True
    )
    enrollment_token_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("enrollment_tokens.id", ondelete="SET NULL"),
        nullable=True
    )
    cert_fingerprint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    current_risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    policy_group_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("policy_groups.id", ondelete="SET NULL"),
        nullable=True
    )

    # Relationships
    enrollment_token: Mapped[Optional["EnrollmentToken"]] = relationship("EnrollmentToken", foreign_keys=[enrollment_token_id])
    policy_group: Mapped[Optional["PolicyGroup"]] = relationship("PolicyGroup", back_populates="agents")
    heartbeats: Mapped[List["Heartbeat"]] = relationship("Heartbeat", back_populates="agent", cascade="all, delete-orphan")
    telemetry_events: Mapped[List["TelemetryEvent"]] = relationship("TelemetryEvent", back_populates="agent", cascade="all, delete-orphan")
    risk_scores: Mapped[List["RiskScore"]] = relationship("RiskScore", back_populates="agent", cascade="all, delete-orphan")
    commands: Mapped[List["Command"]] = relationship("Command", back_populates="agent", cascade="all, delete-orphan")
    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="agent", cascade="all, delete-orphan")
    sync_logs: Mapped[List["OfflineSyncLog"]] = relationship("OfflineSyncLog", back_populates="agent", cascade="all, delete-orphan")

class EnrollmentToken(Base, TimestampUUIDMixin):
    __tablename__ = "enrollment_tokens"

    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    max_uses: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    used_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

class Heartbeat(Base, TimestampUUIDMixin):
    __tablename__ = "heartbeats"

    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    cpu_usage: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    memory_usage: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    disk_usage: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    agent_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Relationships
    agent: Mapped[Agent] = relationship("Agent", back_populates="heartbeats")

    __table_args__ = (
        Index("idx_heartbeats_agent_timestamp", "agent_id", "timestamp"),
    )

class OfflineSyncLog(Base, TimestampUUIDMixin):
    __tablename__ = "offline_sync_log"

    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    batch_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    events_count: Mapped[int] = mapped_column(Integer, nullable=False)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[SyncStatus] = mapped_column(
        Enum(SyncStatus, name="sync_status_type"),
        nullable=False
    )

    # Relationships
    agent: Mapped[Agent] = relationship("Agent", back_populates="sync_logs")
