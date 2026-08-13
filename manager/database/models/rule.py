import enum
import uuid
from typing import List, Optional
from sqlalchemy import String, Boolean, Integer, ForeignKey, Enum, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base, TimestampUUIDMixin

class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ResponseTemplate(Base, TimestampUUIDMixin):
    __tablename__ = "response_templates"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)  # 'KILL_PROCESS', etc.
    default_params_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Relationships
    rules: Mapped[List["Rule"]] = relationship("Rule", back_populates="response_template")

class Rule(Base, TimestampUUIDMixin):
    __tablename__ = "rules"

    rule_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    condition_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity_type"),
        nullable=False,
        index=True
    )
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("mitre_techniques.technique_id", ondelete="SET NULL"),
        nullable=True
    )
    response_action_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("response_templates.id", ondelete="SET NULL"),
        nullable=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    false_positive_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Relationships
    mitre_technique: Mapped[Optional["MitreTechnique"]] = relationship("MitreTechnique", back_populates="rules")
    response_template: Mapped[Optional[ResponseTemplate]] = relationship("ResponseTemplate", back_populates="rules")
    creator: Mapped[Optional["User"]] = relationship("User")
    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="rule")
