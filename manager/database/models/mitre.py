from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import String, Text, ForeignKey, ARRAY, JSON, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base

class MitreTactic(Base):
    __tablename__ = "mitre_tactics"

    tactic_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    techniques: Mapped[List["MitreTechnique"]] = relationship("MitreTechnique", back_populates="tactic")

class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    tactic_id: Mapped[str] = mapped_column(ForeignKey("mitre_tactics.tactic_id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detection_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    data_sources: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String).with_variant(JSON, "sqlite"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    tactic: Mapped[MitreTactic] = relationship("MitreTactic", back_populates="techniques")
    rules: Mapped[List["Rule"]] = relationship("Rule", back_populates="mitre_technique")
    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="mitre_technique")
