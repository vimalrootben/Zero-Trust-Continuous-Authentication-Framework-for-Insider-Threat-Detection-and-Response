import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import Integer, String, ForeignKey, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base, TimestampUUIDMixin

class RiskScore(Base, TimestampUUIDMixin):
    __tablename__ = "risk_scores"

    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    delta: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("rules.id", ondelete="SET NULL"), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    # Relationships
    agent: Mapped["Agent"] = relationship("Agent", back_populates="risk_scores")
    rule: Mapped[Optional["Rule"]] = relationship("Rule")

    __table_args__ = (
        Index("idx_risk_scores_agent_timestamp", "agent_id", "timestamp"),
    )
