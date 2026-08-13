import uuid
from typing import List, Optional
from sqlalchemy import String, Text, Boolean, Integer, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from manager.database.base import Base, TimestampUUIDMixin

class PolicyGroup(Base, TimestampUUIDMixin):
    __tablename__ = "policy_groups"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    policies: Mapped[List["Policy"]] = relationship("Policy", back_populates="policy_group")
    agents: Mapped[List["Agent"]] = relationship("Agent", back_populates="policy_group")

class Policy(Base, TimestampUUIDMixin):
    __tablename__ = "policies"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    condition_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    actions_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    policy_group_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("policy_groups.id", ondelete="SET NULL"),
        nullable=True
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )

    # Relationships
    policy_group: Mapped[Optional[PolicyGroup]] = relationship("PolicyGroup", back_populates="policies")
    creator: Mapped[Optional["User"]] = relationship("User")
    commands: Mapped[List["Command"]] = relationship("Command", back_populates="policy")
