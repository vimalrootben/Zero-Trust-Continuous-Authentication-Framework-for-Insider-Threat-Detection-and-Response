import enum
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, DateTime, Enum, ARRAY, JSON, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from manager.database.base import Base, TimestampUUIDMixin

class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_SHA256 = "hash_sha256"
    HASH_MD5 = "hash_md5"
    URL = "url"

class ThreatIntelIndicator(Base, TimestampUUIDMixin):
    __tablename__ = "threat_intel_indicators"

    ioc_type: Mapped[IOCType] = mapped_column(
        Enum(IOCType, name="ioc_type_enum"),
        nullable=False,
        index=True
    )
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    tags: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String).with_variant(JSON, "sqlite"), nullable=True)

    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_threat_intel_ioc_type_value"),
    )
