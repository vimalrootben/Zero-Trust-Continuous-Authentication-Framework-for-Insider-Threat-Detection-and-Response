"""
Threat Intelligence Feed Protocol and DTOs — Phase 14 (M9).
"""
import enum
from dataclasses import dataclass, field
from typing import Optional, List, Protocol, runtime_checkable


class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_SHA256 = "hash_sha256"
    HASH_MD5 = "hash_md5"
    URL = "url"


@dataclass
class IndicatorDTO:
    ioc_type: str
    value: str
    source: str = ""
    confidence: int = 50
    tags: List[str] = field(default_factory=list)


@dataclass
class SyncResult:
    feed_name: str
    added: int = 0
    updated: int = 0
    errors: int = 0


@runtime_checkable
class ThreatIntelFeed(Protocol):
    """Interface every feed connector must implement."""
    async def fetch_indicators(self) -> List[IndicatorDTO]: ...
