"""
Data Transfer Objects (DTOs) for Agent Telemetry Events and Local Storage.
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class EventSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def priority_rank(cls, severity: str) -> int:
        """Returns integer priority rank for eviction logic (higher rank = higher importance)."""
        ranks = {
            cls.LOW.value: 1,
            cls.MEDIUM.value: 2,
            cls.HIGH.value: 3,
            cls.CRITICAL.value: 4,
        }
        return ranks.get(severity.lower(), 1)


@dataclass
class TelemetryEventDTO:
    """Represents a single collected telemetry event."""
    collector_type: str
    event_type: str
    data: Dict[str, Any]
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: str = EventSeverity.LOW.value
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "collector_type": self.collector_type,
            "event_type": self.event_type,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TelemetryEventDTO":
        return cls(
            event_id=d.get("event_id", str(uuid.uuid4())),
            collector_type=d.get("collector_type", "unknown"),
            event_type=d.get("event_type", "unknown"),
            severity=d.get("severity", EventSeverity.LOW.value),
            timestamp=d.get("timestamp", datetime.now(timezone.utc).isoformat()),
            data=d.get("data", {}),
        )


@dataclass
class TelemetryBatchDTO:
    """Represents a batch of telemetry events for manager submission."""
    agent_id: str
    events: List[TelemetryEventDTO]
    batch_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "batch_id": self.batch_id,
            "events": [e.to_dict() for e in self.events],
        }


@dataclass
class SyncResult:
    """Result of an offline queue flush operation."""
    synced_count: int = 0
    failed_count: int = 0
    remaining_depth: int = 0
    success: bool = True
    error_message: Optional[str] = None
