"""
Pydantic schemas for Manager Telemetry API endpoints.
"""
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class TelemetryEventPayload(BaseModel):
    """Payload representing an individual telemetry event collected by an agent."""
    event_id: uuid.UUID
    collector_type: str
    event_type: str
    severity: str = "low"
    timestamp: datetime
    data: Dict[str, Any] = Field(default_factory=dict)


class TelemetryBatchPayload(BaseModel):
    """Payload representing a batch submission of telemetry events."""
    agent_id: uuid.UUID
    batch_id: uuid.UUID
    events: List[TelemetryEventPayload]


class TelemetryResponse(BaseModel):
    """Response returned to the agent upon successful telemetry batch receipt."""
    accepted: int
    rejected: int = 0
    batch_id: uuid.UUID
