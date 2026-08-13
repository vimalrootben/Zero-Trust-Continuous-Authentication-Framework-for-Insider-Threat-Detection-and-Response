import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field

class EnrollmentTokenCreate(BaseModel):
    """Payload to create a new agent enrollment token."""
    expires_in_hours: int = Field(24, ge=1, description="Expiry time in hours from now")
    max_uses: int = Field(1, ge=1, description="Maximum number of times this token can be consumed")


class EnrollmentTokenResponse(BaseModel):
    """Response payload for enrollment token details."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    token_hash: str
    token: Optional[str] = None  # Raw token only populated on initial creation
    expires_at: datetime
    max_uses: int
    used_count: int
    revoked: bool


class RegistrationRequest(BaseModel):
    """Payload submitted by the host agent to onboard and request certificates."""
    model_config = ConfigDict(populate_by_name=True)

    enrollment_token: str
    hostname: str
    os_version: str
    agent_version: str
    hardware_fingerprint: str = Field(..., alias="device_fingerprint")
    public_key_csr: str  # Base64 PEM encoded CSR


class RegistrationResponse(BaseModel):
    """Successful registration response payload containing signed certificates."""
    agent_id: uuid.UUID
    signed_certificate: str  # Base64 PEM encoded agent cert
    ca_certificate: str      # Base64 PEM CA cert
    initial_policy_group: Optional[uuid.UUID] = None
    heartbeat_interval_seconds: int = 30


class HeartbeatPayload(BaseModel):
    """Telemetry heartbeat payload submitted periodically by the agent."""
    agent_id: uuid.UUID
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    status: str = "active"


class HeartbeatResponse(BaseModel):
    """Database representation of recorded heartbeat details."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_id: uuid.UUID
    timestamp: datetime
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    agent_status: Optional[str] = None


class AgentResponse(BaseModel):
    """Public representation of an enrolled agent."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hostname: str
    device_fingerprint: str
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    department: Optional[str] = None
    status: str
    enrollment_token_id: Optional[uuid.UUID] = None
    cert_fingerprint: Optional[str] = None
    last_seen_at: Optional[datetime] = None
    current_risk_score: int
    policy_group_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime
