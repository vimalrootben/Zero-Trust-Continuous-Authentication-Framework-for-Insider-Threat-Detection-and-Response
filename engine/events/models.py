"""ZTA Canonical Security Event Data Models."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, List


@dataclass
class ZTAAgent:
    """Agent identity metadata."""
    id: str
    name: str
    ip: Optional[str] = None


@dataclass
class ZTAUser:
    """User account context."""
    name: Optional[str] = None
    domain: Optional[str] = None
    session_id: Optional[int] = None


@dataclass
class ZTAProcess:
    """Endpoint process context."""
    name: Optional[str] = None
    path: Optional[str] = None
    pid: Optional[int] = None
    parent_name: Optional[str] = None
    parent_pid: Optional[int] = None
    command_line: Optional[str] = None


@dataclass
class ZTAMitre:
    """MITRE ATT&CK mapping metadata."""
    tactic: Optional[str] = None
    technique: Optional[str] = None
    technique_id: Optional[str] = None


@dataclass
class ZTAWazuhRule:
    """Original detection rule metadata."""
    id: int
    level: int
    description: str
    groups: List[str] = field(default_factory=list)


@dataclass
class ZTAEvent:
    """Canonical normalized security event used across ZTA engines."""
    event_id: str
    timestamp: datetime
    agent: ZTAAgent
    user: ZTAUser = field(default_factory=ZTAUser)
    process: ZTAProcess = field(default_factory=ZTAProcess)
    wazuh_rule: Optional[ZTAWazuhRule] = None
    mitre: ZTAMitre = field(default_factory=ZTAMitre)
    event_type: str = "UNKNOWN"
    severity: str = "LOW"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    raw_event: Dict[str, Any] = field(default_factory=dict)
