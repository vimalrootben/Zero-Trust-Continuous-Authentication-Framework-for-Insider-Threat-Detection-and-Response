"""Execution result data model for controlled test scripts."""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ScriptExecutionResult:
    """Detailed record of a controlled demo script execution."""
    execution_id: str
    script_id: str
    agent_id: str
    status: str  # PENDING, RUNNING, SUCCESS, FAILED, TIMEOUT, REJECTED
    requested_by: str = "SOC_ADMIN"
    source: str = "MANAGER"
    parameters: Dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    completed_at: str = ""
    exit_code: Optional[int] = None
    stdout_summary: str = ""
    stderr_summary: str = ""
    verification: Optional[str] = None
    correlation_id: str = ""
    error: Optional[str] = None
