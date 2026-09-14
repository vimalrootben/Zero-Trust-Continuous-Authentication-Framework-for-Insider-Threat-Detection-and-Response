"""Canonical allowlisted script executor for the ZTA Agent."""

from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

from zta.agent.execution.execution_result import ScriptExecutionResult
from zta.agent.execution.script_registry import SCRIPT_REGISTRY
from zta.agent.execution.validators import ScriptValidationError, validate_script_request


class AllowlistedScriptExecutor:
    """Executes explicitly allowlisted scripts after payload validation."""

    def __init__(self, agent_id: str = "agent-unknown"):
        self.agent_id = agent_id

    def execute_script(self, command_payload: Dict[str, Any]) -> ScriptExecutionResult:
        """Validates and executes a registered benign demo script."""
        command_id = str(command_payload.get("command_id") or f"script-exec-{uuid4().hex[:8]}")
        params = command_payload.get("params") or command_payload.get("parameters") or {}
        script_id = params.get("script_id") or command_payload.get("script_id") or ""
        correlation_id = str(params.get("correlation_id") or f"EXEC-{uuid4().hex[:12]}")
        requested_by = str(command_payload.get("requested_by") or "SOC_ADMIN")
        source = str(command_payload.get("execution_source") or "MANAGER")

        started_at = datetime.now(timezone.utc).isoformat()

        # Security validation
        try:
            validate_script_request(script_id, params)
        except ScriptValidationError as err:
            completed_at = datetime.now(timezone.utc).isoformat()
            return ScriptExecutionResult(
                execution_id=command_id,
                script_id=script_id,
                agent_id=self.agent_id,
                status="REJECTED",
                requested_by=requested_by,
                source=source,
                parameters=params,
                started_at=started_at,
                completed_at=completed_at,
                exit_code=-1,
                stderr_summary=str(err),
                error=str(err),
                correlation_id=correlation_id,
            )
        handler = SCRIPT_REGISTRY[script_id]

        try:
            success, exit_code, stdout, stderr, verification = handler(correlation_id, params)
            completed_at = datetime.now(timezone.utc).isoformat()
            status = "SUCCESS" if success else "FAILED"

            return ScriptExecutionResult(
                execution_id=command_id,
                script_id=script_id,
                agent_id=self.agent_id,
                status=status,
                requested_by=requested_by,
                source=source,
                parameters=params,
                started_at=started_at,
                completed_at=completed_at,
                exit_code=exit_code,
                stdout_summary=stdout[:1000],
                stderr_summary=stderr[:1000],
                verification=verification,
                correlation_id=correlation_id,
                error=stderr if not success else None,
            )
        except Exception as exc:
            completed_at = datetime.now(timezone.utc).isoformat()
            return ScriptExecutionResult(
                execution_id=command_id,
                script_id=script_id,
                agent_id=self.agent_id,
                status="FAILED",
                requested_by=requested_by,
                source=source,
                parameters=params,
                started_at=started_at,
                completed_at=completed_at,
                exit_code=-1,
                stderr_summary=str(exc),
                error=str(exc),
                correlation_id=correlation_id,
            )


# Compatibility alias for existing callers; new production code uses the canonical name.
DemoScriptExecutor = AllowlistedScriptExecutor
