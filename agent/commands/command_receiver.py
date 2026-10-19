"""ZTA Agent Command Receiver & Verification Engine."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from zta.powershell.ps_executor import InvalidParameterError, PSExecutionTimeoutError, PSResult, PowerShellExecutor, UnknownTemplateError
from zta.agent.execution.script_executor import AllowlistedScriptExecutor


class CommandValidationError(Exception):
    """Raised when incoming signed command object fails validation."""
    pass


@dataclass
class CommandExecutionReport:
    """Execution status report sent back to manager or API."""
    command_id: str
    action_type: str
    status: str  # SUCCESS, FAILED
    output: str
    error: Optional[str] = None
    executed_at: str = ""
    verification: Optional[str] = None
    correlation_id: str = ""
    failure_reason: Optional[str] = None
    dry_run: bool = False
    completed_at: str = ""
    verification_status: Optional[str] = None
    error_code: Optional[str] = None


class AgentCommandReceiver:
    """Validates incoming command payloads and dispatches allowlisted execution to PowerShellExecutor."""

    def __init__(self, ps_executor: Optional[PowerShellExecutor] = None, command_validator=None,
                 agent_id: str = "agent-unknown", manager_address: Optional[str] = None):
        self.ps_executor = ps_executor or PowerShellExecutor()
        self.command_validator = command_validator
        self.script_executor = AllowlistedScriptExecutor(agent_id=agent_id)
        self.manager_address = manager_address

    def process_command(self, command_payload: Dict[str, Any], dry_run: bool = False) -> CommandExecutionReport:
        """Validates and executes an incoming command payload.
        
        Args:
            command_payload: Signed command dictionary.
            dry_run: Dry-run flag for validation.
            
        Returns:
            CommandExecutionReport object.
        """
        if not isinstance(command_payload, dict):
            raise CommandValidationError("Command payload must be a JSON dictionary.")

        now_str = datetime.now(timezone.utc).isoformat()
        action_type = ""

        try:
            # Production order: signature -> agent identity -> expiry, then payload.
            if not dry_run:
                if self.command_validator is None:
                    raise CommandValidationError("Command authorization is not configured; execution refused")
                self.command_validator(command_payload)

            command_id = str(command_payload.get("command_id", ""))
            raw_action = command_payload.get("action") or command_payload.get("command_type") or command_payload.get("action_type")
            if not command_id or not isinstance(raw_action, str) or not raw_action:
                raise CommandValidationError("Command identity and action are required")
            params = command_payload.get("params", {})
            if not isinstance(params, dict):
                raise CommandValidationError("Command params must be a JSON dictionary")

            action_map = {
                "ISOLATE_ENDPOINT": "NETWORK_ISOLATION",
                "DISABLE_NETWORK": "NETWORK_ISOLATION",
                "UNISOLATE_ENDPOINT": "NETWORK_ISOLATION",
            }
            action_type = action_map.get(raw_action, raw_action)
            if raw_action == "UNISOLATE_ENDPOINT":
                params = {**params, "Action": "UNISOLATE"}
            if action_type == "NETWORK_ISOLATION" and self.manager_address:
                # The signed action authorizes containment; preserve the actual configured control endpoint.
                params = {**params, "ManagerIP": self.manager_address}

            if action_type == "DEMO_SCRIPT":
                if dry_run:
                    from zta.agent.execution.validators import validate_script_request
                    script_id = params.get('script_id') or command_payload.get('script_id') or ''
                    validate_script_request(script_id, params)
                    return CommandExecutionReport(command_id, "DEMO_SCRIPT", "PREVIEW",
                                                  "Allowlisted script request validated; no action executed",
                                                  dry_run=True, verification_status="NOT_EXECUTED")
                script_res = self.script_executor.execute_script(command_payload)
                return CommandExecutionReport(
                    command_id=command_id,
                    action_type="DEMO_SCRIPT",
                    status=script_res.status,
                    output=script_res.stdout_summary or script_res.stderr_summary,
                    error=script_res.error,
                    executed_at=script_res.started_at,
                    verification=script_res.verification,
                    correlation_id=script_res.correlation_id,
                    failure_reason=script_res.error,
                    dry_run=dry_run,
                    completed_at=script_res.completed_at,
                    verification_status="VERIFIED_SUCCESS" if script_res.status == "SUCCESS" else "EXECUTION_FAILED",
                    error_code=str(script_res.exit_code) if script_res.exit_code not in (None, 0) else None,
                )
            else:
                res: PSResult = self.ps_executor.execute_template(action_type=str(action_type), params=params, dry_run=dry_run)

                unverified = res.verification in ("EXECUTION_COMPLETED_UNVERIFIED", "UNKNOWN")
                return CommandExecutionReport(
                    command_id=command_id,
                    action_type=str(action_type),
                    status=("PREVIEW" if dry_run else "SUCCESS") if res.success else ("UNKNOWN" if unverified else "FAILED"),
                    output=res.output if res.success else f"Execution failed: {res.error}",
                    error=res.error,
                    executed_at="" if dry_run else now_str,
                    verification=res.verification,
                    correlation_id=str(command_payload.get("correlation_id") or params.get("correlation_id") or ""),
                    failure_reason=res.error,
                    dry_run=dry_run,
                    completed_at="" if dry_run else datetime.now(timezone.utc).isoformat(),
                    verification_status=("NOT_EXECUTED" if dry_run else "VERIFIED_SUCCESS" if res.success
                                         else "UNKNOWN" if unverified else "VERIFICATION_FAILED"),
                    error_code=res.error_code or (str(res.exit_code) if res.exit_code else None),
                )

        except (UnknownTemplateError, InvalidParameterError) as err:
            return CommandExecutionReport(
                command_id=command_id,
                action_type=str(action_type),
                status="REJECTED",
                output="",
                error=f"Command Validation Error: {str(err)}",
                failure_reason=str(err),
                executed_at=now_str,
                completed_at=now_str,
                verification_status="REJECTED",
                error_code="VALIDATION_ERROR",
            )
        except PSExecutionTimeoutError as err:
            return CommandExecutionReport(
                command_id=str(command_payload.get("command_id", "cmd-unknown")), action_type=str(action_type),
                status="UNKNOWN", output="", error=str(err), failure_reason=str(err), executed_at=now_str,
                completed_at=datetime.now(timezone.utc).isoformat(), verification="UNKNOWN",
                verification_status="UNKNOWN", error_code="EXECUTION_TIMEOUT")
        except Exception as ex:
            return CommandExecutionReport(
                command_id=str(command_payload.get("command_id", "cmd-unknown")),
                action_type=str(action_type),
                status="FAILED",
                output="",
                error=f"Unexpected Execution Error: {str(ex)}",
                failure_reason=str(ex),
                executed_at=now_str,
                completed_at=datetime.now(timezone.utc).isoformat(),
                verification_status="EXECUTION_FAILED",
                error_code=type(ex).__name__,
            )
