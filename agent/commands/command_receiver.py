"""ZTA Agent Command Receiver & Verification Engine."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from zta.powershell.ps_executor import InvalidParameterError, PSResult, PowerShellExecutor, UnknownTemplateError
from zta.agent.execution.script_executor import DemoScriptExecutor


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
    dry_run: bool = False


class AgentCommandReceiver:
    """Validates incoming command payloads and dispatches allowlisted execution to PowerShellExecutor."""

    def __init__(self, ps_executor: Optional[PowerShellExecutor] = None, command_validator=None):
        self.ps_executor = ps_executor or PowerShellExecutor()
        self.command_validator = command_validator
        self.demo_executor = DemoScriptExecutor()

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

        command_id = str(command_payload.get("command_id", "cmd-unknown"))
        raw_action = str(command_payload.get("action") or command_payload.get("command_type") or command_payload.get("action_type") or "")

        # Alias mapping for SOC actions
        action_map = {
            "ISOLATE_ENDPOINT": "NETWORK_ISOLATION",
            "DISABLE_NETWORK": "NETWORK_ISOLATION",
        }
        action_type = action_map.get(raw_action, raw_action)

        params = command_payload.get("params", {})

        if not action_type:
            raise CommandValidationError("Missing required 'action' or 'command_type' in payload.")

        now_str = datetime.now(timezone.utc).isoformat()

        try:
            if not dry_run:
                if self.command_validator is None:
                    raise CommandValidationError("Command authorization is not configured; execution refused")
                self.command_validator(command_payload)

            if action_type == "DEMO_SCRIPT":
                demo_res = self.demo_executor.execute_script(command_payload)
                return CommandExecutionReport(
                    command_id=command_id,
                    action_type="DEMO_SCRIPT",
                    status=demo_res.status,
                    output=demo_res.stdout_summary or demo_res.stderr_summary,
                    error=demo_res.error,
                    executed_at=demo_res.started_at,
                    verification=demo_res.verification,
                    dry_run=dry_run,
                )
            else:
                res: PSResult = self.ps_executor.execute_template(action_type=str(action_type), params=params, dry_run=dry_run)

                return CommandExecutionReport(
                    command_id=command_id,
                    action_type=str(action_type),
                    status=("PREVIEW" if dry_run else "SUCCESS") if res.success else "FAILED",
                    output=res.output if res.success else f"Execution failed: {res.error}",
                    error=res.error,
                    executed_at="" if dry_run else now_str,
                    verification=res.verification,
                    dry_run=dry_run,
                )

        except (UnknownTemplateError, InvalidParameterError) as err:
            return CommandExecutionReport(
                command_id=command_id,
                action_type=str(action_type),
                status="FAILED",
                output="",
                error=f"Command Validation Error: {str(err)}",
                executed_at=now_str,
            )
        except Exception as ex:
            return CommandExecutionReport(
                command_id=command_id,
                action_type=str(action_type),
                status="FAILED",
                output="",
                error=f"Unexpected Execution Error: {str(ex)}",
                executed_at=now_str,
            )
