"""ZTA Active Response Provider Engine connecting policy decisions to allowlisted PowerShell execution."""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from zta.powershell.ps_executor import PSResult, PowerShellExecutor


@dataclass
class ResponseActionResult:
    """Result of an executed SOC active response action."""
    status: str  # SUCCESS, FAILED
    action: str
    agent_id: str
    message: str
    details: Optional[Dict[str, Any]] = None


class ZTAResponseEngine:
    """Executes allowlisted active response actions via PowerShellExecutor."""

    def __init__(self, ps_executor: Optional[PowerShellExecutor] = None):
        self.ps_executor = ps_executor or PowerShellExecutor()

    def execute_action(self, action_type: str, agent_id: str, params: Optional[Dict[str, Any]] = None, dry_run: bool = False) -> ResponseActionResult:
        """Translates an adaptive policy decision action into an allowlisted response execution.
        
        Args:
            action_type: Policy action (e.g. LOGOFF_USER, KILL_PROCESS, ISOLATE_ENDPOINT).
            agent_id: Target agent identifier.
            params: Parameters passed to script.
            dry_run: Dry-run flag for validation.
            
        Returns:
            ResponseActionResult summary.
        """
        params = params or {}

        try:
            if action_type in ("LOGOFF_USER", "LOGOUT_USER"):
                res = self.ps_executor.execute_template("LOGOFF_USER", params={"UserName": str(params.get("user_name", "")), "SessionId": str(params.get("session_id", ""))}, dry_run=dry_run)
            elif action_type == "KILL_PROCESS":
                res = self.ps_executor.execute_template("KILL_PROCESS", params={"ProcessName": str(params.get("process_name", "")), "ProcessId": str(params.get("pid", ""))}, dry_run=dry_run)
            elif action_type in ("ISOLATE_ENDPOINT", "DISABLE_NETWORK"):
                res = self.ps_executor.execute_template("NETWORK_ISOLATION", params={"Action": "ISOLATE", "ManagerIP": str(params.get("manager_ip", "127.0.0.1"))}, dry_run=dry_run)
            else:
                return ResponseActionResult(
                    status="NOT_EXECUTED" if action_type in {"MONITOR", "ALERT", "NOTIFY_SOC"} else "FAILED",
                    action=action_type,
                    agent_id=agent_id,
                    message=f"No response executor for action: {action_type}",
                )

            return ResponseActionResult(
                status=("PREVIEW" if dry_run else "SUCCESS") if res.success else "FAILED",
                action=action_type,
                agent_id=agent_id,
                message=res.output if res.success else f"Action failed: {res.error}",
                details={"exit_code": res.exit_code, "raw_error": res.error},
            )

        except Exception as e:
            return ResponseActionResult(
                status="FAILED",
                action=action_type,
                agent_id=agent_id,
                message=f"Failed to execute response action: {str(e)}",
            )
