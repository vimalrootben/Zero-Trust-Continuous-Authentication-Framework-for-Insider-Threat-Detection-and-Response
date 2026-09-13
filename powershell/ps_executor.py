"""ZTA Parameterized & Allowlisted PowerShell Script Executor."""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
from typing import Dict, Optional

from zta.powershell.windows_sessions import WindowsSessions


class UnknownTemplateError(Exception):
    """Raised when an unrecognized PowerShell script template is requested."""
    pass


class InvalidParameterError(Exception):
    """Raised when input parameters contain invalid or potentially dangerous injection characters."""
    pass


class PSExecutionTimeoutError(Exception):
    """Raised when a PowerShell script execution exceeds the maximum allowed timeout."""
    pass


@dataclass
class PSResult:
    """Dataclass holding execution results of a PowerShell script."""
    success: bool
    output: str
    error: Optional[str] = None
    exit_code: int = 0
    verification: Optional[str] = None
    dry_run: bool = False


class PowerShellExecutor:
    """Executes allowlisted, parameterized PowerShell scripts using safe subprocess execution."""

    # Allowlisted script templates
    ALLOWLISTED_TEMPLATES = {
        "LOGOFF_USER": "logoff_user.ps1",
        "KILL_PROCESS": "kill_process.ps1",
        "NETWORK_ISOLATION": "network_isolation.ps1",
    }

    PARAMETERS = {
        "LOGOFF_USER": {"UserName", "SessionId"},
        "KILL_PROCESS": {"ProcessName", "ProcessId"},
        "NETWORK_ISOLATION": {"Action", "ManagerIP"},
    }

    # Regex pattern to reject command injection characters (;, |, &, $, `, <, >)
    DANGEROUS_CHAR_PATTERN = re.compile(r"[;\|&\$`<>']")

    def __init__(self, scripts_dir: Optional[str] = None, timeout_seconds: int = 30):
        if scripts_dir is None:
            self.scripts_dir = Path(__file__).parent / "scripts"
        else:
            self.scripts_dir = Path(scripts_dir)
        self.timeout_seconds = timeout_seconds

    def _validate_parameters(self, params: Dict[str, str]):
        """Sanitizes parameter keys and values against command injection patterns."""
        for key, value in params.items():
            if not isinstance(key, str) or self.DANGEROUS_CHAR_PATTERN.search(key):
                raise InvalidParameterError(f"Invalid parameter key: {key}")
            if not isinstance(value, str):
                value = str(value)
            if self.DANGEROUS_CHAR_PATTERN.search(value):
                raise InvalidParameterError(f"Dangerous characters detected in parameter value for '{key}': {value}")

    def execute_template(self, action_type: str, params: Optional[Dict[str, str]] = None, dry_run: bool = False) -> PSResult:
        """Executes an allowlisted PowerShell template with typed parameters.
        
        Args:
            action_type: Key matching ALLOWLISTED_TEMPLATES (e.g. LOGOFF_USER, KILL_PROCESS, NETWORK_ISOLATION).
            params: Dictionary of parameter names and string values.
            dry_run: If True, validates parameters and template without executing subprocess.
            
        Returns:
            PSResult object with execution output and exit code.
        """
        action_type = "LOGOFF_USER" if action_type == "LOGOUT_USER" else action_type
        if action_type not in self.ALLOWLISTED_TEMPLATES:
            raise UnknownTemplateError(f"Action '{action_type}' is not an allowlisted template. Allowed: {list(self.ALLOWLISTED_TEMPLATES.keys())}")

        params = params or {}
        if not isinstance(params, dict) or set(params) - self.PARAMETERS[action_type]:
            raise InvalidParameterError("Unsupported template parameter")
        self._validate_parameters(params)
        if action_type == "LOGOFF_USER":
            username, session_id = params.get("UserName"), str(params.get("SessionId", ""))
            if (not isinstance(username, str) or not username.strip()
                    or any(c in username for c in "*?\r\n") or username.startswith("-")
                    or not session_id.isdecimal() or not 0 < int(session_id) <= 2147483647):
                raise InvalidParameterError("Logout requires an exact username and a positive session ID")

        if action_type == 'KILL_PROCESS':
            pid, name = str(params.get('ProcessId','')), params.get('ProcessName')
            if not pid.isdecimal() or int(pid) <= 4 or not isinstance(name,str) or not name or any(c in name for c in '*?\r\n'):
                raise InvalidParameterError('Process termination requires an exact process name and PID above 4')

        script_filename = self.ALLOWLISTED_TEMPLATES[action_type]
        script_path = self.scripts_dir / script_filename

        if not script_path.exists():
            raise UnknownTemplateError(f"Script template file missing at path: {script_path}")

        # Build parameterized command line
        cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script_path)]
        for k, v in params.items():
            cmd.extend([f"-{k}", str(v)])

        if dry_run:
            return PSResult(
                success=True,
                output=f"[DRY_RUN] Validated template: {script_filename}; no action executed",
                dry_run=True,
                exit_code=0,
            )

        if action_type == "NETWORK_ISOLATION":
            return PSResult(False, "", "Network isolation is unavailable: manager reachability and containment verification are not implemented", 1)

        try:
            sessions = None
            if action_type == "LOGOFF_USER":
                sessions = WindowsSessions()
                sessions.validate_target(int(params["SessionId"]), params["UserName"])
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            if sessions is not None and completed.returncode == 0:
                if not sessions.verify_gone(int(params["SessionId"])):
                    return PSResult(False, "", "Target session remains present after logoff", 1,
                                    verification="SESSION_STILL_PRESENT")
                return PSResult(True, "Target session is no longer present", verification="SESSION_NOT_ACTIVE")
            if action_type == 'KILL_PROCESS':
                verified = completed.returncode == 0 and completed.stdout.strip() == 'PROCESS_NOT_ACTIVE'
                return PSResult(verified, 'Target process is no longer active' if verified else '',
                                None if verified else completed.stderr.strip() or 'Process termination was not verified',
                                completed.returncode, verification='PROCESS_NOT_ACTIVE' if verified else None)
            return PSResult(
                success=(completed.returncode == 0),
                output=completed.stdout.strip(),
                error=completed.stderr.strip() if completed.stderr else None,
                exit_code=completed.returncode,
            )
        except subprocess.TimeoutExpired:
            raise PSExecutionTimeoutError(f"Script '{script_filename}' timed out after {self.timeout_seconds} seconds.")
        except Exception as e:
            return PSResult(
                success=False,
                output="",
                error=str(e),
                exit_code=1,
            )
