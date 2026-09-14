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
        "LOGOFF_USER": {"UserName", "Domain", "SessionId"},
        "KILL_PROCESS": {"ProcessName", "ProcessId", "ProcessPath", "ProcessCreatedAt", "AgentProcessId"},
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
        aliases = {
            "LOGOUT_USER": "LOGOFF_USER",
            "ISOLATE_ENDPOINT": "NETWORK_ISOLATION",
            "DISABLE_NETWORK": "NETWORK_ISOLATION",
            "UNISOLATE_ENDPOINT": "NETWORK_ISOLATION",
        }
        original_action = action_type
        action_type = aliases.get(action_type, action_type)
        if action_type not in self.ALLOWLISTED_TEMPLATES:
            raise UnknownTemplateError(f"Action '{action_type}' is not an allowlisted template. Allowed: {list(self.ALLOWLISTED_TEMPLATES.keys())}")

        params = params or {}
        if not isinstance(params, dict) or set(params) - self.PARAMETERS[action_type]:
            raise InvalidParameterError("Unsupported template parameter")
        self._validate_parameters(params)
        if action_type == "NETWORK_ISOLATION":
            return PSResult(
                success=False,
                output="",
                error="Network isolation is unavailable",
                exit_code=1,
                verification="UNAVAILABLE",
                dry_run=dry_run,
            )
        if action_type == "LOGOFF_USER":
            username, session_id = params.get("UserName"), str(params.get("SessionId", ""))
            if (not isinstance(username, str) or not username.strip()
                    or any(c in username for c in "*?\r\n") or username.startswith("-")
                    or (session_id and (not session_id.isdecimal() or not 0 < int(session_id) <= 2147483647))):
                raise InvalidParameterError("Logout requires an exact username and optional positive session ID")

        if action_type == 'KILL_PROCESS':
            pid, name = str(params.get('ProcessId','')), params.get('ProcessName')
            path, created = params.get('ProcessPath'), params.get('ProcessCreatedAt')
            if (not pid.isdecimal() or int(pid) <= 4 or not isinstance(name,str) or not name
                    or any(c in name for c in '*?\r\n') or not isinstance(path, str) or not path
                    or not isinstance(created, str) or not created):
                raise InvalidParameterError('Process termination requires exact PID, name, path, and creation time')
            params = {**params, 'AgentProcessId': str(os.getpid())}

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

        if action_type == "LOGOFF_USER":
            try:
                sessions = WindowsSessions()
                resolved_id = sessions.logoff(str(params['UserName']), str(params.get('Domain') or ''),
                                               int(params['SessionId']) if str(params.get('SessionId') or '').isdecimal() else None)
                return PSResult(True, f"WTS session {resolved_id} is no longer present", verification="SESSION_NOT_ACTIVE")
            except Exception as exc:
                return PSResult(False, "", str(exc), 1, verification="SESSION_STILL_PRESENT")

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
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
