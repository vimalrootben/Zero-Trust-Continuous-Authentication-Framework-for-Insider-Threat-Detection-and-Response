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
    error_code: Optional[str] = None


class PowerShellExecutor:
    """Executes allowlisted, parameterized PowerShell scripts using safe subprocess execution."""

    # Allowlisted script templates
    ALLOWLISTED_TEMPLATES = {
        "LOGOFF_USER": "logoff_user.ps1",
        "KILL_PROCESS": "kill_process.ps1",
        "NETWORK_ISOLATION": "network_isolation.ps1",
        "LOCAL_ACCOUNT_CONTROL": "local_account_control.ps1",
    }

    PARAMETERS = {
        "LOGOFF_USER": {"UserName", "Domain", "SessionId"},
        "KILL_PROCESS": {"ProcessName", "ProcessId", "ProcessPath", "ProcessCreatedAt", "AgentProcessId"},
        "NETWORK_ISOLATION": {"Action", "ManagerIP", "ManagerPort"},
        "LOCAL_ACCOUNT_CONTROL": {"Action", "UserName", "Domain", "LogoutExistingSessions", "AgentAccount"},
        "LOCK_WORKSTATION": {"UserName", "SessionId"},
        "QUARANTINE_FILE": {"FilePath", "ExpectedSha256"},
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
            "LOCK_LOCAL_ACCOUNT": "LOCAL_ACCOUNT_CONTROL",
            "UNLOCK_LOCAL_ACCOUNT": "LOCAL_ACCOUNT_CONTROL",
        }
        original_action = action_type
        action_type = aliases.get(action_type, action_type)
        native_actions = {"LOCK_WORKSTATION", "QUARANTINE_FILE"}
        if action_type not in self.ALLOWLISTED_TEMPLATES and action_type not in native_actions:
            raise UnknownTemplateError(f"Action '{action_type}' is not an allowlisted template. Allowed: {list(self.ALLOWLISTED_TEMPLATES.keys())}")

        params = params or {}
        if not isinstance(params, dict) or set(params) - self.PARAMETERS[action_type]:
            raise InvalidParameterError("Unsupported template parameter")
        self._validate_parameters(params)
        if action_type == "LOCK_WORKSTATION":
            user, session_id = params.get("UserName"), str(params.get("SessionId", ""))
            if not isinstance(user, str) or not user.strip() or not session_id.isdecimal() or int(session_id) <= 0:
                raise InvalidParameterError("Workstation lock requires an exact user and positive session ID")
            if dry_run:
                return PSResult(True, "[DRY_RUN] Validated native workstation lock; no action executed", dry_run=True)
            if os.name != "nt":
                return PSResult(False, "", "Workstation lock is unavailable on this operating system", 1, "UNAVAILABLE", error_code="UNSUPPORTED_OS")
            import ctypes
            target = WindowsSessions().resolve(user, session_id=int(session_id))
            current_session = ctypes.c_ulong()
            if not ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(current_session)):
                return PSResult(False, "", "Unable to resolve agent service session", 1, "UNKNOWN", error_code="SESSION_LOOKUP_FAILED")
            if current_session.value != target["session_id"]:
                return PSResult(False, "", "Agent is not running in the target interactive session", 1, "UNAVAILABLE", error_code="SESSION_ISOLATION")
            if not ctypes.windll.user32.LockWorkStation():
                return PSResult(False, "", "LockWorkStation failed", ctypes.get_last_error() or 1, "EXECUTION_FAILED", error_code="WINDOWS_API_ERROR")
            return PSResult(False, "LockWorkStation returned successfully", "Windows does not expose a reliable independent lock-state verification here", 0,
                            "EXECUTION_COMPLETED_UNVERIFIED", error_code="UNVERIFIED_POSTCONDITION")
        if action_type == "QUARANTINE_FILE":
            path, expected = params.get("FilePath"), params.get("ExpectedSha256")
            if (not isinstance(path, str) or not path or "\x00" in path or not isinstance(expected, str)
                    or len(expected) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in expected)):
                raise InvalidParameterError("File quarantine requires an exact path and SHA-256 identity")
            if dry_run:
                return PSResult(True, "[DRY_RUN] Validated file quarantine contract; no action executed", dry_run=True)
            from zta.powershell.quarantine import FileQuarantine
            handler = FileQuarantine()
            try:
                handler.validate(path, expected)
                evidence = handler.quarantine(path, expected)
                import json
                return PSResult(True, json.dumps(evidence, sort_keys=True), verification="FILE_QUARANTINED")
            except Exception as exc:
                return PSResult(False, "", str(exc), 1, "QUARANTINE_NOT_VERIFIED", error_code=type(exc).__name__)
        if action_type == "NETWORK_ISOLATION":
            if os.environ.get('ZTA_ENABLE_NETWORK_ISOLATION','false').lower() != 'true':
                return PSResult(False,"","Network isolation is unavailable (disabled pending VM-console validation)",1,"UNAVAILABLE",dry_run)
            action = 'UNISOLATE' if original_action == 'UNISOLATE_ENDPOINT' else str(params.get('Action','ISOLATE')).upper()
            port = str(params.get('ManagerPort','8080'))
            if action not in ('ISOLATE','UNISOLATE') or not port.isdecimal() or not 1 <= int(port) <= 65535:
                raise InvalidParameterError('Invalid network isolation action or manager port')
            params={**params,'Action':action,'ManagerPort':port}
        if action_type == 'LOCAL_ACCOUNT_CONTROL':
            requested = 'UNLOCK' if original_action == 'UNLOCK_LOCAL_ACCOUNT' else 'LOCK'
            username = params.get('UserName')
            logout = str(params.get('LogoutExistingSessions','false')).lower()
            if not isinstance(username,str) or not username or any(c in username for c in '*?\r\n\\') or logout not in ('true','false'):
                raise InvalidParameterError('Local account control requires an exact local username')
            params = {**params, 'Action':requested, 'LogoutExistingSessions':logout,
                      'AgentAccount':os.environ.get('USERNAME','')}
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

        if os.name != "nt":
            return PSResult(False, "", f"{original_action} is unavailable on this operating system", 1, "UNAVAILABLE")

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
            if action_type == 'LOCAL_ACCOUNT_CONTROL':
                expected = ('LOCAL_ACCOUNT_ENABLED','LOCAL_ACCOUNT_RESTORED_DISABLED') if params['Action']=='UNLOCK' else ('LOCAL_ACCOUNT_DISABLED',)
                verified = completed.returncode == 0 and any(marker in completed.stdout for marker in expected)
                return PSResult(verified, completed.stdout.strip() if verified else '',
                                None if verified else completed.stderr.strip() or 'Account state was not verified',
                                completed.returncode if completed.returncode else (0 if verified else 1),
                                verification=next((m for m in expected if m in completed.stdout), 'ACCOUNT_STATE_UNVERIFIED'))
            if action_type == 'NETWORK_ISOLATION':
                expected='UNISOLATION_VERIFIED' if params['Action']=='UNISOLATE' else 'ISOLATION_VERIFIED'
                verified=completed.returncode==0 and expected in completed.stdout
                return PSResult(verified,completed.stdout.strip() if verified else '',None if verified else completed.stderr.strip() or 'Network state was not verified',completed.returncode if completed.returncode else (0 if verified else 1),expected if verified else 'NETWORK_STATE_UNVERIFIED')
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
