"""Consolidated ZTA Controlled Demo Script Execution Engine.

Combines execution result models, security validation, benign handlers, and execution orchestration.
"""

import hashlib
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4


# ==============================================================================
# 1. Execution Result Model
# ==============================================================================

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


# ==============================================================================
# 2. Validation Rules & Allowlist
# ==============================================================================

class ScriptValidationError(Exception):
    """Raised when script request fails security or parameter validation."""
    pass


ALLOWED_SCRIPT_IDS = {
    "DEMO_PROCESS_START",
    "DEMO_FILE_CREATE",
    "DEMO_FILE_MODIFY",
    "DEMO_NETWORK_CONNECTION",
    "DEMO_LISTENING_PORT",
    "DEMO_AUTH_EVENT",
    "DEMO_RULE_TRIGGER",
    "DEMO_LOG_PUSH",
}

SAFE_CORRELATION_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.:]{1,128}$")


def validate_script_request(script_id: str, parameters: Dict[str, Any], demo_mode_enabled: bool) -> None:
    """Strictly validates incoming script ID and parameters."""
    if not demo_mode_enabled:
        raise ScriptValidationError("Demo execution mode is disabled on this agent (DEMO_MODE_ENABLED=false).")

    if not script_id or script_id not in ALLOWED_SCRIPT_IDS:
        raise ScriptValidationError(f"Unauthorized or unapproved script_id '{script_id}'. Only allowlisted demo scripts are permitted.")

    if not isinstance(parameters, dict):
        raise ScriptValidationError("Parameters must be a JSON dictionary.")

    # Block any attempts to inject arbitrary commands
    disallowed_keys = {"command", "cmd", "script", "code", "powershell", "shell", "exec", "eval", "raw"}
    for key in parameters.keys():
        if key.lower() in disallowed_keys:
            raise ScriptValidationError(f"Arbitrary script execution rejected: parameter '{key}' is forbidden.")

    corr_id = parameters.get("correlation_id")
    if corr_id and not SAFE_CORRELATION_REGEX.match(str(corr_id)):
        raise ScriptValidationError("Invalid correlation_id format; must be alphanumeric/dashes/dots.")


# ==============================================================================
# 3. Benign Script Handlers & Registry
# ==============================================================================

def get_demo_temp_dir() -> str:
    """Returns the dedicated safe demo directory under TEMP."""
    base_temp = os.environ.get("TEMP") or os.environ.get("TMP") or ("C:\\temp" if os.name == "nt" else "/tmp")
    demo_dir = os.path.join(base_temp, "edr-demo")
    os.makedirs(demo_dir, exist_ok=True)
    return demo_dir


def run_demo_process_start(correlation_id: str, params: Dict[str, Any]) -> Tuple[bool, int, str, str, str]:
    """Generates real Windows process activity with controlled demo marker."""
    try:
        cmd = ["cmd.exe", "/c", f"echo [DEMO-TEST-001] correlation={correlation_id}"] if (os.name == "nt" or shutil.which("cmd.exe")) else ["sh", "-c", f"echo '[DEMO-TEST-001] correlation={correlation_id}'"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return True, proc.returncode, proc.stdout.strip(), proc.stderr.strip(), "PROCESS_STARTED_AND_EXITED"
    except Exception as exc:
        return False, -1, "", str(exc), "PROCESS_FAILED"


def run_demo_file_create(correlation_id: str, params: Dict[str, Any]) -> Tuple[bool, int, str, str, str]:
    """Generates real filesystem create activity in dedicated safe demo folder."""
    demo_dir = get_demo_temp_dir()
    file_path = os.path.join(demo_dir, f"demo_file_{correlation_id}.txt")
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"ZTA Controlled Demo File Test\nCorrelation: {correlation_id}\nRule: DEMO-TEST-002\n")
        return True, 0, f"Created file {file_path}", "", f"FILE_CREATED:{file_path}"
    except Exception as exc:
        return False, -1, "", str(exc), "FILE_CREATE_FAILED"


def run_demo_file_modify(correlation_id: str, params: Dict[str, Any]) -> Tuple[bool, int, str, str, str]:
    """Generates real filesystem modify activity."""
    demo_dir = get_demo_temp_dir()
    file_path = os.path.join(demo_dir, f"demo_file_{correlation_id}.txt")
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"Modified at {time.time()} with correlation {correlation_id}\n")
        return True, 0, f"Modified file {file_path}", "", f"FILE_MODIFIED:{file_path}"
    except Exception as exc:
        return False, -1, "", str(exc), "FILE_MODIFY_FAILED"


def run_demo_network_connection(correlation_id: str, params: Dict[str, Any]) -> Tuple[bool, int, str, str, str]:
    """Generates real network connection to local test destination port."""
    dest_ip = params.get("destination_ip", "127.0.0.1")
    dest_port = int(params.get("destination_port", 44444))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        res = s.connect_ex((dest_ip, dest_port))
        s.close()
        summary = f"Network connection attempted to {dest_ip}:{dest_port} (result={res})"
        return True, 0, summary, "", f"CONNECTION_ATTEMPTED:{dest_ip}:{dest_port}"
    except Exception as exc:
        return False, -1, "", str(exc), "NETWORK_FAILED"


def run_demo_listening_port(correlation_id: str, params: Dict[str, Any]) -> Tuple[bool, int, str, str, str]:
    """Opens a local listening socket on a test port and closes cleanly."""
    port = int(params.get("port", 44445))
    host = params.get("host", "127.0.0.1")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)

        def _cleanup():
            time.sleep(3.0)
            try:
                s.close()
            except Exception:
                pass

        t = threading.Thread(target=_cleanup, daemon=True)
        t.start()
        return True, 0, f"Listening port opened on {host}:{port} for 3 seconds", "", f"LISTENER_OPENED:{host}:{port}"
    except Exception as exc:
        return False, -1, "", str(exc), "LISTENER_FAILED"


def run_demo_auth_event(correlation_id: str, params: Dict[str, Any]) -> Tuple[bool, int, str, str, str]:
    """Generates an operational authentication test marker."""
    username = params.get("username", "demo_test_user")
    return True, 0, f"Demo auth event simulated for user {username} with correlation {correlation_id}", "", "AUTH_SIMULATED"


def run_demo_rule_trigger(correlation_id: str, params: Dict[str, Any]) -> Tuple[bool, int, str, str, str]:
    """Runs a combined benign test to trigger demo detections."""
    p_ok, p_code, p_out, p_err, p_ver = run_demo_process_start(correlation_id, params)
    f_ok, f_code, f_out, f_err, f_ver = run_demo_file_create(correlation_id, params)
    success = p_ok and f_ok
    return success, 0 if success else -1, f"Process: {p_out} | File: {f_out}", f"{p_err} {f_err}".strip(), f"{p_ver};{f_ver}"


def run_demo_log_push(correlation_id: str, params: Dict[str, Any]) -> Tuple[bool, int, str, str, str]:
    """Emits operational test log message."""
    msg = params.get("message", "Controlled operational demo log message")
    return True, 0, f"Operational log generated: {msg}", "", "LOG_GENERATED"


SCRIPT_REGISTRY = {
    "DEMO_PROCESS_START": run_demo_process_start,
    "DEMO_FILE_CREATE": run_demo_file_create,
    "DEMO_FILE_MODIFY": run_demo_file_modify,
    "DEMO_NETWORK_CONNECTION": run_demo_network_connection,
    "DEMO_LISTENING_PORT": run_demo_listening_port,
    "DEMO_AUTH_EVENT": run_demo_auth_event,
    "DEMO_RULE_TRIGGER": run_demo_rule_trigger,
    "DEMO_LOG_PUSH": run_demo_log_push,
}


# ==============================================================================
# 4. Demo Script Executor Class
# ==============================================================================

class DemoScriptExecutor:
    """Executes explicitly allowlisted demo scripts when demo mode is enabled."""

    def __init__(self, agent_id: str = "agent-unknown"):
        self.agent_id = agent_id

    @property
    def is_demo_mode_enabled(self) -> bool:
        return os.environ.get("DEMO_MODE_ENABLED", "false").lower() in ("true", "1", "yes")

    def execute_script(self, command_payload: Dict[str, Any]) -> ScriptExecutionResult:
        """Validates and executes a registered benign demo script."""
        command_id = str(command_payload.get("command_id") or f"demo-exec-{uuid4().hex[:8]}")
        params = command_payload.get("params") or command_payload.get("parameters") or {}
        script_id = params.get("script_id") or command_payload.get("script_id") or ""
        correlation_id = str(params.get("correlation_id") or f"DEMO-{uuid4().hex[:12]}")
        requested_by = str(command_payload.get("requested_by") or "SOC_ADMIN")
        source = str(command_payload.get("execution_source") or "MANAGER")

        started_at = datetime.now(timezone.utc).isoformat()

        # Security validation
        try:
            validate_script_request(script_id, params, self.is_demo_mode_enabled)
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
