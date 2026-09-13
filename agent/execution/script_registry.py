"""Registry of explicitly approved benign demo test scripts."""

import os
import shutil
import socket
import subprocess
import threading
import time
from typing import Any, Dict, Tuple


def get_demo_temp_dir() -> str:
    """Returns the dedicated safe demo directory under TEMP."""
    base_temp = os.environ.get("TEMP") or os.environ.get("TMP") or ("C:\\temp" if os.name == "nt" else "/tmp")
    demo_dir = os.path.join(base_temp, "edr-demo")
    os.makedirs(demo_dir, exist_ok=True)
    return demo_dir


def run_demo_process_start(correlation_id: str, params: Dict[str, Any]) -> Tuple[bool, int, str, str, str]:
    """Generates real Windows process activity with controlled demo marker."""
    try:
        # Benign command marker
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
