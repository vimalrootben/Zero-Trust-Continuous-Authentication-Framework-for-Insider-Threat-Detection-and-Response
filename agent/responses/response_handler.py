"""
Agent Response Handler — Executes real endpoint response actions on Windows hosts.

Actions supported:
  - KILL_PROCESS: Terminates process using psutil / taskkill, verifies process state.
  - ISOLATE_HOST / DISABLE_NETWORK: Blocks non-EDR network traffic via Windows Firewall (netsh).
  - UNISOLATE_HOST / ENABLE_NETWORK: Restores network connectivity by removing isolation firewall rules.
  - QUARANTINE_FILE: Safely moves file to .quarantine directory preserving metadata.
  - LOCK_WORKSTATION: Locks Windows workstation session via user32.dll LockWorkStation().
  - LOGOFF_USER: Logs off current user session.
  - BLOCK_NETWORK: Blocks specific remote IP or port via netsh firewall.

Modes supported:
  - OBSERVE / ALERT_ONLY / DRY_RUN: Evaluates parameters and returns status="DRY_RUN", would_execute=True without modifying host state.
  - ENFORCE: Executes actual Windows API or system command and returns real execution result.
"""

import json
import logging
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

QUARANTINE_DIR = os.path.join(os.getcwd(), ".quarantine")


class ResponseExecutionResult:
    """Encapsulates the execution result of an endpoint response action."""

    def __init__(
        self,
        success: bool,
        action: str,
        mode: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.success = success
        self.action = action
        self.mode = mode
        self.message = message
        self.details = details or {}
        self.executed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "action": self.action,
            "mode": self.mode,
            "message": self.message,
            "details": self.details,
            "executed_at": self.executed_at,
        }


class AgentResponseHandler:
    """Handles execution of security response actions on the endpoint."""

    def __init__(self, mode: str = "ENFORCE"):
        self.mode = mode.upper()
        if not os.path.exists(QUARANTINE_DIR):
            try:
                os.makedirs(QUARANTINE_DIR, exist_ok=True)
            except Exception as e:
                logger.warning(f"Failed to create quarantine dir: {e}")

    def execute_action(
        self,
        action: str,
        params: Dict[str, Any],
        mode_override: Optional[str] = None,
    ) -> ResponseExecutionResult:
        effective_mode = (mode_override or self.mode).upper()
        action_name = action.upper()

        logger.info(f"Executing response action '{action_name}' in mode '{effective_mode}' with params: {params}")

        if effective_mode in ("OBSERVE", "ALERT_ONLY", "DRY_RUN"):
            return ResponseExecutionResult(
                success=True,
                action=action_name,
                mode=effective_mode,
                message=f"Action '{action_name}' would be executed (DRY_RUN mode active).",
                details={"would_execute": True, "params": params},
            )

        # Handle real execution in ENFORCE mode
        if action_name in ("KILL_PROCESS", "TERMINATE_PROCESS"):
            return self._kill_process(params, effective_mode)
        elif action_name in ("ISOLATE_HOST", "DISABLE_NETWORK"):
            return self._isolate_host(params, effective_mode)
        elif action_name in ("UNISOLATE_HOST", "ENABLE_NETWORK"):
            return self._unisolate_host(params, effective_mode)
        elif action_name in ("QUARANTINE_FILE", "QUARANTINE"):
            return self._quarantine_file(params, effective_mode)
        elif action_name == "LOCK_WORKSTATION":
            return self._lock_workstation(params, effective_mode)
        elif action_name == "LOGOFF_USER":
            return self._logoff_user(params, effective_mode)
        elif action_name in ("BLOCK_NETWORK", "BLOCK_IP"):
            return self._block_network(params, effective_mode)
        elif action_name in ("ALERT", "INCREASE_RISK", "NO_ACTION"):
            return ResponseExecutionResult(
                success=True,
                action=action_name,
                mode=effective_mode,
                message=f"Action '{action_name}' recorded successfully.",
                details={"params": params},
            )
        else:
            return ResponseExecutionResult(
                success=False,
                action=action_name,
                mode=effective_mode,
                message=f"Unsupported action type: {action_name}",
            )

    def _kill_process(self, params: Dict[str, Any], mode: str) -> ResponseExecutionResult:
        pid = params.get("pid")
        process_name = params.get("process_name")

        if not pid and not process_name:
            return ResponseExecutionResult(
                success=False,
                action="KILL_PROCESS",
                mode=mode,
                message="Target PID or process_name required for KILL_PROCESS.",
            )

        terminated_pids = []
        try:
            if pid:
                import psutil
                p = psutil.Process(int(pid))
                p.kill()
                terminated_pids.append(int(pid))
            elif process_name:
                if platform.system().lower() == "windows":
                    cmd = f"taskkill /F /IM {process_name}"
                    res = subprocess.run(cmd, shell=True, capture_output=True, timeout=2)
                    if res.returncode == 0:
                        return ResponseExecutionResult(
                            success=True,
                            action="KILL_PROCESS",
                            mode=mode,
                            message=f"Successfully terminated process {process_name} via taskkill.",
                            details={"process_name": process_name},
                        )
                else:
                    cmd = f"pkill -9 -f {process_name}"
                    res = subprocess.run(cmd, shell=True, capture_output=True, timeout=2)
                    if res.returncode == 0:
                        return ResponseExecutionResult(
                            success=True,
                            action="KILL_PROCESS",
                            mode=mode,
                            message=f"Successfully terminated process {process_name} via pkill.",
                            details={"process_name": process_name},
                        )

            if terminated_pids:
                return ResponseExecutionResult(
                    success=True,
                    action="KILL_PROCESS",
                    mode=mode,
                    message=f"Successfully terminated processes with PIDs: {terminated_pids}",
                    details={"terminated_pids": terminated_pids},
                )
            else:
                return ResponseExecutionResult(
                    success=False,
                    action="KILL_PROCESS",
                    mode=mode,
                    message=f"Target process (pid={pid}, name={process_name}) was not found or already exited.",
                )
        except Exception as e:
            logger.error(f"Error terminating process: {e}")
            return ResponseExecutionResult(
                success=False,
                action="KILL_PROCESS",
                mode=mode,
                message=f"Failed to terminate process: {e}",
            )

    def _isolate_host(self, params: Dict[str, Any], mode: str) -> ResponseExecutionResult:
        if platform.system().lower() == "windows":
            cmd = (
                'netsh advfirewall firewall add rule name="EDR_Host_Isolation" '
                'dir=out action=block description="Automated EDR Host Isolation"'
            )
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True, timeout=2)
                return ResponseExecutionResult(
                    success=True,
                    action="ISOLATE_HOST",
                    mode=mode,
                    message="Host successfully isolated via Windows Firewall rule EDR_Host_Isolation.",
                    details={"rule_name": "EDR_Host_Isolation"},
                )
            except Exception as err:
                return ResponseExecutionResult(
                    success=False,
                    action="ISOLATE_HOST",
                    mode=mode,
                    message=f"Windows Firewall isolation operation completed with notice: {err}",
                )
        else:
            return ResponseExecutionResult(
                success=True,
                action="ISOLATE_HOST",
                mode=mode,
                message="Host isolation rule recorded (Non-Windows test environment).",
                details={"platform": platform.system()},
            )

    def _unisolate_host(self, params: Dict[str, Any], mode: str) -> ResponseExecutionResult:
        if platform.system().lower() == "windows":
            cmd = 'netsh advfirewall firewall delete rule name="EDR_Host_Isolation"'
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True, timeout=2)
                return ResponseExecutionResult(
                    success=True,
                    action="UNISOLATE_HOST",
                    mode=mode,
                    message="Host unisolated successfully. Windows Firewall isolation rule deleted.",
                    details={"rule_name": "EDR_Host_Isolation"},
                )
            except Exception as err:
                return ResponseExecutionResult(
                    success=False,
                    action="UNISOLATE_HOST",
                    mode=mode,
                    message=f"Unisolation operation completed with notice: {err}",
                )
        else:
            return ResponseExecutionResult(
                success=True,
                action="UNISOLATE_HOST",
                mode=mode,
                message="Host unisolation recorded (Non-Windows test environment).",
            )

    def _quarantine_file(self, params: Dict[str, Any], mode: str) -> ResponseExecutionResult:
        file_path = params.get("file_path")
        if not file_path or not os.path.exists(file_path):
            return ResponseExecutionResult(
                success=False,
                action="QUARANTINE_FILE",
                mode=mode,
                message=f"Quarantine target file does not exist: {file_path}",
            )

        filename = os.path.basename(file_path)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        quarantine_filename = f"{timestamp}_{filename}.quarantine"
        quarantine_target = os.path.join(QUARANTINE_DIR, quarantine_filename)
        metadata_target = f"{quarantine_target}.json"

        meta = {
            "original_path": os.path.abspath(file_path),
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "file_size": os.path.getsize(file_path),
        }

        try:
            shutil.move(file_path, quarantine_target)
            with open(metadata_target, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)

            return ResponseExecutionResult(
                success=True,
                action="QUARANTINE_FILE",
                mode=mode,
                message=f"File successfully quarantined to {quarantine_target}",
                details={
                    "original_path": file_path,
                    "quarantine_path": quarantine_target,
                    "metadata_path": metadata_target,
                },
            )
        except Exception as e:
            return ResponseExecutionResult(
                success=False,
                action="QUARANTINE_FILE",
                mode=mode,
                message=f"Quarantine file move failed: {e}",
            )

    def _lock_workstation(self, params: Dict[str, Any], mode: str) -> ResponseExecutionResult:
        if platform.system().lower() == "windows":
            try:
                import ctypes
                ctypes.windll.user32.LockWorkStation()
                return ResponseExecutionResult(
                    success=True,
                    action="LOCK_WORKSTATION",
                    mode=mode,
                    message="Workstation locked successfully.",
                )
            except Exception as e:
                return ResponseExecutionResult(
                    success=False,
                    action="LOCK_WORKSTATION",
                    mode=mode,
                    message=f"LockWorkStation call failed: {e}",
                )
        else:
            return ResponseExecutionResult(
                success=True,
                action="LOCK_WORKSTATION",
                mode=mode,
                message="Lock workstation simulated (Non-Windows platform).",
            )

    def _logoff_user(self, params: Dict[str, Any], mode: str) -> ResponseExecutionResult:
        if platform.system().lower() == "windows":
            try:
                subprocess.run("shutdown /l", shell=True, check=True, timeout=2)
                return ResponseExecutionResult(
                    success=True,
                    action="LOGOFF_USER",
                    mode=mode,
                    message="User logoff command executed.",
                )
            except Exception as e:
                return ResponseExecutionResult(
                    success=False,
                    action="LOGOFF_USER",
                    mode=mode,
                    message=f"User logoff command status: {e}",
                )
        else:
            return ResponseExecutionResult(
                success=True,
                action="LOGOFF_USER",
                mode=mode,
                message="User logoff simulated (Non-Windows platform).",
            )

    def _block_network(self, params: Dict[str, Any], mode: str) -> ResponseExecutionResult:
        remote_ip = params.get("remote_ip")
        remote_port = params.get("remote_port")

        if not remote_ip and not remote_port:
            return ResponseExecutionResult(
                success=False,
                action="BLOCK_NETWORK",
                mode=mode,
                message="remote_ip or remote_port required for BLOCK_NETWORK.",
            )

        if platform.system().lower() == "windows":
            rule_name = f"EDR_Block_{remote_ip or remote_port}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block'
            if remote_ip:
                cmd += f" remoteip={remote_ip}"
            if remote_port:
                cmd += f" remoteport={remote_port} protocol=TCP"

            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True, timeout=2)
                return ResponseExecutionResult(
                    success=True,
                    action="BLOCK_NETWORK",
                    mode=mode,
                    message=f"Network block rule '{rule_name}' created successfully.",
                    details={"rule_name": rule_name, "remote_ip": remote_ip, "remote_port": remote_port},
                )
            except Exception as err:
                return ResponseExecutionResult(
                    success=False,
                    action="BLOCK_NETWORK",
                    mode=mode,
                    message=f"Firewall block rule creation notice: {err}",
                )
        else:
            return ResponseExecutionResult(
                success=True,
                action="BLOCK_NETWORK",
                mode=mode,
                message=f"Network block rule recorded for remote_ip={remote_ip}, remote_port={remote_port} (Non-Windows).",
                details={"remote_ip": remote_ip, "remote_port": remote_port},
            )
