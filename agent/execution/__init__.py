"""Canonical allowlisted script execution surface for the ZTA Agent."""
from .execution_result import ScriptExecutionResult
from .validators import ScriptValidationError, validate_script_request, ALLOWED_SCRIPT_IDS
from .script_registry import (
    SCRIPT_REGISTRY,
    get_demo_temp_dir,
    run_demo_process_start,
    run_demo_file_create,
    run_demo_file_modify,
    run_demo_network_connection,
    run_demo_listening_port,
    run_demo_auth_event,
    run_demo_rule_trigger,
    run_demo_log_push,
)
from .script_executor import AllowlistedScriptExecutor, DemoScriptExecutor

__all__ = [
    "ScriptExecutionResult",
    "ScriptValidationError",
    "validate_script_request",
    "ALLOWED_SCRIPT_IDS",
    "SCRIPT_REGISTRY",
    "get_demo_temp_dir",
    "run_demo_process_start",
    "run_demo_file_create",
    "run_demo_file_modify",
    "run_demo_network_connection",
    "run_demo_listening_port",
    "run_demo_auth_event",
    "run_demo_rule_trigger",
    "run_demo_log_push",
    "DemoScriptExecutor",
    "AllowlistedScriptExecutor",
]
