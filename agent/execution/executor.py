"""Compatibility imports for the retired duplicate execution implementation.

New code must import the canonical split modules (`script_executor`,
`script_registry`, and `validators`) directly.
"""

from .execution_result import ScriptExecutionResult
from .script_executor import AllowlistedScriptExecutor, DemoScriptExecutor
from .script_registry import (
    SCRIPT_REGISTRY,
    get_demo_temp_dir,
    run_demo_auth_event,
    run_demo_file_create,
    run_demo_file_modify,
    run_demo_listening_port,
    run_demo_log_push,
    run_demo_network_connection,
    run_demo_process_start,
    run_demo_rule_trigger,
)
from .validators import ALLOWED_SCRIPT_IDS, ScriptValidationError, validate_script_request

__all__ = [
    "ScriptExecutionResult", "ScriptValidationError", "validate_script_request",
    "ALLOWED_SCRIPT_IDS", "SCRIPT_REGISTRY", "get_demo_temp_dir",
    "run_demo_process_start", "run_demo_file_create", "run_demo_file_modify",
    "run_demo_network_connection", "run_demo_listening_port",
    "run_demo_auth_event", "run_demo_rule_trigger", "run_demo_log_push",
    "AllowlistedScriptExecutor", "DemoScriptExecutor",
]
