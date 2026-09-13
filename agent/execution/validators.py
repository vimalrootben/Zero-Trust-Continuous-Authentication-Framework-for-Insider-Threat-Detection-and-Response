"""Validation rules for controlled demo script execution."""

import os
import re
from typing import Any, Dict


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
    """Strictly validates incoming script ID and parameters.
    
    Ensures:
    1. Demo mode is enabled.
    2. script_id is in the strict allowlist.
    3. No arbitrary command bodies/strings are provided.
    4. Correlation ID is clean and well-formed.
    """
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
