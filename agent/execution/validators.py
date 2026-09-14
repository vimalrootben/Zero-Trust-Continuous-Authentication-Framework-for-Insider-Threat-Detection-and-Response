"""Validation rules for allowlisted agent script execution."""

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
SCRIPT_PARAMETERS = {
    "DEMO_PROCESS_START": set(), "DEMO_FILE_CREATE": set(), "DEMO_FILE_MODIFY": set(),
    "DEMO_NETWORK_CONNECTION": {"destination_ip", "destination_port"},
    "DEMO_LISTENING_PORT": {"host", "port"}, "DEMO_AUTH_EVENT": {"username"},
    "DEMO_RULE_TRIGGER": set(), "DEMO_LOG_PUSH": {"message"},
}


def validate_script_request(script_id: str, parameters: Dict[str, Any]) -> None:
    """Strictly validates incoming script ID and parameters.
    
    Ensures:
    1. script_id is in the unchanged strict allowlist.
    2. No arbitrary command bodies/strings are provided.
    3. Correlation ID is clean and well-formed.
    """
    if not script_id or script_id not in ALLOWED_SCRIPT_IDS:
        raise ScriptValidationError(f"Unauthorized or unapproved script_id '{script_id}'. Only allowlisted scripts are permitted.")

    if not isinstance(parameters, dict):
        raise ScriptValidationError("Parameters must be a JSON dictionary.")

    # Block any attempts to inject arbitrary commands
    disallowed_keys = {"command", "cmd", "script", "code", "powershell", "shell", "exec", "eval", "raw"}
    for key in parameters.keys():
        if key.lower() in disallowed_keys:
            raise ScriptValidationError(f"Arbitrary script execution rejected: parameter '{key}' is forbidden.")

    allowed = SCRIPT_PARAMETERS[script_id] | {"script_id", "correlation_id"}
    unsupported = set(parameters) - allowed
    if unsupported:
        raise ScriptValidationError(f"Unsupported parameters for {script_id}: {sorted(unsupported)}")

    corr_id = parameters.get("correlation_id")
    if corr_id and not SAFE_CORRELATION_REGEX.match(str(corr_id)):
        raise ScriptValidationError("Invalid correlation_id format; must be alphanumeric/dashes/dots.")
    for key in ("destination_port", "port"):
        if key in parameters:
            try:
                port = int(parameters[key])
            except (TypeError, ValueError):
                raise ScriptValidationError(f"{key} must be an integer")
            if not 1 <= port <= 65535:
                raise ScriptValidationError(f"{key} must be between 1 and 65535")
    for key in ("destination_ip", "host", "username", "message"):
        if key in parameters and (not isinstance(parameters[key], str) or not 1 <= len(parameters[key]) <= 256):
            raise ScriptValidationError(f"{key} must be a non-empty string of at most 256 characters")
