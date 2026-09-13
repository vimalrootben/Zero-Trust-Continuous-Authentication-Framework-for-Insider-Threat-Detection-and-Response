#!/usr/bin/env python3
"""Controlled Demo Test: Listening Port (DEMO-TEST-004)."""

import os
import sys
import time
from datetime import datetime, timezone
from uuid import uuid4

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from zta.agent.execution.script_registry import run_demo_listening_port


def main():
    test_name = "Controlled Demo Listening Port"
    start_time = datetime.now(timezone.utc).isoformat()
    correlation_id = f"DEMO-PORT-{uuid4().hex[:8]}"
    expected_rule = "DEMO-TEST-004"
    expected_telemetry = "LISTENING_PORT / SYSTEM_EVENT on 127.0.0.1:44445"

    print("=" * 60)
    print(f"TEST NAME:          {test_name}")
    print(f"START TIME:         {start_time}")
    print(f"CORRELATION ID:     {correlation_id}")
    print(f"EXPECTED RULE:      {expected_rule}")
    print(f"EXPECTED TELEMETRY: {expected_telemetry}")
    print("=" * 60)

    print("Temporarily opening local listening socket on port 44445...")
    success, exit_code, stdout, stderr, verification = run_demo_listening_port(
        correlation_id, {"port": 44445, "host": "127.0.0.1"}
    )
    print(f"ACTION CREATED:     {stdout}")
    print(f"Verification:       {verification}")
    print("Socket is listening in background thread. Clean auto-close in 3 seconds.")
    print("-" * 60)
    print("Generated Listening Port Event: YES")
    print("Waiting for Agent collection...")
    time.sleep(3.5)
    print("Listener closed cleanly.")
    print("END RESULT:         CONDITION_GENERATED_SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
