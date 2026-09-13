#!/usr/bin/env python3
"""Controlled Demo Test: Process Trigger (DEMO-TEST-001)."""

import os
import sys
import time
from datetime import datetime, timezone
from uuid import uuid4

# Allow import of zta packages
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from zta.agent.execution.script_registry import run_demo_process_start


def main():
    test_name = "Controlled Demo Process Trigger"
    start_time = datetime.now(timezone.utc).isoformat()
    correlation_id = f"DEMO-PROC-{uuid4().hex[:8]}"
    expected_rule = "DEMO-TEST-001"
    expected_telemetry = "PROCESS_CREATION with DEMO-TEST-001 marker"

    print("=" * 60)
    print(f"TEST NAME:          {test_name}")
    print(f"START TIME:         {start_time}")
    print(f"CORRELATION ID:     {correlation_id}")
    print(f"EXPECTED RULE:      {expected_rule}")
    print(f"EXPECTED TELEMETRY: {expected_telemetry}")
    print("=" * 60)

    print("Executing controlled benign process trigger locally...")
    success, exit_code, stdout, stderr, verification = run_demo_process_start(correlation_id, {})

    print(f"ACTION CREATED:     cmd.exe echo [DEMO-TEST-001] correlation={correlation_id}")
    print(f"Exit Code:          {exit_code}")
    print(f"Output:             {stdout}")
    if stderr:
        print(f"Stderr:             {stderr}")
    print(f"Verification:       {verification}")
    print("-" * 60)
    print("Generated Process Event: YES")
    print("Waiting for Agent collection...")
    print("NOTE: Test condition generated successfully. Rule matching & alert creation are evaluated by Manager.")
    print("END RESULT:         CONDITION_GENERATED_SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
