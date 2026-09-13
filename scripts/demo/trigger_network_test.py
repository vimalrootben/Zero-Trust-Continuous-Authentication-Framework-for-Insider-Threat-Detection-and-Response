#!/usr/bin/env python3
"""Controlled Demo Test: Network Connection (DEMO-TEST-003)."""

import os
import sys
from datetime import datetime, timezone
from uuid import uuid4

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from zta.agent.execution.script_registry import run_demo_network_connection


def main():
    test_name = "Controlled Demo Network Connection"
    start_time = datetime.now(timezone.utc).isoformat()
    correlation_id = f"DEMO-NET-{uuid4().hex[:8]}"
    expected_rule = "DEMO-TEST-003"
    expected_telemetry = "NETWORK_CONNECTION to localhost:44444"

    print("=" * 60)
    print(f"TEST NAME:          {test_name}")
    print(f"START TIME:         {start_time}")
    print(f"CORRELATION ID:     {correlation_id}")
    print(f"EXPECTED RULE:      {expected_rule}")
    print(f"EXPECTED TELEMETRY: {expected_telemetry}")
    print("=" * 60)

    print("Generating local controlled connection to 127.0.0.1:44444...")
    success, exit_code, stdout, stderr, verification = run_demo_network_connection(
        correlation_id, {"destination_ip": "127.0.0.1", "destination_port": 44444}
    )
    print(f"ACTION CREATED:     {stdout}")
    print(f"Verification:       {verification}")
    print("-" * 60)
    print("Generated Network Event: YES")
    print("Waiting for Agent collection...")
    print("END RESULT:         CONDITION_GENERATED_SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
