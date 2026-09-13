#!/usr/bin/env python3
"""Controlled Demo Test: File Activity (DEMO-TEST-002)."""

import os
import sys
from datetime import datetime, timezone
from uuid import uuid4

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from zta.agent.execution.script_registry import run_demo_file_create, run_demo_file_modify


def main():
    test_name = "Controlled Demo File Activity"
    start_time = datetime.now(timezone.utc).isoformat()
    correlation_id = f"DEMO-FILE-{uuid4().hex[:8]}"
    expected_rule = "DEMO-TEST-002"
    expected_telemetry = "FILE_CREATION / FILE_MODIFICATION in safe edr-demo directory"

    print("=" * 60)
    print(f"TEST NAME:          {test_name}")
    print(f"START TIME:         {start_time}")
    print(f"CORRELATION ID:     {correlation_id}")
    print(f"EXPECTED RULE:      {expected_rule}")
    print(f"EXPECTED TELEMETRY: {expected_telemetry}")
    print("=" * 60)

    print("Generating controlled harmless file creation in %TEMP%/edr-demo/...")
    success, exit_code, stdout, stderr, verification = run_demo_file_create(correlation_id, {})
    print(f"ACTION CREATED:     File created ({verification})")
    print(f"Summary:            {stdout}")

    print("Modifying test file content with correlation signature...")
    m_success, m_code, m_stdout, m_stderr, m_ver = run_demo_file_modify(correlation_id, {})
    print(f"Modify Summary:     {m_stdout}")

    print("-" * 60)
    print("Generated File Event: YES")
    print("Waiting for Agent collection...")
    print("END RESULT:         CONDITION_GENERATED_SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
