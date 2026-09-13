#!/usr/bin/env python3
"""End-to-End Orchestrator: Full Pipeline Demo & Validation (DEMO-TEST-001 through DEMO-TEST-004)."""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from uuid import uuid4

import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from zta.agent.execution.script_registry import (
    run_demo_process_start,
    run_demo_file_create,
    run_demo_file_modify,
    run_demo_network_connection,
    run_demo_listening_port,
)


def run_full_pipeline_demo(manager_url: str = "http://127.0.0.1:8080", admin_token: str = ""):
    session_correlation_id = f"DEMO-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc).isoformat()

    print("=" * 80)
    print("ZTA ZERO TRUST EDR - CONTROLLED DEMO & PIPELINE VALIDATION")
    print(f"SESSION CORRELATION ID: {session_correlation_id}")
    print(f"START TIME:             {start_time}")
    print(f"TARGET MANAGER URL:     {manager_url}")
    print("=" * 80)

    headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}
    results = []

    tests = [
        {
            "num": 1,
            "name": "Process Trigger Event",
            "rule_code": "DEMO-TEST-001",
            "func": lambda cid: run_demo_process_start(cid, {}),
            "telemetry_type": "PROCESS_CREATION",
        },
        {
            "num": 2,
            "name": "File Activity Event",
            "rule_code": "DEMO-TEST-002",
            "func": lambda cid: run_demo_file_create(cid, {}),
            "telemetry_type": "FILE_CREATION",
        },
        {
            "num": 3,
            "name": "Network Connection Event",
            "rule_code": "DEMO-TEST-003",
            "func": lambda cid: run_demo_network_connection(cid, {"destination_ip": "127.0.0.1", "destination_port": 44444}),
            "telemetry_type": "NETWORK_CONNECTION",
        },
        {
            "num": 4,
            "name": "Listening Port Event",
            "rule_code": "DEMO-TEST-004",
            "func": lambda cid: run_demo_listening_port(cid, {"port": 44445, "host": "127.0.0.1"}),
            "telemetry_type": "SYSTEM_EVENT",
        },
    ]

    for t in tests:
        test_corr = f"{session_correlation_id}-T{t['num']}"
        print(f"\n[{t['num']}/4] EXECUTING DEMO CONDITION: {t['name']}")
        print(f"  Correlation ID: {test_corr}")
        print(f"  Expected Rule:  {t['rule_code']}")

        ok, code, stdout, stderr, ver = t["func"](test_corr)
        print(f"  OS Event Generated: {'YES' if ok else 'NO'}")
        print(f"  Verification Marker: {ver}")

        results.append({
            "test_num": t["num"],
            "test_name": t["name"],
            "rule_code": t["rule_code"],
            "correlation_id": test_corr,
            "generated": ok,
            "verification": ver,
            "stdout": stdout,
        })

    print("\n" + "=" * 80)
    print("DEMO ACTIVITY GENERATION SUMMARY:")
    print("=" * 80)
    for r in results:
        status_str = "SUCCESS (Condition Generated)" if r["generated"] else "FAILED"
        print(f"Test {r['test_num']}: {r['test_name']} -> {status_str} | Corr: {r['correlation_id']}")

    print("-" * 80)
    print("Querying Manager Status & Telemetry...")
    try:
        res = requests.get(f"{manager_url}/api/zta/overview", headers=headers, timeout=5)
        if res.status_code == 200:
            ov = res.json()
            print(f"Manager Status:         {ov.get('status')}")
            print(f"Active Endpoints:       {ov.get('online_agents')} / {ov.get('total_endpoints')}")
            print(f"Total Stored Events:    {ov.get('total_events')}")
            print(f"Open Alerts:            {ov.get('open_incidents')}")
            print(f"Rule Matches:           {ov.get('rule_matches')}")
            print(f"Policy Triggers:        {ov.get('policy_triggers')}")
    except Exception as exc:
        print(f"Manager status check note: {exc} (Manager may be offline or in background mode)")

    print("=" * 80)
    print(f"END RESULT: FULL DEMO PIPELINE GENERATED (Correlation: {session_correlation_id})")
    print("=" * 80)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZTA Full Pipeline Demo Orchestrator")
    parser.add_argument("--manager-url", default="http://127.0.0.1:8080", help="Manager API URL")
    parser.add_argument("--token", default=os.environ.get("ZTA_ADMIN_TOKEN", ""), help="Admin Bearer Token")
    args = parser.parse_args()
    run_full_pipeline_demo(args.manager_url, args.token)
