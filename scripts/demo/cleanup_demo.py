#!/usr/bin/env python3
"""Controlled Demo Cleanup Utility."""

import os
import shutil
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from zta.agent.execution.script_registry import get_demo_temp_dir


def cleanup_demo_artifacts():
    """Removes temporary demo files while preserving production telemetry and database logs."""
    demo_dir = get_demo_temp_dir()
    cleaned = 0
    if os.path.exists(demo_dir):
        for item in os.listdir(demo_dir):
            item_path = os.path.join(demo_dir, item)
            try:
                if os.path.isfile(item_path):
                    os.remove(item_path)
                    cleaned += 1
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                    cleaned += 1
            except Exception as e:
                print(f"Warning: Could not remove {item_path}: {e}")
    print(f"Cleaned up {cleaned} temporary demo artifacts in {demo_dir}.")


if __name__ == "__main__":
    cleanup_demo_artifacts()
