#!/usr/bin/env python
"""ZTA Endpoint Agent standalone root launcher."""
from pathlib import Path
import sys

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from zta.agent.agent_daemon import main

if __name__ == "__main__":
    main()
