#!/usr/bin/env python
"""ZTA Manager standalone root launcher."""
from pathlib import Path
import sys

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from zta.dashboard.run_dashboard import main

if __name__ == "__main__":
    main()
