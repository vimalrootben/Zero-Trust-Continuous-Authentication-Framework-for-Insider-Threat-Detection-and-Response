#!/usr/bin/env bash
# Compatibility setup entry point for ZTA's Python manager application.
set -euo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
bash "$PROJECT_DIR/install-zta.sh"
cd "$PROJECT_DIR"
.venv/bin/python -m pytest -q
printf '%s\n' 'ZTA dashboard/API setup verified. Native EDR components in src/ require a separate build and deployment.'
