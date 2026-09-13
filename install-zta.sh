#!/usr/bin/env bash
# Install ZTA Platform locally without changing system Python or manager config.
set -euo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"
command -v python3 >/dev/null || { echo 'Python 3.11+ is required.' >&2; exit 1; }
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
echo 'ZTA Platform installed.'
echo "Start: $PROJECT_DIR/.venv/bin/python -m zta"
echo "Tests: $PROJECT_DIR/.venv/bin/python -m pytest"
