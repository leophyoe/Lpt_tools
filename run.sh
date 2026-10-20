#!/usr/bin/env bash
# CyberSecuritySuite Startup Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Prepend bin and virtual environment to PATH
export PATH="$SCRIPT_DIR/bin:$SCRIPT_DIR/.venv/bin:$PATH"

# Check if .venv python exists
if [ -f "$SCRIPT_DIR/.venv/bin/python" ]; then
    PYTHON_EXEC="$SCRIPT_DIR/.venv/bin/python"
else
    PYTHON_EXEC="$(which python3)"
fi

exec "$PYTHON_EXEC" "$SCRIPT_DIR/main.py" "$@"

