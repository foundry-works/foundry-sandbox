#!/bin/bash
# Backward-compatible wrapper — delegates to modular runner
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/redteam/runner.sh" "$@"
