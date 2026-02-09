#!/bin/bash

# AI Dev Sandbox - Ephemeral worktree-based development environments
#
# Thin wrapper that delegates all commands to the Python CLI.
# The Python CLI (foundry_sandbox.cli) handles command dispatch,
# including shell fallback for any remaining unmigrated commands.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export SCRIPT_DIR

exec python3 -m foundry_sandbox.cli "$@"
