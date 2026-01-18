#!/bin/bash

SANDBOX_HOME="${SANDBOX_HOME:-$HOME/.sandboxes}"
REPOS_DIR="$SANDBOX_HOME/repos"
WORKTREES_DIR="$SANDBOX_HOME/worktrees"
CLAUDE_CONFIGS_DIR="$SANDBOX_HOME/claude-config"

if [ -z "${SCRIPT_DIR:-}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

DOCKER_IMAGE="foundry-sandbox:latest"
CONTAINER_USER="ubuntu"
CONTAINER_HOME="/home/$CONTAINER_USER"

SANDBOX_DEBUG="${SANDBOX_DEBUG:-0}"
SANDBOX_VERBOSE="${SANDBOX_VERBOSE:-0}"
SANDBOX_ASSUME_YES="${SANDBOX_ASSUME_YES:-0}"

# Network mode: full, limited, host-only, none
SANDBOX_NETWORK_MODE="${SANDBOX_NETWORK_MODE:-limited}"
