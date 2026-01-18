#!/bin/bash

cmd_stop() {
    local name="$1"

    if [ -z "$name" ]; then
        echo "Usage: $0 stop <sandbox-name>"
        exit 1
    fi

    derive_sandbox_paths "$name"
    local worktree_path="$DERIVED_WORKTREE_PATH"
    local container="$DERIVED_CONTAINER_NAME"
    local session
    session=$(tmux_session_name "$name")
    local claude_config_path="$DERIVED_CLAUDE_CONFIG_PATH"
    local override_file="$DERIVED_OVERRIDE_FILE"

    echo "Stopping sandbox: $name..."

    tmux kill-session -t "$session" 2>/dev/null || true

    compose_down "$worktree_path" "$claude_config_path" "$container" "$override_file" "false"
}
