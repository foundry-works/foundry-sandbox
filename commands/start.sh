#!/bin/bash

cmd_start() {
    local name="$1"

    if [ -z "$name" ]; then
        echo "Usage: $0 start <sandbox-name>"
        exit 1
    fi

    derive_sandbox_paths "$name"
    local worktree_path="$DERIVED_WORKTREE_PATH"
    local container="$DERIVED_CONTAINER_NAME"
    local claude_config_path="$DERIVED_CLAUDE_CONFIG_PATH"
    local override_file="$DERIVED_OVERRIDE_FILE"

    if [ ! -d "$worktree_path" ]; then
        echo "Error: Sandbox '$name' not found"
        exit 1
    fi

    check_image_freshness

    echo "Starting sandbox: $name..."
    ensure_override_from_metadata "$name" "$override_file"
    compose_up "$worktree_path" "$claude_config_path" "$container" "$override_file"

    local container_id="${container}-dev-1"
    copy_configs_to_container "$container_id"
}
