#!/bin/bash

cmd_attach() {
    local name="$1"

    if [ -z "$name" ]; then
        if command -v fzf &>/dev/null && [ -d "$WORKTREES_DIR" ]; then
            name=$(ls -1 "$WORKTREES_DIR" 2>/dev/null | fzf --prompt="Select sandbox: " --height=10 --reverse)
            if [ -z "$name" ]; then
                echo "No sandbox selected."
                exit 1
            fi
        else
            echo "Usage: $0 attach <sandbox-name>"
            echo ""
            cmd_list
            exit 1
        fi
    fi

    derive_sandbox_paths "$name"
    local worktree_path="$DERIVED_WORKTREE_PATH"
    local container="$DERIVED_CONTAINER_NAME"
    local claude_config_path="$DERIVED_CLAUDE_CONFIG_PATH"

    if [ ! -d "$worktree_path" ]; then
        echo "Error: Sandbox '$name' not found"
        cmd_list
        exit 1
    fi

    local container_id="${container}-dev-1"
    if ! container_is_running "$container"; then
        echo "Container not running. Starting..."
        cmd_start "$name"
    else
        # Load metadata to get network mode and other settings
        load_sandbox_metadata "$name" || true

        if [ "${SANDBOX_SYNC_ON_ATTACH:-0}" = "1" ]; then
            sync_runtime_credentials "$container_id"
        else
            log_debug "Skipping credential sync on attach (SANDBOX_SYNC_ON_ATTACH=0)"
        fi

        # Refresh firewall IPs for rotating domains (if limited mode)
        if [ "${SANDBOX_NETWORK_MODE:-}" = "limited" ]; then
            log_debug "Refreshing firewall IPs for rotating domains..."
            docker exec "$container_id" sudo /usr/local/bin/network-firewall.sh refresh 2>/dev/null || true
        fi
    fi

    sync_opencode_local_plugins_on_first_attach "$name" "$container_id"

    tmux_attach "$name"
}
