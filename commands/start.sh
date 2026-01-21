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
    load_sandbox_metadata "$name" || true

    echo "Starting sandbox: $name..."
    ensure_override_from_metadata "$name" "$override_file"
    ensure_dir "$(dirname "$override_file")"
    local claude_home_path
    claude_home_path=$(path_claude_home "$name")
    ensure_dir "$claude_home_path"
    add_claude_home_to_override "$override_file" "$claude_home_path"

    # Pre-populate Claude plugins if not already cached (skip if already populated)
    prepopulate_claude_plugins "$claude_home_path" "1"

    local enable_ssh="0"
    if [ "${SANDBOX_SYNC_SSH:-0}" = "1" ]; then
        if [ "${SANDBOX_SSH_MODE:-}" = "init" ] || [ "${SANDBOX_SSH_MODE:-}" = "disabled" ]; then
            log_warn "SSH mode '${SANDBOX_SSH_MODE:-}' disables forwarding; use --with-ssh to enable."
            add_ssh_agent_to_override "$override_file" ""
        else
            local ssh_agent_sock=""
            ssh_agent_sock=$(resolve_ssh_agent_sock) || ssh_agent_sock=""
            if [ -n "$ssh_agent_sock" ]; then
                add_ssh_agent_to_override "$override_file" "$ssh_agent_sock"
                enable_ssh="1"
            else
                log_warn "SSH agent not detected; SSH forwarding disabled (agent-only mode)."
                add_ssh_agent_to_override "$override_file" ""
            fi
        fi
    else
        add_ssh_agent_to_override "$override_file" ""
    fi
    compose_up "$worktree_path" "$claude_config_path" "$container" "$override_file"

    local container_id="${container}-dev-1"
    copy_configs_to_container "$container_id" "0" "$enable_ssh"

    # Apply network restrictions AFTER plugin/MCP registration completes
    if [ -n "${SANDBOX_NETWORK_MODE:-}" ] && [ "$SANDBOX_NETWORK_MODE" != "full" ]; then
        echo "Applying network mode: $SANDBOX_NETWORK_MODE"
        if [ "$SANDBOX_NETWORK_MODE" = "limited" ]; then
            run_cmd docker exec "$container_id" sudo /usr/local/bin/network-firewall.sh
        else
            run_cmd docker exec "$container_id" sudo /usr/local/bin/network-mode "$SANDBOX_NETWORK_MODE"
        fi
    fi
}
