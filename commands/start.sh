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
    add_timezone_to_override "$override_file"

    # Pre-populate foundry skills and hooks if not already installed (skip if already populated)
    prepopulate_foundry_global "$claude_home_path" "1"

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

    # Export gh token if available (needed for macOS keychain)
    if export_gh_token; then
        log_info "GitHub CLI token exported for container"
    fi

    # Check if credential isolation is enabled (api-proxy container exists)
    # and repopulate stubs volume before starting
    local isolate_credentials=""
    if docker ps -a --format '{{.Names}}' | grep -q "^${container}-api-proxy-"; then
        isolate_credentials="true"
        populate_stubs_volume "$container"
        export STUBS_VOLUME_NAME="${container}_stubs"
        # Export ALLOW_PR_OPERATIONS from metadata
        if [ "${SANDBOX_ALLOW_PR:-0}" = "1" ]; then
            export ALLOW_PR_OPERATIONS=true
        else
            export ALLOW_PR_OPERATIONS=
        fi
    fi

    compose_up "$worktree_path" "$claude_config_path" "$container" "$override_file" "$isolate_credentials"

    local container_id="${container}-dev-1"

    # Refresh gateway session on restart (if credential isolation enabled)
    # Destroys old token and creates a new one for security
    if setup_gateway_url "$container" 2>/dev/null; then
        # Clean up old session first
        cleanup_gateway_session "$container_id"
        # Create new session with fresh token
        local repo_spec="${SANDBOX_REPO_URL:-}"
        repo_spec=$(echo "$repo_spec" | sed -E 's#^(https?://)?github\.com/##; s#^git@github\.com:##; s#\.git$##')
        if setup_gateway_session "$container_id" "$repo_spec"; then
            export SANDBOX_GATEWAY_ENABLED=true
        else
            log_warn "Gateway session refresh failed - git operations may not work"
        fi
    fi

    copy_configs_to_container "$container_id" "0" "$enable_ssh" "$SANDBOX_WORKING_DIR"

    # Log sparse checkout reminder if enabled
    if [ "${SANDBOX_SPARSE_CHECKOUT:-0}" = "1" ] && [ -n "$SANDBOX_WORKING_DIR" ]; then
        log_info "Sparse checkout active for: $SANDBOX_WORKING_DIR"
    fi

    # Re-install Python packages if configured
    if [ -n "${SANDBOX_PIP_REQUIREMENTS:-}" ]; then
        install_pip_requirements "$container_id" "$SANDBOX_PIP_REQUIREMENTS"
    fi

    # Apply network restrictions AFTER plugin/MCP registration completes
    if [ -n "${SANDBOX_NETWORK_MODE:-}" ]; then
        echo "Applying network mode: $SANDBOX_NETWORK_MODE"
        if [ "$SANDBOX_NETWORK_MODE" = "limited" ]; then
            run_cmd docker exec "$container_id" sudo /usr/local/bin/network-firewall.sh
        else
            run_cmd docker exec "$container_id" sudo /usr/local/bin/network-mode "$SANDBOX_NETWORK_MODE"
        fi
    fi
}
