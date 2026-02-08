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
    export SANDBOX_ENABLE_OPENCODE SANDBOX_ENABLE_ZAI
    if [ "${SANDBOX_ENABLE_ZAI:-0}" != "1" ]; then
        export ZHIPU_API_KEY=
    fi

    local uses_credential_isolation="0"
    if docker ps -a --format '{{.Names}}' | grep -q "^${container}-unified-proxy-"; then
        uses_credential_isolation="1"
    fi

    if [ "$uses_credential_isolation" = "1" ]; then
        if [ ! -f "$HOME/.codex/auth.json" ]; then
            log_warn "Credential isolation: ~/.codex/auth.json not found; Codex CLI will not work."
            log_warn "Run 'codex auth' to create it if you plan to use Codex."
        fi
        if [ ! -f "$HOME/.local/share/opencode/auth.json" ]; then
            if [ "${SANDBOX_ENABLE_OPENCODE:-0}" = "1" ]; then
                if has_zai_key; then
                    log_warn "OpenCode enabled but auth file not found; relying on ZHIPU_API_KEY fallback (credential isolation)."
                else
                    log_warn "OpenCode enabled but auth file not found; OpenCode CLI will not work in credential isolation."
                fi
            else
                log_warn "Credential isolation: ~/.local/share/opencode/auth.json not found; OpenCode CLI will not work."
                log_warn "Run 'opencode auth login' to create it if you plan to use OpenCode."
            fi
        fi
        if [ ! -f "$HOME/.gemini/oauth_creds.json" ] && [ -z "${GEMINI_API_KEY:-}" ]; then
            log_warn "Credential isolation: ~/.gemini/oauth_creds.json not found and GEMINI_API_KEY not set; Gemini CLI will not work."
            log_warn "Run 'gemini auth' or set GEMINI_API_KEY if you plan to use Gemini."
        fi
    fi

    warn_claude_auth_conflict

    if [ "${SANDBOX_ENABLE_ZAI:-0}" = "1" ] && ! has_zai_key; then
        log_warn "ZAI enabled but ZHIPU_API_KEY not set on host; claude-zai will not work."
    fi

    if [ "${SANDBOX_ENABLE_OPENCODE:-0}" = "1" ] && ! has_opencode_key && [ "$uses_credential_isolation" != "1" ]; then
        log_warn "OpenCode enabled but auth file not found; OpenCode setup will be skipped."
        log_warn "Run 'opencode auth login' or re-run with --with-opencode after configuring ~/.local/share/opencode/auth.json."
    fi

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

    # Check if credential isolation is enabled (unified-proxy container exists)
    # and repopulate stubs volume before starting
    local isolate_credentials=""
    if docker ps -a --format '{{.Names}}' | grep -q "^${container}-unified-proxy-"; then
        isolate_credentials="true"
        populate_stubs_volume "$container"
        export STUBS_VOLUME_NAME="${container}_stubs"
        export HMAC_VOLUME_NAME="${container}_hmac"
        # Reuse the existing per-sandbox secret volume when available.
        if docker volume inspect "${HMAC_VOLUME_NAME}" >/dev/null 2>&1; then
            # Repair legacy permissions so both runtime users can read the secret.
            repair_hmac_secret_permissions "$container" || \
                die "Failed to repair HMAC secret permissions for ${HMAC_VOLUME_NAME}"

            local hmac_secret_count
            hmac_secret_count=$(hmac_secret_file_count "$container") || \
                die "Failed to inspect HMAC secrets in ${HMAC_VOLUME_NAME}"
            if ! [[ "$hmac_secret_count" =~ ^[0-9]+$ ]]; then
                die "Invalid HMAC secret count '${hmac_secret_count}' in ${HMAC_VOLUME_NAME}"
            fi

            if [ "$hmac_secret_count" -eq 1 ]; then
                # Prevent accidental reprovisioning with an unrelated host SANDBOX_ID.
                unset SANDBOX_ID
            elif [ "$hmac_secret_count" -eq 0 ]; then
                # Existing volume with no secret: provision a new secret on start.
                SANDBOX_ID=$(generate_sandbox_id "${container}:${name}:$(date +%s%N)") || \
                    die "Failed to generate sandbox identity (missing SHA-256 toolchain)"
                export SANDBOX_ID
                log_warn "HMAC volume ${HMAC_VOLUME_NAME} had no secrets; provisioning a new git shadow secret"
                log_step "Sandbox ID: ${SANDBOX_ID}"
            else
                die "HMAC volume ${HMAC_VOLUME_NAME} has ${hmac_secret_count} secrets (expected 1)"
            fi
        else
            # Backward compatibility: old sandboxes may predate git shadow secret volumes.
            SANDBOX_ID=$(generate_sandbox_id "${container}:${name}:$(date +%s%N)") || \
                die "Failed to generate sandbox identity (missing SHA-256 toolchain)"
            export SANDBOX_ID
            log_warn "Missing HMAC volume ${HMAC_VOLUME_NAME}; provisioning a new git shadow secret"
            log_step "Sandbox ID: ${SANDBOX_ID}"
        fi
        # Export ALLOW_PR_OPERATIONS from metadata
        if [ "${SANDBOX_ALLOW_PR:-0}" = "1" ]; then
            export ALLOW_PR_OPERATIONS=true
        else
            export ALLOW_PR_OPERATIONS=
        fi
    fi

    compose_up "$worktree_path" "$claude_config_path" "$container" "$override_file" "$isolate_credentials"

    local container_id="${container}-dev-1"

    # Register container with unified-proxy on restart (credential isolation)
    if [ "$isolate_credentials" = "true" ]; then
        if [ -z "${SANDBOX_BRANCH:-}" ]; then
            die "Sandbox branch identity missing (created before branch isolation support). Recreate sandbox with 'cast new'."
        fi
        export SANDBOX_GATEWAY_ENABLED=true
        fix_proxy_worktree_paths "${container}-unified-proxy-1" "$(whoami)"
        local repo_spec="${SANDBOX_REPO_URL:-}"
        repo_spec=$(echo "$repo_spec" | sed -E 's#^(https?://)?github\.com/##; s#^git@github\.com:##; s#\.git$##')
        local metadata_json=""
        if command -v jq >/dev/null 2>&1; then
            metadata_json=$(jq -n \
                --arg repo "$repo_spec" \
                --arg allow_pr "${SANDBOX_ALLOW_PR:-0}" \
                --arg sandbox_branch "${SANDBOX_BRANCH:-}" \
                --arg from_branch "${SANDBOX_FROM_BRANCH:-}" \
                '{repo: $repo, allow_pr: ($allow_pr == "1"), sandbox_branch: $sandbox_branch, from_branch: $from_branch}')
        fi
        if ! setup_proxy_registration "$container_id" "$metadata_json"; then
            die "Failed to register container with unified-proxy"
        fi
    fi

    copy_configs_to_container "$container_id" "0" "$enable_ssh" "$SANDBOX_WORKING_DIR" "$isolate_credentials" "$SANDBOX_FROM_BRANCH" "$SANDBOX_BRANCH" "$SANDBOX_REPO_URL"

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
