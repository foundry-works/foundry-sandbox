#!/bin/bash

cmd_new() {
    parse_new_args "$@"
    local repo_url="$NEW_REPO_URL"
    local branch="$NEW_BRANCH"
    local from_branch="$NEW_FROM_BRANCH"
    local mounts=("${NEW_MOUNTS[@]}")
    local copies=("${NEW_COPIES[@]}")
    local network_mode="$NEW_NETWORK_MODE"
    local sync_ssh="$NEW_SYNC_SSH"
    local ssh_mode="$NEW_SSH_MODE"
    local skip_key_check="$NEW_SKIP_KEY_CHECK"
    local ssh_agent_sock=""
    local repo_root=""
    local current_branch=""

    if [ -n "$repo_url" ]; then
        case "$repo_url" in
            .|/*|./*|../*|~/*)
                repo_root=$(git -C "$repo_url" rev-parse --show-toplevel 2>/dev/null || true)
                if [ -z "$repo_root" ]; then
                    die "Not a git repository: $repo_url"
                fi
                current_branch=$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
                if [ -z "$current_branch" ] || [ "$current_branch" = "HEAD" ]; then
                    die "Repository is in a detached HEAD state; specify a base branch."
                fi
                if [ -z "$branch" ] && [ -z "$from_branch" ]; then
                    from_branch="$current_branch"
                fi
                local origin_url
                origin_url=$(git -C "$repo_root" remote get-url origin 2>/dev/null || true)
                if [ -n "$origin_url" ]; then
                    repo_url="$origin_url"
                else
                    repo_url="$repo_root"
                fi
                ;;
        esac
    fi

    if [ -z "$branch" ]; then
        local timestamp
        timestamp=$(date +%Y%m%d-%H%M)
        local repo_name
        repo_name=$(basename "${repo_url%.git}" | sed 's/.*\///')
        local user_segment="${USER:-}"
        if [ -z "$user_segment" ]; then
            user_segment=$(id -un 2>/dev/null || true)
        fi
        if [ -z "$user_segment" ]; then
            user_segment=$(whoami 2>/dev/null || true)
        fi
        user_segment=$(sanitize_ref_component "$user_segment")
        local safe_repo_name
        safe_repo_name=$(sanitize_ref_component "$repo_name")
        if [ -z "$user_segment" ]; then
            user_segment="user"
        fi
        if [ -z "$safe_repo_name" ]; then
            safe_repo_name="repo"
        fi
        branch="${user_segment}/${safe_repo_name}-${timestamp}"
        if ! git check-ref-format --branch "$branch" >/dev/null 2>&1; then
            local fallback_branch="${safe_repo_name}-${timestamp}"
            if git check-ref-format --branch "$fallback_branch" >/dev/null 2>&1; then
                branch="$fallback_branch"
            else
                branch="sandbox-${timestamp}"
            fi
        fi
        from_branch="${from_branch:-main}"
    fi

    if [ -z "$repo_url" ]; then
        echo "Usage: $0 new <repo> [branch] [from-branch] [options]"
        echo ""
        echo "Options:"
        echo "  --mount, -v host:container[:ro]  Mount host path into container"
        echo "  --copy, -c  host:container       Copy host path into container (once at creation)"
        echo "  --network, -n <mode>             Network isolation mode (default: limited)"
        echo "                                   Modes: full, limited, host-only, none"
        echo "  --with-ssh                       Enable SSH agent forwarding (opt-in, agent-only)"
        echo "  --skip-key-check                 Skip API key validation"
        echo ""
        echo "Examples:"
        echo "  $0 new user/repo                     # auto-create sandbox branch from main"
        echo "  $0 new .                             # use current repo/branch"
        echo "  $0 new user/repo feature-branch      # checkout existing branch"
        echo "  $0 new user/repo new-feature main    # create new branch from main"
        echo "  $0 new user/repo feature --mount /data:/data --mount /models:/models:ro"
        echo "  $0 new user/repo feature --copy /path/to/models:/models"
        echo "  $0 new user/repo feature --network=limited  # restrict network to whitelist"
        exit 1
    fi

    # Check API keys unless skipped (keys are expected in the environment)
    if [ "$skip_key_check" != "true" ]; then
        if ! check_any_ai_key; then
            # No AI key - prompt to continue
            if ! prompt_missing_keys; then
                die "Sandbox creation cancelled."
            fi
        elif ! check_any_search_key; then
            # AI key present but no search key - just warn
            show_missing_search_keys_warning
        fi
    fi

    # Validate --copy source paths exist before creating anything
    if [ ${#copies[@]} -gt 0 ]; then
        for copy_spec in "${copies[@]}"; do
            local src="${copy_spec%%:*}"
            if [ ! -e "$src" ]; then
                die "Copy source does not exist: $src"
            fi
        done
    fi

    if [[ "$repo_url" != http* && "$repo_url" != git@* && "$repo_url" != *"://"* && "$repo_url" != /* && "$repo_url" != ./* && "$repo_url" != ../* && "$repo_url" != ~/* ]]; then
        repo_url="https://github.com/$repo_url"
    fi

    validate_git_url "$repo_url"
    check_image_freshness

    SANDBOX_NETWORK_MODE="$network_mode"
    SANDBOX_SYNC_SSH="$sync_ssh"
    SANDBOX_SSH_MODE=""
    if [ "$SANDBOX_SYNC_SSH" = "1" ]; then
        if [ "$ssh_mode" = "init" ] || [ "$ssh_mode" = "disabled" ]; then
            log_warn "SSH mode '$ssh_mode' disables forwarding; use --with-ssh to enable."
            SANDBOX_SYNC_SSH="0"
        else
            SANDBOX_SSH_MODE="always"
        fi
    fi
    if [ "$SANDBOX_SYNC_SSH" != "1" ]; then
        SANDBOX_SSH_MODE="disabled"
    fi
    if [ "$SANDBOX_SYNC_SSH" = "1" ]; then
        ssh_agent_sock=$(resolve_ssh_agent_sock) || ssh_agent_sock=""
    fi

    local bare_path
    bare_path=$(repo_to_path "$repo_url")
    local name
    name=$(sandbox_name "$bare_path" "$branch")
    local worktree_dir
    worktree_dir=$(path_worktree "$name")
    local metadata_path
    local legacy_metadata_path
    metadata_path=$(path_metadata_file "$name")
    legacy_metadata_path=$(path_metadata_legacy_file "$name")
    if [ -f "$metadata_path" ] || [ -f "$legacy_metadata_path" ]; then
        if ! load_sandbox_metadata "$name"; then
            die "Sandbox name collision: existing metadata for '$name' cannot be read."
        fi
        if [ -n "$SANDBOX_REPO_URL" ]; then
            local existing_bare
            existing_bare=$(repo_to_path "$SANDBOX_REPO_URL")
            if [ "$existing_bare" != "$bare_path" ]; then
                die "Sandbox name collision: '$name' already used for $SANDBOX_REPO_URL. Pick a different branch name."
            fi
        fi
    fi
    if dir_exists "$worktree_dir"; then
        local worktree_git="$worktree_dir/.git"
        if [ -f "$worktree_git" ]; then
            local gitdir=""
            gitdir=$(sed -n 's/^gitdir: //p' "$worktree_git" 2>/dev/null || true)
            if [ -n "$gitdir" ]; then
                if [[ "$gitdir" != /* ]]; then
                    gitdir="$worktree_dir/$gitdir"
                fi
                case "$gitdir" in
                    "$bare_path"/*) ;;
                    *)
                        die "Sandbox name collision: '$name' already points to another repo worktree."
                        ;;
                esac
            else
                die "Sandbox name collision: '$name' already exists but is not a sandbox worktree."
            fi
        else
            die "Sandbox name collision: '$name' already exists at $worktree_dir."
        fi
    fi
    local container
    container=$(container_name "$name")

    echo "Creating sandbox: $name"

    ensure_bare_repo "$repo_url" "$bare_path"
    create_worktree "$bare_path" "$worktree_dir" "$branch" "$from_branch"

    local claude_config_path
    claude_config_path=$(path_claude_config "$name")
    ensure_dir "$claude_config_path"

    local override_file
    override_file=$(path_override_file "$name")
    local claude_home_path
    if [ ${#mounts[@]} -gt 0 ]; then
        echo "Adding custom mounts..."
        cat > "$override_file" <<OVERRIDES
services:
  dev:
    volumes:
OVERRIDES
        for mount in "${mounts[@]}"; do
            echo "      - $mount" >> "$override_file"
        done
    fi

    # Add network mode configuration
    if [ -n "$network_mode" ] && [ "$network_mode" != "full" ]; then
        echo "Setting network mode: $network_mode"
        add_network_to_override "$network_mode" "$override_file"
    elif [ "$network_mode" = "full" ]; then
        # Full mode: still add capabilities for runtime switching
        add_network_to_override "full" "$override_file"
    fi

    claude_home_path=$(path_claude_home "$name")
    ensure_dir "$claude_home_path"
    add_claude_home_to_override "$override_file" "$claude_home_path"

    # Pre-populate Claude plugins on host before container starts (no network needed inside)
    prepopulate_claude_plugins "$claude_home_path" "0"

    local runtime_enable_ssh="0"
    if [ "$SANDBOX_SYNC_SSH" = "1" ]; then
        if [ -n "$ssh_agent_sock" ]; then
            echo "Enabling SSH agent forwarding..."
            add_ssh_agent_to_override "$override_file" "$ssh_agent_sock"
            runtime_enable_ssh="1"
        else
            log_warn "SSH agent not detected; SSH forwarding disabled (agent-only mode)."
            add_ssh_agent_to_override "$override_file" ""
        fi
    else
        add_ssh_agent_to_override "$override_file" ""
    fi

    write_sandbox_metadata "$name" "$repo_url" "$branch" "$from_branch" "${mounts[@]}" -- "${copies[@]}"

    local container_id="${container}-dev-1"
    echo "Starting container: $container..."
    compose_up "$worktree_dir" "$claude_config_path" "$container" "$override_file"
    copy_configs_to_container "$container_id" "0" "$runtime_enable_ssh"

    if [ ${#copies[@]} -gt 0 ]; then
        echo "Copying files into container..."
        for copy_spec in "${copies[@]}"; do
            local src="${copy_spec%%:*}"
            local dst="${copy_spec#*:}"
            if [ ! -e "$src" ]; then
                echo "  Warning: Source '$src' does not exist, skipping"
                continue
            fi
            echo "  $src -> $dst"
            # Use tar piping instead of docker cp to avoid read-only rootfs issues
            if [ -d "$src" ]; then
                copy_dir_to_container "$container_id" "$src" "$dst"
            else
                copy_file_to_container "$container_id" "$src" "$dst"
            fi
        done
    fi

    # Install foundry permissions into workspace
    install_workspace_permissions "$container_id"

    # Apply network restrictions AFTER plugin/MCP registration completes
    if [ -n "$network_mode" ] && [ "$network_mode" != "full" ]; then
        echo "Applying network mode: $network_mode"
        if [ "$network_mode" = "limited" ]; then
            run_cmd docker exec "$container_id" sudo /usr/local/bin/network-firewall.sh
        else
            run_cmd docker exec "$container_id" sudo /usr/local/bin/network-mode "$network_mode"
        fi
    fi

    echo ""
    echo "Sandbox '$name' is ready!"
    echo "  Attach:  $0 attach $name"
    echo "  Stop:    $0 stop $name"
    echo "  Destroy: $0 destroy $name"
    echo ""

    tmux_attach "$name"
}
