#!/bin/bash

cmd_new() {
    parse_new_args "$@"
    local repo_url="$NEW_REPO_URL"
    local branch="$NEW_BRANCH"
    local from_branch="$NEW_FROM_BRANCH"
    local mounts=("${NEW_MOUNTS[@]}")
    local copies=("${NEW_COPIES[@]}")
    local network_mode="$NEW_NETWORK_MODE"

    if [ -z "$branch" ]; then
        local timestamp
        timestamp=$(date +%Y%m%d-%H%M)
        local repo_name
        repo_name=$(basename "${repo_url%.git}" | sed 's/.*\///')
        branch="sandbox/${repo_name}-${timestamp}"
        from_branch="main"
    fi

    if [ -z "$repo_url" ]; then
        echo "Usage: $0 new <repo> [branch] [from-branch] [options]"
        echo ""
        echo "Options:"
        echo "  --mount, -v host:container[:ro]  Mount host path into container"
        echo "  --copy, -c  host:container       Copy host path into container (once at creation)"
        echo "  --network, -n <mode>             Network isolation mode (default: full)"
        echo "                                   Modes: full, limited, host-only, none"
        echo ""
        echo "Examples:"
        echo "  $0 new user/repo                     # auto-create sandbox branch from main"
        echo "  $0 new user/repo feature-branch      # checkout existing branch"
        echo "  $0 new user/repo new-feature main    # create new branch from main"
        echo "  $0 new user/repo feature --mount /data:/data --mount /models:/models:ro"
        echo "  $0 new user/repo feature --copy /path/to/models:/models"
        echo "  $0 new user/repo feature --network=limited  # restrict network to whitelist"
        exit 1
    fi

    if [[ "$repo_url" != http* && "$repo_url" != git@* ]]; then
        repo_url="https://github.com/$repo_url"
    fi

    validate_git_url "$repo_url"
    check_image_freshness

    local bare_path
    bare_path=$(repo_to_path "$repo_url")
    local name
    name=$(sandbox_name "$bare_path" "$branch")
    local worktree_dir
    worktree_dir=$(path_worktree "$name")
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

    write_sandbox_metadata "$name" "$repo_url" "$branch" "$from_branch" "${mounts[@]}" -- "${copies[@]}"

    echo "Starting container: $container..."
    compose_up "$worktree_dir" "$claude_config_path" "$container" "$override_file"

    local container_id="${container}-dev-1"
    copy_configs_to_container "$container_id"

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
            run_cmd docker exec "$container_id" mkdir -p "$(dirname "$dst")"
            run_cmd docker cp "$src" "$container_id:$dst"
        done
    fi

    echo ""
    echo "Sandbox '$name' is ready!"
    echo "  Attach:  $0 attach $name"
    echo "  Stop:    $0 stop $name"
    echo "  Destroy: $0 destroy $name"
    echo ""

    tmux_attach "$name"
}
