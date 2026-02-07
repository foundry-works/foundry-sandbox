#!/bin/bash

cmd_prune() {
    local force=false
    local json_output=false
    local no_container=false
    local networks=false
    local all=false

    while [ $# -gt 0 ]; do
        case "$1" in
            -f|--force) force=true ;;
            --json) json_output=true ;;
            --no-container) no_container=true ;;
            --networks) networks=true ;;
            --all) all=true; no_container=true; networks=true ;;
        esac
        shift
    done

    local removed=()
    local removed_no_container=()
    local removed_networks=()

    # Remove orphaned configs (configs without a worktree)
    for config_dir in "$CLAUDE_CONFIGS_DIR"/*/; do
        [ -d "$config_dir" ] || continue
        local name
        name=$(basename "$config_dir")
        local worktree="$WORKTREES_DIR/$name"
        if ! dir_exists "$worktree"; then
            if [ "$force" = false ]; then
                format_header "Orphaned config: $name"
                format_kv "Claude config" "$config_dir"
                if ! prompt_confirm "Remove this config?" false; then
                    continue
                fi
            fi
            # Load metadata before removal, save to local vars
            SANDBOX_BRANCH="" SANDBOX_REPO_URL=""
            load_sandbox_metadata "$name" 2>/dev/null || true
            local _prune_branch="${SANDBOX_BRANCH:-}"
            local _prune_repo="${SANDBOX_REPO_URL:-}"
            remove_path "$config_dir"
            cleanup_sandbox_branch "$_prune_branch" "$_prune_repo"
            removed+=("$name")
        fi
    done

    # Remove sandboxes with no running container (worktree exists but no running container)
    if [ "$no_container" = true ]; then
        for worktree_dir in "$WORKTREES_DIR"/*/; do
            [ -d "$worktree_dir" ] || continue
            local name
            name=$(basename "$worktree_dir")
            local container
            container=$(container_name "$name")
            local config_dir="$CLAUDE_CONFIGS_DIR/$name"

            # Check if container is running (stopped containers count as "no container")
            if ! docker ps --filter "name=^${container}-dev-1$" -q 2>/dev/null | grep -q .; then
                if [ "$force" = false ]; then
                    format_header "No container: $name"
                    format_kv "Worktree" "$worktree_dir"
                    [ -d "$config_dir" ] && format_kv "Claude config" "$config_dir"
                    if ! prompt_confirm "Remove this sandbox?" false; then
                        continue
                    fi
                fi
                # Load metadata before removal, save to local vars
                SANDBOX_BRANCH="" SANDBOX_REPO_URL=""
                load_sandbox_metadata "$name" 2>/dev/null || true
                local _prune_branch="${SANDBOX_BRANCH:-}"
                local _prune_repo="${SANDBOX_REPO_URL:-}"
                # Remove worktree
                remove_worktree "$worktree_dir"
                # Remove config if it exists
                [ -d "$config_dir" ] && remove_path "$config_dir"
                # Clean up branch after worktree removal
                cleanup_sandbox_branch "$_prune_branch" "$_prune_repo"
                removed_no_container+=("$name")
            fi
        done
    fi

    # Remove orphaned Docker networks (sandbox networks with no running containers)
    if [ "$networks" = true ]; then
        local network_name
        while IFS= read -r network_name; do
            [ -z "$network_name" ] && continue
            # Extract sandbox name from network name (e.g., sandbox-foo-bar_credential-isolation -> sandbox-foo-bar)
            local sandbox_name="${network_name%_credential-isolation}"
            sandbox_name="${sandbox_name%_proxy-egress}"

            # Check if any RUNNING containers belong to this sandbox
            # Stopped containers are not a reason to keep the network
            if ! docker ps -q --filter "name=^${sandbox_name}-" 2>/dev/null | grep -q .; then
                if [ "$force" = false ]; then
                    format_header "Orphaned network: $network_name"
                    if ! prompt_confirm "Remove this network?" false; then
                        continue
                    fi
                fi
                # Remove stopped containers that reference this sandbox before network removal
                local stopped_id
                while IFS= read -r stopped_id; do
                    [ -z "$stopped_id" ] && continue
                    docker rm "$stopped_id" 2>/dev/null || true
                done < <(docker ps -aq --filter "status=exited" --filter "name=^${sandbox_name}-" 2>/dev/null)
                # Disconnect any dangling endpoints before removal
                local endpoint
                while IFS= read -r endpoint; do
                    [ -z "$endpoint" ] && continue
                    docker network disconnect -f "$network_name" "$endpoint" 2>/dev/null || true
                done < <(docker network inspect --format '{{range .Containers}}{{.Name}} {{end}}' "$network_name" 2>/dev/null | tr ' ' '\n')
                if docker network rm "$network_name" 2>/dev/null; then
                    removed_networks+=("$network_name")
                else
                    log_warn "Failed to remove network: $network_name"
                fi
            fi
        done < <(docker network ls --format '{{.Name}}' | grep -E '^sandbox-.*_(credential-isolation|proxy-egress)$')
    fi

    if [ "$json_output" = true ]; then
        {
            for name in "${removed[@]}"; do
                printf '{"name":"%s","type":"orphaned_config"}\n' "$(json_escape "$name")"
            done
            for name in "${removed_no_container[@]}"; do
                printf '{"name":"%s","type":"no_container"}\n' "$(json_escape "$name")"
            done
            for name in "${removed_networks[@]}"; do
                printf '{"name":"%s","type":"orphaned_network"}\n' "$(json_escape "$name")"
            done
        } | json_array_from_lines
        return
    fi

    local any_removed=false
    if [ ${#removed[@]} -gt 0 ]; then
        any_removed=true
        format_header "Removed orphaned configs:"
        for name in "${removed[@]}"; do
            format_kv_list_item "$name"
        done
    fi

    if [ ${#removed_no_container[@]} -gt 0 ]; then
        any_removed=true
        format_header "Removed sandboxes (no container):"
        for name in "${removed_no_container[@]}"; do
            format_kv_list_item "$name"
        done
    fi

    if [ ${#removed_networks[@]} -gt 0 ]; then
        any_removed=true
        format_header "Removed orphaned networks:"
        for name in "${removed_networks[@]}"; do
            format_kv_list_item "$name"
        done
    fi

    if [ "$any_removed" = false ]; then
        if [ "$all" = true ]; then
            format_kv "Prune" "no orphans found"
        elif [ "$networks" = true ]; then
            format_kv "Prune" "no orphaned networks"
        elif [ "$no_container" = true ]; then
            format_kv "Prune" "no orphans found"
        else
            format_kv "Prune" "no orphaned configs"
        fi
    fi
}
