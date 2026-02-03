#!/bin/bash

cmd_destroy_all() {
    local keep_worktree=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --keep-worktree) keep_worktree=true ;;
        esac
        shift
    done

    local sandboxes=()
    for worktree in "$WORKTREES_DIR"/*/; do
        [ -d "$worktree" ] || continue
        sandboxes+=("$(basename "$worktree")")
    done

    if [ ${#sandboxes[@]} -eq 0 ]; then
        echo "No sandboxes to destroy."
        return 0
    fi

    echo "This will destroy ALL sandboxes (${#sandboxes[@]} total):"
    for name in "${sandboxes[@]}"; do
        echo "  - $name"
    done
    echo ""
    echo "Including:"
    echo "  - All Docker containers and volumes"
    [ "$keep_worktree" = false ] && echo "  - All worktrees"
    [ "$keep_worktree" = false ] && echo "  - All Claude configs"
    echo ""

    # First confirmation
    read -r -p "Are you sure you want to destroy all sandboxes? [y/N] " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        return 0
    fi

    # Second confirmation
    read -r -p "Type 'destroy all' to confirm: " response
    if [ "$response" != "destroy all" ]; then
        echo "Aborted."
        return 0
    fi

    local failed=()
    for name in "${sandboxes[@]}"; do
        echo ""
        echo "Destroying sandbox: $name..."

        derive_sandbox_paths "$name"
        local worktree_path="$DERIVED_WORKTREE_PATH"
        local container="$DERIVED_CONTAINER_NAME"
        local claude_config_path="$DERIVED_CLAUDE_CONFIG_PATH"
        local override_file="$DERIVED_OVERRIDE_FILE"
        local session
        session=$(tmux_session_name "$name")

        tmux kill-session -t "$session" 2>/dev/null || true
        compose_down "$worktree_path" "$claude_config_path" "$container" "$override_file" "true" 2>/dev/null || true

        if [ "$keep_worktree" = false ] && [ -d "$claude_config_path" ]; then
            rm -rf "$claude_config_path"
        fi

        if [ "$keep_worktree" = false ]; then
            if [ -d "$worktree_path" ]; then
                if ! remove_worktree "$worktree_path"; then
                    failed+=("$name")
                    continue
                fi
            fi
        fi

        # Remove credential isolation networks for this sandbox
        for network_suffix in credential-isolation proxy-egress; do
            local network_name="${container}_${network_suffix}"
            if docker network inspect "$network_name" >/dev/null 2>&1; then
                docker network rm "$network_name" 2>/dev/null || true
            fi
        done

        echo "Sandbox '$name' destroyed."
    done

    # Final cleanup: remove any remaining orphaned sandbox networks
    local orphaned_networks=0
    while IFS= read -r network_name; do
        [ -z "$network_name" ] && continue
        if docker network rm "$network_name" 2>/dev/null; then
            ((orphaned_networks++))
        fi
    done < <(docker network ls --format '{{.Name}}' | grep -E '^sandbox-.*_(credential-isolation|proxy-egress)$')

    echo ""
    echo "Destroyed ${#sandboxes[@]} sandbox(es)."
    [ "$orphaned_networks" -gt 0 ] && echo "Cleaned up $orphaned_networks orphaned network(s)."

    if [ ${#failed[@]} -gt 0 ]; then
        echo "Failed to fully remove worktrees for: ${failed[*]}"
        return 1
    fi
}
