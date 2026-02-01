#!/bin/bash

cmd_destroy() {
    parse_destroy_args "$@"
    local name="$DESTROY_NAME"
    local keep_worktree="$DESTROY_KEEP_WORKTREE"
    local force="$DESTROY_FORCE"

    if [ -z "$name" ]; then
        echo "Usage: $0 destroy <sandbox-name> [--keep-worktree] [-f|--force] [-y|--yes]"
        exit 1
    fi

    derive_sandbox_paths "$name"
    local worktree_path="$DERIVED_WORKTREE_PATH"
    local container="$DERIVED_CONTAINER_NAME"
    local claude_config_path="$DERIVED_CLAUDE_CONFIG_PATH"
    local override_file="$DERIVED_OVERRIDE_FILE"
    local session
    session=$(tmux_session_name "$name")

    if [ "$force" = false ]; then
        echo "This will destroy sandbox '$name' including:"
        echo "  - Docker container and volumes"
        [ "$keep_worktree" = false ] && echo "  - Worktree at $worktree_path"
        [ "$keep_worktree" = false ] && echo "  - Claude config at $claude_config_path"
        echo ""
        SANDBOX_ASSUME_YES="$DESTROY_ASSUME_YES"
        if ! prompt_confirm "Are you sure?" false; then
            echo "Aborted."
            exit 0
        fi
    fi

    echo "Destroying sandbox: $name..."

    tmux kill-session -t "$session" 2>/dev/null || true

    # Cleanup gateway session before destroying container (if credential isolation was enabled)
    local container_id="${container}-dev-1"
    if docker ps -q -f "name=${container_id}" 2>/dev/null | grep -q .; then
        # Set up GATEWAY_URL if gateway container is running
        if setup_gateway_url "$container" 2>/dev/null; then
            cleanup_gateway_session "$container_id"
        fi
    fi

    compose_down "$worktree_path" "$claude_config_path" "$container" "$override_file" "true" 2>/dev/null || true

    # Remove stubs volume (external volume not removed by compose down -v)
    remove_stubs_volume "$container"

    if [ "$keep_worktree" = false ] && [ -d "$claude_config_path" ]; then
        echo "Removing Claude config..."
        rm -rf "$claude_config_path"
    fi

    if [ "$keep_worktree" = false ]; then
        if [ -d "$worktree_path" ]; then
            echo "Removing worktree..."
            remove_worktree "$worktree_path"
        fi
    fi

    echo "Sandbox '$name' destroyed."
}
