#!/bin/bash

cmd_prune() {
    local force=false
    local json_output=false
    local no_container=false

    while [ $# -gt 0 ]; do
        case "$1" in
            -f|--force) force=true ;;
            --json) json_output=true ;;
            --no-container) no_container=true ;;
        esac
        shift
    done

    local removed=()
    local removed_no_container=()

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
            remove_path "$config_dir"
            removed+=("$name")
        fi
    done

    # Remove sandboxes with no container (worktree exists but container doesn't)
    if [ "$no_container" = true ]; then
        for worktree_dir in "$WORKTREES_DIR"/*/; do
            [ -d "$worktree_dir" ] || continue
            local name
            name=$(basename "$worktree_dir")
            local container
            container=$(container_name "$name")
            local config_dir="$CLAUDE_CONFIGS_DIR/$name"

            # Check if container exists (running or stopped)
            if ! docker ps -a --filter "name=^${container}-dev-1$" -q 2>/dev/null | grep -q .; then
                if [ "$force" = false ]; then
                    format_header "No container: $name"
                    format_kv "Worktree" "$worktree_dir"
                    [ -d "$config_dir" ] && format_kv "Claude config" "$config_dir"
                    if ! prompt_confirm "Remove this sandbox?" false; then
                        continue
                    fi
                fi
                # Remove worktree
                remove_worktree "$worktree_dir"
                # Remove config if it exists
                [ -d "$config_dir" ] && remove_path "$config_dir"
                removed_no_container+=("$name")
            fi
        done
    fi

    if [ "$json_output" = true ]; then
        {
            for name in "${removed[@]}"; do
                printf '{"name":"%s","type":"orphaned_config"}\n' "$(json_escape "$name")"
            done
            for name in "${removed_no_container[@]}"; do
                printf '{"name":"%s","type":"no_container"}\n' "$(json_escape "$name")"
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

    if [ "$any_removed" = false ]; then
        if [ "$no_container" = true ]; then
            format_kv "Prune" "no orphans found"
        else
            format_kv "Prune" "no orphaned configs"
        fi
    fi
}
