#!/bin/bash

cmd_prune() {
    local force=false
    local json_output=false

    while [ $# -gt 0 ]; do
        case "$1" in
            -f|--force) force=true ;;
            --json) json_output=true ;;
        esac
        shift
    done

    local removed=()

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

    if [ "$json_output" = true ]; then
        for name in "${removed[@]}"; do
            printf '{"name":"%s"}\n' "$(json_escape "$name")"
        done | json_array_from_lines
        return
    fi

    if [ ${#removed[@]} -eq 0 ]; then
        format_kv "Prune" "no orphaned configs"
    else
        format_header "Removed configs:"
        for name in "${removed[@]}"; do
            format_kv_list_item "$name"
        done
    fi
}
