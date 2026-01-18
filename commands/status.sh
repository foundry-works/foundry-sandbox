#!/bin/bash

cmd_status() {
    local name=""
    local json_output=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --json) json_output=true ;;
            *) [ -z "$name" ] && name="$1" ;;
        esac
        shift
    done

    if [ -z "$name" ]; then
        if [ "$json_output" = true ]; then
            for worktree in "$WORKTREES_DIR"/*/; do
                [ -d "$worktree" ] || continue
                local sandbox_name
                sandbox_name=$(basename "$worktree")
                sandbox_info_json "$sandbox_name"
            done | json_array_from_lines
        else
            format_header "Sandboxes:"
            format_section_break
            for worktree in "$WORKTREES_DIR"/*/; do
                [ -d "$worktree" ] || continue
                local sandbox_name
                sandbox_name=$(basename "$worktree")
                sandbox_info_text_summary "$sandbox_name"
            done
        fi
        return
    fi

    if [ "$json_output" = true ]; then
        sandbox_info_json "$name"
        return
    fi

    derive_sandbox_paths "$name"
    local worktree_path="$DERIVED_WORKTREE_PATH"
    local container="$DERIVED_CONTAINER_NAME"
    local claude_config_path="$DERIVED_CLAUDE_CONFIG_PATH"
    local container_id="${container}-dev-1"

    collect_sandbox_info "$name"

    format_header "Sandbox: $SANDBOX_INFO_NAME"
    if [ "$SANDBOX_INFO_WORKTREE_EXISTS" = true ]; then
        format_kv "Worktree" "$SANDBOX_INFO_WORKTREE"
    else
        format_kv "Worktree" "missing"
    fi

    if [ "$SANDBOX_INFO_CONFIG_EXISTS" = true ]; then
        format_kv "Claude config" "$SANDBOX_INFO_CONFIG"
    else
        format_kv "Claude config" "missing"
    fi

    format_kv "Container" "$SANDBOX_INFO_CONTAINER_ID ($SANDBOX_INFO_DOCKER_STATUS)"

    if [ "$SANDBOX_INFO_TMUX" = "attached" ]; then
        format_kv "Tmux" "attached"
    else
        format_kv "Tmux" "none"
    fi

    if [ -n "$SANDBOX_INFO_REPO" ] || [ -n "$SANDBOX_INFO_BRANCH" ]; then
        [ -n "$SANDBOX_INFO_REPO" ] && format_kv "Repo" "$SANDBOX_INFO_REPO"
        [ -n "$SANDBOX_INFO_BRANCH" ] && format_kv "Branch" "$SANDBOX_INFO_BRANCH"
        [ -n "$SANDBOX_INFO_FROM_BRANCH" ] && format_kv "From branch" "$SANDBOX_INFO_FROM_BRANCH"
        if [ ${#SANDBOX_INFO_MOUNTS[@]} -gt 0 ]; then
            format_kv "Mounts" ""
            for mount in "${SANDBOX_INFO_MOUNTS[@]}"; do
                format_kv_list_item "$mount"
            done
        fi
        if [ ${#SANDBOX_INFO_COPIES[@]} -gt 0 ]; then
            format_kv "Copies" ""
            for copy in "${SANDBOX_INFO_COPIES[@]}"; do
                format_kv_list_item "$copy"
            done
        fi
    else
        format_kv "Metadata" "none"
    fi
}
