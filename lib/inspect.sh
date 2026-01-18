#!/bin/bash

collect_sandbox_info() {
    local name="$1"

    SANDBOX_INFO_NAME="$name"
    SANDBOX_INFO_WORKTREE="$WORKTREES_DIR/$name"
    SANDBOX_INFO_CONFIG="$CLAUDE_CONFIGS_DIR/$name"
    SANDBOX_INFO_CONTAINER_NAME="$(container_name "$name")"
    SANDBOX_INFO_CONTAINER_ID="${SANDBOX_INFO_CONTAINER_NAME}-dev-1"

    SANDBOX_INFO_WORKTREE_EXISTS=false
    SANDBOX_INFO_CONFIG_EXISTS=false
    if dir_exists "$SANDBOX_INFO_WORKTREE"; then
        SANDBOX_INFO_WORKTREE_EXISTS=true
    fi
    if dir_exists "$SANDBOX_INFO_CONFIG"; then
        SANDBOX_INFO_CONFIG_EXISTS=true
    fi

    SANDBOX_INFO_DOCKER_STATUS=$(docker ps -a --filter "name=^${SANDBOX_INFO_CONTAINER_NAME}-dev" --format "{{.Status}}" 2>/dev/null | head -1)
    if [ -z "$SANDBOX_INFO_DOCKER_STATUS" ]; then
        SANDBOX_INFO_DOCKER_STATUS="no container"
    fi

    if tmux_session_exists "$name"; then
        SANDBOX_INFO_TMUX="attached"
    else
        SANDBOX_INFO_TMUX="none"
    fi

    SANDBOX_INFO_REPO=""
    SANDBOX_INFO_BRANCH=""
    SANDBOX_INFO_FROM_BRANCH=""
    SANDBOX_INFO_MOUNTS=()
    SANDBOX_INFO_COPIES=()

    if load_sandbox_metadata "$name"; then
        SANDBOX_INFO_REPO="$SANDBOX_REPO_URL"
        SANDBOX_INFO_BRANCH="$SANDBOX_BRANCH"
        SANDBOX_INFO_FROM_BRANCH="$SANDBOX_FROM_BRANCH"
        SANDBOX_INFO_MOUNTS=("${SANDBOX_MOUNTS[@]}")
        SANDBOX_INFO_COPIES=("${SANDBOX_COPIES[@]}")
    fi
}

sandbox_info_json() {
    local name="$1"
    collect_sandbox_info "$name"

    local repo
    repo=$(json_escape "$SANDBOX_INFO_REPO")
    local branch
    branch=$(json_escape "$SANDBOX_INFO_BRANCH")
    local from_branch
    from_branch=$(json_escape "$SANDBOX_INFO_FROM_BRANCH")
    local worktree
    worktree=$(json_escape "$SANDBOX_INFO_WORKTREE")
    local config
    config=$(json_escape "$SANDBOX_INFO_CONFIG")
    local container
    container=$(json_escape "$SANDBOX_INFO_CONTAINER_ID")
    local docker_status
    docker_status=$(json_escape "$SANDBOX_INFO_DOCKER_STATUS")
    local tmux
    tmux=$(json_escape "$SANDBOX_INFO_TMUX")

    local mounts_json="[]"
    if [ ${#SANDBOX_INFO_MOUNTS[@]} -gt 0 ]; then
        mounts_json="["
        local first=true
        for mount in "${SANDBOX_INFO_MOUNTS[@]}"; do
            local mount_escaped
            mount_escaped=$(json_escape "$mount")
            if [ "$first" = true ]; then
                first=false
                mounts_json+="\"$mount_escaped\""
            else
                mounts_json+=",\"$mount_escaped\""
            fi
        done
        mounts_json+="]"
    fi

    local copies_json="[]"
    if [ ${#SANDBOX_INFO_COPIES[@]} -gt 0 ]; then
        copies_json="["
        local first_copy=true
        for copy in "${SANDBOX_INFO_COPIES[@]}"; do
            local copy_escaped
            copy_escaped=$(json_escape "$copy")
            if [ "$first_copy" = true ]; then
                first_copy=false
                copies_json+="\"$copy_escaped\""
            else
                copies_json+=",\"$copy_escaped\""
            fi
        done
        copies_json+="]"
    fi

    printf '{"name":"%s","worktree":"%s","worktree_exists":%s,' "$SANDBOX_INFO_NAME" "$worktree" "$SANDBOX_INFO_WORKTREE_EXISTS"
    printf '"claude_config":"%s","claude_config_exists":%s,' "$config" "$SANDBOX_INFO_CONFIG_EXISTS"
    printf '"container":"%s","docker_status":"%s","tmux":"%s",' "$container" "$docker_status" "$tmux"
    printf '"repo":"%s","branch":"%s","from_branch":"%s",' "$repo" "$branch" "$from_branch"
    printf '"mounts":%s,"copies":%s}' "$mounts_json" "$copies_json"
}

sandbox_info_text_summary() {
    local name="$1"
    collect_sandbox_info "$name"
    local tmux_suffix=""
    if [ "$SANDBOX_INFO_TMUX" = "attached" ]; then
        tmux_suffix=" [tmux]"
    fi
    format_table_row "$name" "$SANDBOX_INFO_DOCKER_STATUS" "$tmux_suffix"
}
