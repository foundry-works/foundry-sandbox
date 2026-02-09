#!/bin/bash
# Shell bridge wrappers for foundry_sandbox.git_worktree Python module.
# Original logic replaced by _bridge_call delegates per dual-implementation policy.

configure_sparse_checkout() {
    local bare_path="$1"
    local worktree_path="$2"
    local working_dir="$3"

    _bridge_call foundry_sandbox.git_worktree configure-sparse-checkout "$bare_path" "$worktree_path" "$working_dir" || return 1
}

worktree_has_changes() {
    local worktree_path="$1"

    _bridge_call foundry_sandbox.git_worktree worktree-has-changes "$worktree_path" || return 1
    [ "$BRIDGE_RESULT" = "true" ]
}

create_worktree() {
    local bare_path="$1"
    local worktree_path="$2"
    local branch="$3"
    local from_branch="${4:-}"
    local sparse_checkout="${5:-0}"
    local working_dir="${6:-}"

    _bridge_call foundry_sandbox.git_worktree create-worktree "$bare_path" "$worktree_path" "$branch" "$from_branch" "$sparse_checkout" "$working_dir" || return 1
}

cleanup_sandbox_branch() {
    local branch="$1"
    local repo_url="$2"

    # Early return if branch or repo_url empty
    [ -z "$branch" ] && return 0
    [ -z "$repo_url" ] && return 0

    # Resolve repo_url to bare_path before delegating to Python
    local bare_path
    bare_path=$(repo_to_path "$repo_url")

    _bridge_call foundry_sandbox.git_worktree cleanup-sandbox-branch "$branch" "$bare_path" || return 1
}

remove_worktree() {
    local worktree_path="$1"

    _bridge_call foundry_sandbox.git_worktree remove-worktree "$worktree_path" || return 1
}
