#!/bin/bash

worktree_has_changes() {
    local worktree_path="$1"
    if git -C "$worktree_path" diff --quiet && git -C "$worktree_path" diff --cached --quiet; then
        return 1
    fi
    return 0
}

create_worktree() {
    local bare_path="$1"
    local worktree_path="$2"
    local branch="$3"
    local from_branch="$4"

    if [ ! -d "$worktree_path" ]; then
        if [ -n "$from_branch" ]; then
            log_info "Creating new branch '$branch' from '$from_branch'..."
            git -C "$bare_path" fetch origin "$from_branch:$from_branch" 2>/dev/null || true
            git -C "$bare_path" worktree add -b "$branch" "$worktree_path" "$from_branch"
        else
            log_info "Creating worktree for branch: $branch..."
            if ! git -C "$bare_path" worktree add "$worktree_path" "$branch" 2>/dev/null; then
                log_info "Branch not found locally, fetching..."
                git -C "$bare_path" fetch origin "$branch:$branch" 2>/dev/null || \
                git -C "$bare_path" fetch origin "refs/heads/$branch:refs/heads/$branch"
                git -C "$bare_path" worktree add "$worktree_path" "$branch"
            fi
        fi
    else
        log_info "Worktree already exists at $worktree_path"
        log_info "Pulling latest changes..."
        if worktree_has_changes "$worktree_path"; then
            log_warn "Uncommitted changes detected. Skipping pull."
        else
            git -C "$worktree_path" pull --ff-only || log_warn "Could not fast-forward. You may need to pull manually."
        fi
    fi
}

remove_worktree() {
    local worktree_path="$1"
    if [ -d "$worktree_path" ]; then
        local git_dir
        git_dir=$(git -C "$worktree_path" rev-parse --git-dir 2>/dev/null)
        if [ -n "$git_dir" ]; then
            local bare_path
            bare_path=$(dirname "$(dirname "$git_dir")")
            git -C "$bare_path" worktree remove "$worktree_path" --force 2>/dev/null || rm -rf "$worktree_path"
        else
            rm -rf "$worktree_path"
        fi
    fi
}
