#!/bin/bash

configure_sparse_checkout() {
    local bare_path="$1"
    local worktree_path="$2"
    local working_dir="$3"

    # Get the gitdir for this worktree from the .git file
    # (created by git worktree add, even with --no-checkout)
    local gitdir
    gitdir=$(sed 's/gitdir: //' "$worktree_path/.git")

    # Enable per-worktree config at bare repo level
    git -C "$bare_path" config extensions.worktreeConfig true

    # Enable sparse checkout in worktree config (write directly to avoid "not a work tree" error)
    # Use cone mode which properly handles nested directories and always includes root files
    git config --file "$gitdir/config.worktree" core.sparseCheckout true
    git config --file "$gitdir/config.worktree" core.sparseCheckoutCone true

    # Write sparse-checkout patterns for cone mode
    # Cone mode format: just list directory paths, root files are always included
    mkdir -p "$gitdir/info"
    cat > "$gitdir/info/sparse-checkout" << EOF
.github
$working_dir
EOF

    log_warn "Sparse checkout enabled. Only files in '$working_dir' and root configs are available."
    log_warn "Use 'git sparse-checkout add <path>' inside the container to add more paths."
}

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
    local sparse_checkout="${5:-0}"
    local working_dir="${6:-}"

    # Prune stale worktree registrations (e.g., from destroyed sandboxes)
    git -C "$bare_path" worktree prune 2>/dev/null || true

    if [ ! -d "$worktree_path" ]; then
        if [ -n "$from_branch" ]; then
            git_with_retry -C "$bare_path" fetch origin "$from_branch:$from_branch" 2>/dev/null || true
            # Check if branch already exists (e.g., from a previous destroyed sandbox)
            if git -C "$bare_path" show-ref --verify --quiet "refs/heads/$branch"; then
                log_info "Using existing branch '$branch'..."
                # For sparse checkout: create worktree without checking out files
                if [ "$sparse_checkout" = "1" ] && [ -n "$working_dir" ]; then
                    git -C "$bare_path" worktree add --no-checkout "$worktree_path" "$branch"
                    configure_sparse_checkout "$bare_path" "$worktree_path" "$working_dir"
                    git -C "$worktree_path" checkout
                else
                    git -C "$bare_path" worktree add "$worktree_path" "$branch"
                fi
            else
                log_info "Creating new branch '$branch' from '$from_branch'..."
                # For sparse checkout: create worktree without checking out files
                if [ "$sparse_checkout" = "1" ] && [ -n "$working_dir" ]; then
                    git -C "$bare_path" worktree add --no-checkout -b "$branch" "$worktree_path" "$from_branch"
                    configure_sparse_checkout "$bare_path" "$worktree_path" "$working_dir"
                    git -C "$worktree_path" checkout
                else
                    git -C "$bare_path" worktree add -b "$branch" "$worktree_path" "$from_branch"
                fi
            fi
        else
            log_info "Creating worktree for branch: $branch..."
            # For sparse checkout: create worktree without checking out files
            if [ "$sparse_checkout" = "1" ] && [ -n "$working_dir" ]; then
                if ! git -C "$bare_path" worktree add --no-checkout "$worktree_path" "$branch" 2>/dev/null; then
                    log_info "Branch not found locally, fetching..."
                    git_with_retry -C "$bare_path" fetch origin "$branch:$branch" 2>/dev/null || \
                    git_with_retry -C "$bare_path" fetch origin "refs/heads/$branch:refs/heads/$branch"
                    git -C "$bare_path" worktree add --no-checkout "$worktree_path" "$branch"
                fi
                configure_sparse_checkout "$bare_path" "$worktree_path" "$working_dir"
                git -C "$worktree_path" checkout
            else
                if ! git -C "$bare_path" worktree add "$worktree_path" "$branch" 2>/dev/null; then
                    log_info "Branch not found locally, fetching..."
                    git_with_retry -C "$bare_path" fetch origin "$branch:$branch" 2>/dev/null || \
                    git_with_retry -C "$bare_path" fetch origin "refs/heads/$branch:refs/heads/$branch"
                    git -C "$bare_path" worktree add "$worktree_path" "$branch"
                fi
            fi
        fi
    else
        log_info "Worktree already exists at $worktree_path"
        log_info "Pulling latest changes..."
        if worktree_has_changes "$worktree_path"; then
            log_warn "Uncommitted changes detected. Skipping pull."
        else
            git_with_retry -C "$worktree_path" pull --ff-only || log_warn "Could not fast-forward. You may need to pull manually."
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
