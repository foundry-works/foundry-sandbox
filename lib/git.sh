#!/bin/bash

ensure_bare_repo() {
    local repo_url="$1"
    local bare_path="$2"

    if [ ! -d "$bare_path" ]; then
        log_info "Cloning bare repo to $bare_path..."
        mkdir -p "$(dirname "$bare_path")"
        git clone --bare "$repo_url" "$bare_path"
    else
        log_info "Bare repo exists, fetching latest..."
        git -C "$bare_path" fetch --all --prune
    fi
}

ensure_repo_checkout() {
    local repo_url="$1"
    local checkout_path="$2"
    local branch="${3:-main}"

    if [ -z "$repo_url" ] || [ -z "$checkout_path" ]; then
        return 1
    fi

    ensure_dir "$(dirname "$checkout_path")"

    if [ ! -d "$checkout_path/.git" ]; then
        if [ -e "$checkout_path" ]; then
            log_warn "Path exists but is not a git repo: $checkout_path"
            return 1
        fi
        log_info "Cloning $repo_url to $checkout_path..."
        git clone --branch "$branch" "$repo_url" "$checkout_path" || return 1
        return 0
    fi

    if git -C "$checkout_path" diff --quiet && git -C "$checkout_path" diff --cached --quiet; then
        log_info "Updating $repo_url in $checkout_path..."
        git -C "$checkout_path" fetch origin --prune || return 1
        if ! git -C "$checkout_path" checkout "$branch" >/dev/null 2>&1; then
            git -C "$checkout_path" checkout -b "$branch" "origin/$branch" >/dev/null 2>&1 || return 1
        fi
        git -C "$checkout_path" pull --ff-only origin "$branch" || log_warn "Could not fast-forward $checkout_path"
    else
        log_warn "Uncommitted changes in $checkout_path; skipping pull."
    fi
}

branch_exists() {
    local bare_path="$1"
    local branch="$2"
    git -C "$bare_path" show-ref --verify --quiet "refs/heads/$branch"
}

 
