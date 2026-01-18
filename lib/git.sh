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

branch_exists() {
    local bare_path="$1"
    local branch="$2"
    git -C "$bare_path" show-ref --verify --quiet "refs/heads/$branch"
}

 
