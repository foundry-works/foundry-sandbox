#!/bin/bash

log_info() {
    echo "$@"
}

log_debug() {
    if [ "$SANDBOX_DEBUG" = "1" ]; then
        echo "DEBUG: $*"
    fi
}

log_warn() {
    echo "Warning: $*" >&2
}

log_error() {
    echo "Error: $*" >&2
}

# Cross-platform sed in-place edit (GNU vs BSD)
sed_inplace() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# Convert repo URL to bare clone path
# e.g., https://github.com/user/repo -> ~/.sandboxes/repos/github.com/user/repo.git
repo_to_path() {
    local url="$1"
    local path="${url#https://}"
    path="${path#git@}"
    path="${path/://}"
    path="${path%.git}"
    echo "$REPOS_DIR/${path}.git"
}

# Get sandbox name from repo and branch
sandbox_name() {
    local repo_path="$1"
    local branch="$2"
    local repo_name
    repo_name=$(basename "$repo_path" .git)
    local safe_branch="${branch//\//-}"
    echo "${repo_name}-${safe_branch}"
}

# Get container name
container_name() {
    echo "sandbox-$1"
}

export_docker_env() {
    export DOCKER_UID
    export DOCKER_GID
    export HOST_USER
    DOCKER_UID=$(id -u)
    DOCKER_GID=$(id -g)
    HOST_USER=$(whoami)
}
