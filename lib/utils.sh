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

is_macos() {
    [[ "$OSTYPE" == "darwin"* ]]
}

resolve_ssh_agent_sock() {
    if [ "${SANDBOX_SYNC_SSH:-0}" != "1" ]; then
        return 1
    fi

    if [ -n "${SANDBOX_SSH_AUTH_SOCK:-}" ]; then
        echo "$SANDBOX_SSH_AUTH_SOCK"
        return 0
    fi

    if [ -z "${SSH_AUTH_SOCK:-}" ]; then
        return 1
    fi

    if [ -S "$SSH_AUTH_SOCK" ]; then
        echo "$SSH_AUTH_SOCK"
        return 0
    fi

    return 1
}

# Convert repo URL to bare clone path
# e.g., https://github.com/user/repo -> ~/.sandboxes/repos/github.com/user/repo.git
repo_to_path() {
    local url="$1"
    if [ -z "$url" ]; then
        echo "$REPOS_DIR/unknown.git"
        return
    fi

    # Local filesystem path (absolute or relative)
    case "$url" in
        ~/*|/*|./*|../*)
            local expanded="$url"
            if [[ "$expanded" == "~/"* ]]; then
                expanded="${expanded/#\~/$HOME}"
            fi
            local abs="$expanded"
            if [ -d "$expanded" ] || [ -f "$expanded" ]; then
                abs=$(cd "$expanded" 2>/dev/null && pwd) || abs="$expanded"
            fi
            abs="${abs#/}"
            echo "$REPOS_DIR/local/${abs}.git"
            return
            ;;
    esac

    local path="${url#https://}"
    path="${path#git@}"
    path="${path/://}"
    path="${path%.git}"
    echo "$REPOS_DIR/${path}.git"
}

# Sanitize a single git ref path component for generated branch names.
sanitize_ref_component() {
    local raw="$1"
    local safe

    safe=$(printf "%s" "$raw" | sed -E 's/[^A-Za-z0-9._-]+/-/g; s/^[._-]+//; s/[._-]+$//')
    while [[ "$safe" == *..* ]]; do
        safe="${safe//../-}"
    done
    if [[ "$safe" == *.lock ]]; then
        safe="${safe%.lock}-lock"
    fi
    echo "$safe"
}

# Get sandbox name from repo and branch
sandbox_name() {
    local repo_path="$1"
    local branch="$2"
    local safe_branch="${branch//\//-}"
    echo "${safe_branch}"
}

# Get container name
container_name() {
    echo "sandbox-$1"
}

export_docker_env() {
    export DOCKER_UID
    export DOCKER_GID
    DOCKER_UID=$(id -u)
    DOCKER_GID=$(id -g)
}
