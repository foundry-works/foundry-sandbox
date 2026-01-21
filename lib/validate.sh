#!/bin/bash

die() {
    log_error "$@"
    exit 1
}

warn() {
    log_warn "$@"
}

try_or_warn() {
    "$@" || warn "Command failed: $*"
}

try_or_die() {
    "$@" || die "Command failed: $*"
}

require_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || die "Missing required command: $cmd"
}

check_docker_running() {
    docker info >/dev/null 2>&1 || die "Docker is not running or not accessible"
}

validate_git_url() {
    local url="$1"
    [ -n "$url" ] || die "Repository URL required"
    if [[ "$url" != http* && "$url" != git@* && "$url" != */* ]]; then
        die "Invalid repository URL: $url"
    fi
}

validate_sandbox_name() {
    local name="$1"
    [ -n "$name" ] || die "Sandbox name required"
}

validate_environment() {
    require_command git
    require_command docker
    ensure_dir "$REPOS_DIR"
    ensure_dir "$WORKTREES_DIR"
    ensure_dir "$CLAUDE_CONFIGS_DIR"
}

validate_ssh_mode() {
    local mode="$1"
    case "$mode" in
        init|always|disabled)
            return 0
            ;;
        *)
            die "Invalid SSH mode: $mode (use: always, disabled)"
            ;;
    esac
}
