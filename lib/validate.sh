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

# Array of dangerous mount paths that should not be mounted into containers
declare -a DANGEROUS_PATHS=(
    "$HOME/.ssh"
    "$HOME/.aws"
    "$HOME/.config/gcloud"
    "$HOME/.config/gh"
    "$HOME/.azure"
    "$HOME/.netrc"
    "$HOME/.kube"
    "$HOME/.gnupg"
    "$HOME/.docker"
    "$HOME/.npmrc"
    "$HOME/.pypirc"
    "/var/run/docker.sock"
    "/run/docker.sock"
)

# Helper function to check if a path is dangerous
# Returns 0 (true) if path is dangerous, 1 (false) if safe
# Sets MATCHED_DANGEROUS_PATH to the dangerous path that was matched
is_dangerous_mount_path() {
    local path="$1"
    local resolved_path

    # Try to resolve the real path (following symlinks and making path canonical)
    # Use -m flag to allow paths that don't exist yet
    if command -v realpath >/dev/null 2>&1; then
        resolved_path=$(realpath -m "$path" 2>/dev/null) || resolved_path="$path"
    else
        resolved_path="$path"
    fi

    # Check against each dangerous path
    for dangerous in "${DANGEROUS_PATHS[@]}"; do
        # Check for exact match
        if [ "$path" = "$dangerous" ] || [ "$resolved_path" = "$dangerous" ]; then
            MATCHED_DANGEROUS_PATH="$dangerous"
            return 0
        fi

        # Check if path is under a dangerous directory (subdirectory check)
        if [[ "$path" == "$dangerous"/* ]] || [[ "$resolved_path" == "$dangerous"/* ]]; then
            MATCHED_DANGEROUS_PATH="$dangerous"
            return 0
        fi
    done

    return 1
}

# Validate that a mount path is not dangerous
# Dies with error if path is dangerous
validate_mount_path() {
    local path="$1"
    [ -n "$path" ] || die "Mount path required"

    if is_dangerous_mount_path "$path"; then
        die "Cannot mount dangerous path: $path (matches: $MATCHED_DANGEROUS_PATH, use --allow-dangerous-mount to override)"
    fi
}
