#!/bin/bash

# Array of dangerous paths that should be validated during credential isolation
DANGEROUS_PATHS=(
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

validate_mount_path() {
    local mount_path="$1"
    local canonical_path
    canonical_path=$(realpath -m "$mount_path" 2>/dev/null) || canonical_path="$mount_path"

    for dangerous in "${DANGEROUS_PATHS[@]}"; do
        local dangerous_canonical
        dangerous_canonical=$(realpath -m "$dangerous" 2>/dev/null) || dangerous_canonical="$dangerous"

        # Check exact match
        if [[ "$canonical_path" == "$dangerous_canonical" ]]; then
            echo "Error: Mount path '$mount_path' is a dangerous credential path: $dangerous"
            return 1
        fi

        # Check if mount is parent of dangerous (would expose credentials)
        if [[ "$dangerous_canonical" == "$canonical_path"/* ]]; then
            echo "Error: Mount path '$mount_path' would expose credential directory: $dangerous"
            return 1
        fi

        # Check if mount is child of dangerous (inside credentials)
        if [[ "$canonical_path" == "$dangerous_canonical"/* ]]; then
            echo "Error: Mount path '$mount_path' is inside credential directory: $dangerous"
            return 1
        fi
    done

    return 0
}

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

# Detect embedded credentials in git remote URLs
# Pattern matches: ://user:password@ format (credentials in URL)
# Returns: 0 if no embedded credentials, 1 if found
validate_git_remotes() {
    local git_dir="${1:-.git}"
    local config_file="$git_dir/config"

    if [ ! -f "$config_file" ]; then
        # No git config - nothing to validate
        return 0
    fi

    # Pattern: ://[^:]+:[^@]+@ matches "://user:password@" in URLs
    # This catches embedded credentials in remote URLs like:
    #   https://user:token@github.com/...
    #   git://user:pass@host/...
    local credential_pattern='://[^:]+:[^@]+@'

    # Search for embedded credentials in remote URLs
    if grep -qE "$credential_pattern" "$config_file" 2>/dev/null; then
        # Find the offending line(s) for clearer error message
        local offending_lines
        offending_lines=$(grep -E "$credential_pattern" "$config_file" 2>/dev/null | head -3)

        log_error "Embedded credentials detected in git config: $config_file"
        log_error "Remote URLs must not contain credentials (user:pass@)"
        log_error "Offending lines:"
        echo "$offending_lines" | while read -r line; do
            # Redact the actual password from the error message
            local redacted
            redacted=$(echo "$line" | sed -E 's#(://[^:]+:)[^@]+(@)#\1***\2#g')
            log_error "  $redacted"
        done
        log_error "Remove credentials from git remote URLs before enabling credential isolation"
        return 1
    fi

    return 0
}
