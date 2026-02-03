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

# Cross-platform realpath that works on both GNU (Linux) and BSD (macOS)
# Tries GNU realpath options first, falls back to basic realpath or python3
_realpath_canonical() {
    local path="$1"
    local must_exist="${2:-false}"

    # Try GNU realpath -e (path must exist) or -m (no existence required)
    if [ "$must_exist" = "true" ]; then
        realpath -e "$path" 2>/dev/null && return 0
    else
        realpath -m "$path" 2>/dev/null && return 0
    fi

    # Try basic realpath (works on macOS for existing paths)
    realpath "$path" 2>/dev/null && return 0

    # Fallback to python3 for non-existent paths on macOS
    python3 -c "import os; print(os.path.abspath('$path'))" 2>/dev/null && return 0

    # Last resort: return the path as-is
    echo "$path"
}

validate_mount_path() {
    local mount_path="$1"
    local canonical_path

    # Resolve the canonical path, preferring existing paths for security
    # This prevents TOCTOU race conditions where an attacker could swap
    # a symlink target between validation and mount
    canonical_path=$(_realpath_canonical "$mount_path" true)
    if [ -z "$canonical_path" ]; then
        # Path doesn't exist yet - resolve without existence requirement
        canonical_path=$(_realpath_canonical "$mount_path" false)
    fi

    for dangerous in "${DANGEROUS_PATHS[@]}"; do
        local dangerous_canonical
        # Dangerous paths should typically exist
        dangerous_canonical=$(_realpath_canonical "$dangerous" true)
        if [ -z "$dangerous_canonical" ]; then
            dangerous_canonical=$(_realpath_canonical "$dangerous" false)
        fi

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

check_docker_network_capacity() {
    local isolate_credentials="${1:-true}"

    # Only check if credential isolation is enabled (creates networks)
    if [ "$isolate_credentials" != "true" ]; then
        return 0
    fi

    # Count existing sandbox networks as a warning indicator
    local sandbox_network_count
    sandbox_network_count=$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -cE '^sandbox-' || true)
    sandbox_network_count="${sandbox_network_count:-0}"

    # Try to create a test network to verify capacity
    local test_network_name="sandbox-network-capacity-test-$$"

    if ! docker network create "$test_network_name" >/dev/null 2>&1; then
        log_error "Docker network address pool exhausted"
        log_error ""
        log_error "Docker cannot create new networks. This typically happens when:"
        log_error "  - Many sandboxes have been created without cleanup"
        log_error "  - Orphaned networks remain from destroyed sandboxes"
        log_error ""
        log_error "Current sandbox networks: $sandbox_network_count"
        log_error ""
        log_error "Remediation steps:"
        log_error "  1. Clean up orphaned sandbox networks:"
        log_error "     cast prune --networks"
        log_error ""
        log_error "  2. If that doesn't help, remove ALL unused Docker networks:"
        log_error "     docker network prune"
        log_error ""
        log_error "  3. If problems persist, restart Docker Desktop"
        return 1
    fi

    # Clean up test network
    docker network rm "$test_network_name" >/dev/null 2>&1 || true

    # Warn if many sandbox networks exist (potential future issue)
    if [ "$sandbox_network_count" -gt 20 ]; then
        # Count orphaned networks (no running containers)
        local orphaned_count=0
        while IFS= read -r net; do
            [ -z "$net" ] && continue
            local sandbox_name="${net%_credential-isolation}"
            sandbox_name="${sandbox_name%_proxy-egress}"
            if ! docker ps -q --filter "name=^${sandbox_name}-" 2>/dev/null | grep -q .; then
                ((orphaned_count++))
            fi
        done < <(docker network ls --format '{{.Name}}' | grep -E '^sandbox-')

        if [ "$orphaned_count" -gt 0 ]; then
            log_warn "Found $orphaned_count orphaned sandbox networks (of $sandbox_network_count total)"
            log_warn "Run 'cast prune --networks' to clean up"
        else
            log_warn "Found $sandbox_network_count active sandbox networks"
            log_warn "Consider destroying unused sandboxes with 'cast destroy <name>'"
        fi
    fi

    return 0
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
# Pattern matches: ://user:password@host format (credentials in URL)
# Returns: 0 if no embedded credentials, 1 if found
validate_git_remotes() {
    local git_dir="${1:-.git}"
    local config_file="$git_dir/config"

    if [ ! -f "$config_file" ]; then
        # No git config - nothing to validate
        return 0
    fi

    # Pattern: ://[^/:@]+:[^/:@]+@[^/]+ matches "://user:password@host" in URLs
    # More specific pattern that requires:
    #   - :// protocol prefix
    #   - username (no :, /, or @)
    #   - : separator
    #   - password (no :, /, or @)
    #   - @ separator
    #   - hostname (at least one char before /)
    # This avoids false positives like http://host:port/path@something
    local credential_pattern='://[^/:@]+:[^/:@]+@[^/]+'

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
