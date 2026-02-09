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

# Section header with arrow (bold)
log_section() {
    echo ""
    echo -e "\033[1m▸ $1\033[0m"
}

# Indented step message (2 spaces)
log_step() {
    echo "  $*"
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

# Check if gum is available for TUI components
has_gum() {
    command -v gum &>/dev/null
}

detect_host_timezone() {
    if [ -f /etc/timezone ]; then
        local tz
        tz=$(tr -d ' \t\n' < /etc/timezone 2>/dev/null || true)
        if [ -n "$tz" ]; then
            echo "$tz"
            return 0
        fi
    fi

    local link=""
    link=$(readlink /etc/localtime 2>/dev/null || true)
    if [ -n "$link" ]; then
        case "$link" in
            */zoneinfo/*)
                local tz
                tz="${link#*zoneinfo/}"
                if [ -n "$tz" ]; then
                    echo "$tz"
                    return 0
                fi
                ;;
        esac
    fi

    return 1
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

# Check if a sandbox exists (has metadata or worktree)
sandbox_exists() {
    local name="$1"
    local metadata_path worktree_dir
    metadata_path=$(path_metadata_file "$name")
    worktree_dir=$(path_worktree "$name")

    [ -f "$metadata_path" ] || dir_exists "$worktree_dir"
}

# Find next available sandbox name (appends -2, -3, etc. if base exists)
find_next_sandbox_name() {
    local base_name="$1"
    local candidate="$base_name"
    local counter=2

    while sandbox_exists "$candidate"; do
        candidate="${base_name}-${counter}"
        ((counter++))
    done

    echo "$candidate"
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

# Compute SHA-256 hash in a cross-platform way.
# Reads input from stdin and prints lowercase hex digest.
portable_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
        return 0
    fi

    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
        return 0
    fi

    if command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 -hex | awk '{print $NF}'
        return 0
    fi

    return 1
}

# Generate a short, stable-format sandbox identifier for git shadow auth.
generate_sandbox_id() {
    local seed="$1"
    local digest

    digest=$(printf '%s' "$seed" | portable_sha256 2>/dev/null) || return 1
    printf '%s\n' "${digest}" | cut -c1-16
}

# ---------------------------------------------------------------------------
# Dependency guards & bridge helper (callsite-scoped, no global preamble)
# ---------------------------------------------------------------------------

# Check that python3 is available and >= 3.10.
# Usage: require_python3
require_python3() {
    if ! command -v python3 >/dev/null 2>&1; then
        log_error "python3 is required but not found. Please install Python 3.10+."
        return 1
    fi

    local version
    version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null) || {
        log_error "Failed to determine Python version."
        return 1
    }

    local major minor
    major="${version%%.*}"
    minor="${version#*.}"

    if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 10 ]; }; then
        log_error "Python >= 3.10 required, found $version."
        return 1
    fi
}

# Check that a Python module is importable.
# Usage: require_python_module <module_name>
require_python_module() {
    local module="$1"
    if [ -z "$module" ]; then
        log_error "require_python_module: module name required"
        return 1
    fi

    if ! python3 -c "import $module" >/dev/null 2>&1; then
        log_error "Python module '$module' is not installed."
        log_error "Install with:  pip install $module"
        log_error "  or (editable):  pip install -e ."
        return 1
    fi
}

# Check that jq is available.
# Usage: require_jq
require_jq() {
    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq is required but not found."
        log_error "Install with:  apt-get install jq  (Debian/Ubuntu)"
        log_error "           or: brew install jq      (macOS)"
        return 1
    fi
}

# Call a Python bridge module and parse the JSON envelope.
#
# Usage: _bridge_call <module> <command> [args...]
# On success: sets BRIDGE_RESULT to the JSON-encoded "result" field.
# On failure: logs error to stderr, returns non-zero.
#
# Envelope format (from foundry_sandbox/_bridge.py):
#   Success: {"ok": true,  "result": <value>, "error": null}
#   Error:   {"ok": false, "result": null,     "error": {"code": "...", "message": "..."}}
#
# Exit codes from Python:
#   0  – success envelope
#   1  – known error envelope
#   2+ – crash (no valid JSON on stdout)
_bridge_call() {
    local module="$1" command="$2"
    shift 2

    BRIDGE_RESULT=""

    local output rc=0
    output=$(python3 -m "$module" "$command" "$@" 2>/dev/null) || rc=$?

    # Crash: non-zero exit with no usable output
    if [ $rc -ge 2 ]; then
        log_error "Bridge crash (exit $rc) calling $module $command"
        if [ "$SANDBOX_DEBUG" = "1" ]; then
            # Re-run to capture stderr for debugging
            python3 -m "$module" "$command" "$@" >/dev/null || true
        fi
        return 1
    fi

    # Empty output
    if [ -z "$output" ]; then
        log_error "Bridge returned empty output for $module $command"
        return 1
    fi

    # Parse envelope
    local ok
    ok=$(printf '%s' "$output" | jq -r '.ok // empty' 2>/dev/null) || {
        log_error "Bridge returned invalid JSON for $module $command"
        return 1
    }

    if [ "$ok" = "true" ]; then
        BRIDGE_RESULT=$(printf '%s' "$output" | jq -c '.result')
        return 0
    fi

    # Error envelope
    local err_code err_msg
    err_code=$(printf '%s' "$output" | jq -r '.error.code // "unknown"')
    err_msg=$(printf '%s' "$output" | jq -r '.error.message // "no details"')
    log_error "Bridge error ($err_code): $err_msg"
    return 1
}
