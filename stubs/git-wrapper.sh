#!/bin/bash
# Git wrapper for sandbox environment.
#
# Installed at /usr/local/bin/git (takes precedence over /usr/bin/git).
# Proxies git commands through the authenticated git API endpoint when
# operating inside /workspace. Falls through to /usr/bin/git for all
# other paths.
#
# Security:
# - JSON constructed via jq or python3 (never shell string interpolation)
# - HMAC-SHA256 signature on every request
# - Secret read from mounted file (not env var)
# - Signal handling with proper exit codes
# - 30s timeout on proxy requests

set -euo pipefail

# ---------------------------------------------------------------------------
# Dependency Check
# ---------------------------------------------------------------------------

# python3 is required for HMAC-SHA256 computation (no fallback by design,
# to keep the secret entirely in-process memory and avoid /proc leakage).
if ! command -v python3 >/dev/null 2>&1; then
    echo "error: git wrapper: python3 is required but not found in PATH" >&2
    echo "hint: install python3 (e.g., apt-get install python3) to enable git operations through the sandbox proxy" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REAL_GIT="/usr/bin/git"
GIT_API_HOST="${GIT_API_HOST:-unified-proxy}"
GIT_API_PORT="${GIT_API_PORT:-8083}"
GIT_API_URL="http://${GIT_API_HOST}:${GIT_API_PORT}/git/exec"
SANDBOX_ID="${SANDBOX_ID:-}"
HMAC_SECRETS_DIR="${GIT_HMAC_SECRETS_DIR:-/run/secrets/sandbox-hmac}"
HMAC_SECRET_FILE="${GIT_HMAC_SECRET_FILE:-${HMAC_SECRETS_DIR}/${SANDBOX_ID}}"
PROXY_TIMEOUT=30

# ---------------------------------------------------------------------------
# Signal handling: exit with 128 + signal_number
# ---------------------------------------------------------------------------

cleanup() {
    local sig="$1"
    # Kill any background curl process
    if [[ -n "${CURL_PID:-}" ]]; then
        kill "$CURL_PID" 2>/dev/null || true
    fi
    exit $((128 + sig))
}

trap 'cleanup 2' INT
trap 'cleanup 15' TERM

# ---------------------------------------------------------------------------
# Path resolution: determine working directory
# ---------------------------------------------------------------------------

resolve_cwd() {
    local cwd="$PWD"

    # Check for -C <dir> flag (must be before subcommand)
    local i=0
    local args=("$@")
    while [[ $i -lt ${#args[@]} ]]; do
        case "${args[$i]}" in
            -C)
                if [[ $((i + 1)) -lt ${#args[@]} ]]; then
                    cwd="${args[$((i + 1))]}"
                fi
                break
                ;;
            -C*)
                # -C<dir> without space
                cwd="${args[$i]#-C}"
                break
                ;;
            --)
                break
                ;;
            -*)
                # Skip other flags; some take values
                ;;
            *)
                # Reached subcommand, stop scanning
                break
                ;;
        esac
        ((i++))
    done

    # Canonicalize with symlink resolution
    local canonical
    canonical=$(realpath -m "$cwd" 2>/dev/null) || true

    if [[ -z "$canonical" ]]; then
        echo "error: git wrapper: cannot resolve path '$cwd'" >&2
        exit 1
    fi

    echo "$canonical"
}

# ---------------------------------------------------------------------------
# Check if path is under /workspace
# ---------------------------------------------------------------------------

is_workspace_path() {
    local path="$1"
    [[ "$path" == "/workspace" || "$path" == /workspace/* ]]
}

# ---------------------------------------------------------------------------
# Sandbox identity discovery for restart resilience
# ---------------------------------------------------------------------------

discover_sandbox_identity() {
    # Fast path: explicit identity with matching secret file.
    if [[ -n "$SANDBOX_ID" && -f "$HMAC_SECRET_FILE" ]]; then
        return 0
    fi

    if [[ ! -d "$HMAC_SECRETS_DIR" ]]; then
        return 1
    fi

    local candidates=()
    local secret_path=""
    shopt -s nullglob
    for secret_path in "$HMAC_SECRETS_DIR"/*; do
        [[ -f "$secret_path" ]] || continue
        candidates+=("${secret_path##*/}")
    done
    shopt -u nullglob

    # Per-sandbox volume should have exactly one secret file.
    if [[ ${#candidates[@]} -eq 1 ]]; then
        SANDBOX_ID="${candidates[0]}"
        HMAC_SECRET_FILE="${HMAC_SECRETS_DIR}/${SANDBOX_ID}"
        return 0
    fi

    return 1
}

# ---------------------------------------------------------------------------
# Convert canonical workspace path to repo-relative cwd for API requests
# ---------------------------------------------------------------------------

to_request_cwd() {
    local cwd="$1"

    if [[ "$cwd" == "/workspace" ]]; then
        echo "."
        return
    fi

    if [[ "$cwd" == /workspace/* ]]; then
        echo "${cwd#/workspace/}"
        return
    fi

    # Fallback for unexpected inputs (should not happen after workspace check)
    echo "."
}

# ---------------------------------------------------------------------------
# JSON serialization: use jq with null-delimited input, fall back to python3
# ---------------------------------------------------------------------------

serialize_args() {
    local cwd="$1"
    shift

    # Strip null bytes from arguments for safety
    local clean_args=()
    for arg in "$@"; do
        clean_args+=("$(printf '%s' "$arg" | tr -d '\0')")
    done

    # Prefer python3 for JSON safety (handles embedded newlines, all unicode).
    # Fall back to jq with newline-delimited input (cannot handle args with
    # embedded newlines — acceptable since git args rarely contain them).
    if command -v python3 >/dev/null 2>&1; then
        printf '%s\0' "${clean_args[@]}" | \
            python3 -c '
import json, sys
data = sys.stdin.buffer.read()
args = [a.decode("utf-8") for a in data.split(b"\x00") if a]
print(json.dumps({"args": args, "cwd": sys.argv[1]}))
' "$cwd"
    elif command -v jq >/dev/null 2>&1; then
        # Newline-delimited: args with embedded newlines will be split.
        # This is a known limitation — prefer python3 path when available.
        printf '%s\n' "${clean_args[@]}" | \
            jq -Rsc --arg cwd "$cwd" \
            '{args: (split("\n") | map(select(length > 0))), cwd: $cwd}'
    else
        echo "error: git wrapper: neither python3 nor jq available for JSON serialization" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# HMAC-SHA256 signature computation
# ---------------------------------------------------------------------------

compute_hmac() {
    local method="$1"
    local path="$2"
    local body="$3"
    local timestamp="$4"
    local nonce="$5"
    local secret_file="$6"

    # Use python3 for HMAC computation to keep the secret entirely in-process
    # memory. The previous openssl approach leaked the secret via
    # /proc/<pid>/cmdline because it was passed as a command-line argument.
    python3 -c '
import hashlib, hmac, sys

method, path, body, timestamp, nonce, secret_file = sys.argv[1:7]

# Read secret from file
with open(secret_file, "rb") as f:
    secret = f.read().strip()

# SHA-256 of body
body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

# Canonical string: METHOD\nPATH\nSHA256(body)\nTIMESTAMP\nNONCE
canonical = f"{method}\n{path}\n{body_hash}\n{timestamp}\n{nonce}"

# HMAC-SHA256
sig = hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
print(sig)
' "$method" "$path" "$body" "$timestamp" "$nonce" "$secret_file"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Resolve working directory
CWD=$(resolve_cwd "$@")

# If not under /workspace, fall through to real git
if ! is_workspace_path "$CWD"; then
    exec "$REAL_GIT" "$@"
fi

discover_sandbox_identity || true

# Validate sandbox identity and HMAC secret file
if [[ -z "$SANDBOX_ID" ]]; then
    echo "error: git wrapper: SANDBOX_ID not set and could not be discovered" >&2
    exit 1
fi
if [[ ! -f "$HMAC_SECRET_FILE" ]]; then
    echo "error: git wrapper: HMAC secret file not found at $HMAC_SECRET_FILE" >&2
    exit 1
fi
if [[ ! -r "$HMAC_SECRET_FILE" ]]; then
    echo "error: git wrapper: HMAC secret file is not readable at $HMAC_SECRET_FILE" >&2
    exit 1
fi

# Build JSON body with cwd relative to /workspace.
# The git API resolves this relative path against its own repo root mount.
REQUEST_CWD=$(to_request_cwd "$CWD")
BODY=$(serialize_args "$REQUEST_CWD" "$@")
if [[ -z "$BODY" ]]; then
    echo "error: git wrapper: failed to serialize arguments" >&2
    exit 1
fi

# Generate auth headers
TIMESTAMP=$(date +%s)
NONCE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
SIGNATURE=$(compute_hmac "POST" "/git/exec" "$BODY" "$TIMESTAMP" "$NONCE" "$HMAC_SECRET_FILE")

# Send request to git API with timeout
RESPONSE_FILE=$(mktemp)
HTTP_CODE_FILE=$(mktemp)
trap 'rm -f "$RESPONSE_FILE" "$HTTP_CODE_FILE"; cleanup 2' INT
trap 'rm -f "$RESPONSE_FILE" "$HTTP_CODE_FILE"; cleanup 15' TERM

curl -s --max-time "$PROXY_TIMEOUT" --connect-timeout 5 \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-Sandbox-Id: $SANDBOX_ID" \
    -H "X-Request-Timestamp: $TIMESTAMP" \
    -H "X-Request-Nonce: $NONCE" \
    -H "X-Request-Signature: $SIGNATURE" \
    -d "$BODY" \
    -o "$RESPONSE_FILE" \
    -w "%{http_code}" \
    "$GIT_API_URL" > "$HTTP_CODE_FILE" 2>/dev/null &
CURL_PID=$!
wait "$CURL_PID" 2>/dev/null
CURL_EXIT=$?
unset CURL_PID

HTTP_CODE=$(cat "$HTTP_CODE_FILE" 2>/dev/null || echo "000")

# Handle connection failures
if [[ $CURL_EXIT -ne 0 ]] || [[ "$HTTP_CODE" == "000" ]]; then
    rm -f "$RESPONSE_FILE" "$HTTP_CODE_FILE"
    echo "error: git proxy unavailable (connection failed after ${PROXY_TIMEOUT}s)" >&2
    exit 1
fi

RESPONSE=$(cat "$RESPONSE_FILE")
rm -f "$RESPONSE_FILE" "$HTTP_CODE_FILE"

# Handle HTTP errors
case "$HTTP_CODE" in
    200)
        ;;
    401)
        echo "error: git proxy authentication failed" >&2
        exit 1
        ;;
    429)
        RETRY_AFTER=$(echo "$RESPONSE" | jq -r '.retry_after // empty' 2>/dev/null || true)
        if [[ -n "$RETRY_AFTER" ]]; then
            echo "error: git rate limit exceeded. Try again in ${RETRY_AFTER}s." >&2
        else
            echo "error: git rate limit exceeded." >&2
        fi
        exit 1
        ;;
    400)
        ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error // "bad request"' 2>/dev/null || echo "bad request")
        echo "error: $ERROR_MSG" >&2
        exit 1
        ;;
    422)
        ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error // "validation failed"' 2>/dev/null || echo "validation failed")
        echo "error: $ERROR_MSG" >&2
        exit 1
        ;;
    *)
        echo "error: git proxy returned HTTP $HTTP_CODE" >&2
        exit 1
        ;;
esac

# Parse response
EXIT_CODE=$(echo "$RESPONSE" | jq -r '.exit_code // 0' 2>/dev/null || echo 1)
STDOUT=$(echo "$RESPONSE" | jq -r '.stdout // ""' 2>/dev/null || true)
STDERR=$(echo "$RESPONSE" | jq -r '.stderr // ""' 2>/dev/null || true)
STDOUT_B64=$(echo "$RESPONSE" | jq -r '.stdout_b64 // ""' 2>/dev/null || true)

# Fall back to stdout_b64 when stdout is empty
if [[ -z "$STDOUT" && -n "$STDOUT_B64" ]]; then
    STDOUT=$(printf '%s' "$STDOUT_B64" | python3 - <<'PY' 2>/dev/null || true
import base64, sys
data = sys.stdin.read().strip()
try:
    decoded = base64.b64decode(data)
    sys.stdout.write(decoded.decode("utf-8", errors="replace"))
except Exception:
    pass
PY
    )
fi

# Output results
if [[ -n "$STDOUT" ]]; then
    printf '%s\n' "$STDOUT"
fi
if [[ -n "$STDERR" ]]; then
    printf '%s\n' "$STDERR" >&2
fi

exit "$EXIT_CODE"
