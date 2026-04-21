#!/bin/bash
# Git wrapper for foundry-git-safety.
#
# Proxies git commands through the authenticated git API endpoint when
# operating inside the workspace. Falls through to /usr/bin/git for all
# other paths.
#
# Configuration (env vars or .foundry/config in workspace):
#   GIT_API_HOST    - API server hostname (default: host.docker.internal)
#   GIT_API_PORT    - API server port (default: 8083)
#   SBX_PROXY       - HTTP proxy for sandbox egress (default: http://gateway.docker.internal:3128)
#   SANDBOX_ID      - Sandbox identifier (or SANDBOX_VM_ID)
#   WORKSPACE_DIR   - Workspace root directory
#   GIT_HMAC_SECRET_FILE - Path to HMAC secret file

set -euo pipefail

umask 077

# ---------------------------------------------------------------------------
# Dependency Check
# ---------------------------------------------------------------------------

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: git wrapper: python3 is required but not found in PATH" >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "error: git wrapper: curl is required but not found in PATH" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Configuration with auto-discovery
# ---------------------------------------------------------------------------

REAL_GIT="/usr/bin/git"
WORKSPACE_DIR="${WORKSPACE_DIR:-}"

# Auto-discover config from .foundry/config if available
if [[ -z "${GIT_API_HOST:-}" && -n "$WORKSPACE_DIR" && -f "${WORKSPACE_DIR}/.foundry/config" ]]; then
    _raw_host=$(grep -E '^GIT_API_HOST=' "${WORKSPACE_DIR}/.foundry/config" 2>/dev/null | head -1 | cut -d= -f2- || true)
    # Sanitize: only allow hostname chars (alphanumeric, dots, hyphens)
    if [[ "$_raw_host" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        GIT_API_HOST="$_raw_host"
    fi
fi
if [[ -z "${GIT_API_PORT:-}" && -n "$WORKSPACE_DIR" && -f "${WORKSPACE_DIR}/.foundry/config" ]]; then
    _raw_port=$(grep -E '^GIT_API_PORT=' "${WORKSPACE_DIR}/.foundry/config" 2>/dev/null | head -1 | cut -d= -f2- || true)
    # Sanitize: only allow numeric port
    if [[ "$_raw_port" =~ ^[0-9]+$ ]] && (( _raw_port >= 1 && _raw_port <= 65535 )); then
        GIT_API_PORT="$_raw_port"
    fi
fi

GIT_API_HOST="${GIT_API_HOST:-host.docker.internal}"
GIT_API_PORT="${GIT_API_PORT:-8083}"
GIT_API_URL="http://${GIT_API_HOST}:${GIT_API_PORT}/git/exec"
SBX_PROXY="${SBX_PROXY:-http://gateway.docker.internal:3128}"
SANDBOX_ID="${SANDBOX_ID:-}"
HMAC_SECRET_FILE="${GIT_HMAC_SECRET_FILE:-}"
PROXY_TIMEOUT=30

# Discover HMAC secret if not set
if [[ -z "$HMAC_SECRET_FILE" ]]; then
    if [[ -f "/run/foundry/hmac-secret" ]]; then
        HMAC_SECRET_FILE="/run/foundry/hmac-secret"
    fi
fi

# Fallback: discover SANDBOX_ID from VM identity
if [[ -z "$SANDBOX_ID" ]]; then
    SANDBOX_ID="${SANDBOX_VM_ID:-}"
fi

# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

# Track temp files for signal-safe cleanup
_TEMP_FILES=()

cleanup() {
    local sig="$1"
    # Clean up temp files first (safe even if empty or already deleted)
    for f in "${_TEMP_FILES[@]:-}"; do
        rm -f "$f" 2>/dev/null || true
    done
    if [[ -n "${CURL_PID:-}" ]]; then
        kill "$CURL_PID" 2>/dev/null || true
    fi
    exit $((128 + sig))
}

trap 'cleanup 2' INT
trap 'cleanup 15' TERM

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

resolve_cwd() {
    local cwd="$PWD"
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
                cwd="${args[$i]#-C}"
                break
                ;;
        esac
        ((i++))
    done
    echo "$cwd"
}

is_workspace_path() {
    local path="$1"
    if [[ -z "$WORKSPACE_DIR" ]]; then
        return 1
    fi
    [[ "$path" == "$WORKSPACE_DIR" || "$path" == "$WORKSPACE_DIR"/* ]]
}

# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------

serialize_args() {
    local cwd="$1"
    shift

    local clean_args=()
    for arg in "$@"; do
        clean_args+=("$(printf '%s' "$arg" | tr -d '\0')")
    done

    if command -v jq >/dev/null 2>&1; then
        printf '%s\0' "$cwd" "${clean_args[@]}" | jq -Rs '
            split("\u0000") |
            .[:-1] |
            {cwd: .[0], args: .[1:]}
        '
    else
        python3 - "$cwd" "${clean_args[@]}" <<'PY'
import json, sys
cwd = sys.argv[1]
args = sys.argv[2:]
print(json.dumps({"cwd": cwd, "args": args}))
PY
    fi
}

# ---------------------------------------------------------------------------
# HMAC computation
# ---------------------------------------------------------------------------

compute_hmac() {
    local method="$1" path="$2" body="$3" timestamp="$4" nonce="$5" secret_file="$6"

    # Pass body via stdin to avoid exposing it in /proc/<pid>/cmdline
    printf '%s' "$body" | python3 - "$method" "$path" "$timestamp" "$nonce" "$secret_file" <<'PY'
import hashlib, hmac, sys

method = sys.argv[1]
path = sys.argv[2]
timestamp = sys.argv[3]
nonce = sys.argv[4]
secret_file = sys.argv[5]

body = sys.stdin.buffer.read()

with open(secret_file, "rb") as f:
    secret = f.read(4096).rstrip(b"\n")

body_hash = hashlib.sha256(body).hexdigest()
canonical = f"{method}\n{path}\n{body_hash}\n{timestamp}\n{nonce}"
sig = hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
print(sig)
PY
}

# ---------------------------------------------------------------------------
# Convert workspace path to relative cwd
# ---------------------------------------------------------------------------

to_request_cwd() {
    local cwd="$1"
    if [[ -z "$WORKSPACE_DIR" ]]; then
        echo "."
        return
    fi
    if [[ "$cwd" == "$WORKSPACE_DIR" ]]; then
        echo "."
        return
    fi
    if [[ "$cwd" == "$WORKSPACE_DIR"/* ]]; then
        echo "${cwd#"$WORKSPACE_DIR"/}"
        return
    fi
    echo "."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

CWD=$(resolve_cwd "$@")

if ! is_workspace_path "$CWD"; then
    exec "$REAL_GIT" "$@"
fi

if [[ -z "$SANDBOX_ID" ]]; then
    echo "error: git wrapper: SANDBOX_ID not set (set SANDBOX_VM_ID or SANDBOX_ID)" >&2
    exit 1
fi

# Validate SANDBOX_ID to prevent header injection (no newlines, CR, or control chars)
if [[ "$SANDBOX_ID" =~ [[:cntrl:]] ]]; then
    echo "error: git wrapper: SANDBOX_ID contains invalid characters" >&2
    exit 1
fi

if [[ -z "$HMAC_SECRET_FILE" || ! -f "$HMAC_SECRET_FILE" ]]; then
    echo "error: git wrapper: HMAC secret file not found (set GIT_HMAC_SECRET_FILE or check /run/foundry/hmac-secret)" >&2
    exit 1
fi

if [[ ! -r "$HMAC_SECRET_FILE" ]]; then
    echo "error: git wrapper: HMAC secret file is not readable at $HMAC_SECRET_FILE" >&2
    exit 1
fi

REQUEST_CWD=$(to_request_cwd "$CWD")
BODY=$(serialize_args "$REQUEST_CWD" "$@")
if [[ -z "$BODY" ]]; then
    echo "error: git wrapper: failed to serialize arguments" >&2
    exit 1
fi

TIMESTAMP=$(date +%s)
NONCE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
SIGNATURE=$(compute_hmac "POST" "/git/exec" "$BODY" "$TIMESTAMP" "$NONCE" "$HMAC_SECRET_FILE")

RESPONSE_FILE=$(mktemp)
HTTP_CODE_FILE=$(mktemp)
PARSED_EXIT=$(mktemp)
PARSED_STDOUT=$(mktemp)
PARSED_STDERR=$(mktemp)
_TEMP_FILES+=("$RESPONSE_FILE" "$HTTP_CODE_FILE" "$PARSED_EXIT" "$PARSED_STDOUT" "$PARSED_STDERR")

# Use proxy if SBX_PROXY is set, otherwise direct
CURL_PROXY_ARGS=()
if [[ -n "$SBX_PROXY" ]]; then
    CURL_PROXY_ARGS=(--proxy "$SBX_PROXY")
fi

printf '%s' "$BODY" | curl -s --max-time "$PROXY_TIMEOUT" --connect-timeout 5 \
    "${CURL_PROXY_ARGS[@]}" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-Sandbox-Id: $SANDBOX_ID" \
    -H "X-Request-Timestamp: $TIMESTAMP" \
    -H "X-Request-Nonce: $NONCE" \
    -H "X-Request-Signature: $SIGNATURE" \
    --data-binary @- \
    -o "$RESPONSE_FILE" \
    -w "%{http_code}" \
    "$GIT_API_URL" > "$HTTP_CODE_FILE" 2>/dev/null &
CURL_PID=$!
wait "$CURL_PID" 2>/dev/null
CURL_EXIT=$?
unset CURL_PID

HTTP_CODE=$(cat "$HTTP_CODE_FILE" 2>/dev/null || echo "000")

if [[ $CURL_EXIT -ne 0 ]] || [[ "$HTTP_CODE" == "000" ]]; then
    rm -f "$RESPONSE_FILE" "$HTTP_CODE_FILE"
    echo "error: git proxy unavailable (connection failed after ${PROXY_TIMEOUT}s)" >&2
    exit 1
fi

case "$HTTP_CODE" in
    200) ;;
    401)
        rm -f "$RESPONSE_FILE" "$HTTP_CODE_FILE"
        echo "error: git proxy authentication failed" >&2
        exit 1
        ;;
    429)
        RETRY_AFTER=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); v=d.get("retry_after",""); print(v if v else "")' "$RESPONSE_FILE" 2>/dev/null || true)
        if [[ -n "$RETRY_AFTER" ]]; then
            echo "error: git rate limit exceeded. Try again in ${RETRY_AFTER}s." >&2
        else
            echo "error: git rate limit exceeded." >&2
        fi
        rm -f "$RESPONSE_FILE" "$HTTP_CODE_FILE"
        exit 1
        ;;
    400|422)
        ERROR_MSG=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("error","request failed"))' "$RESPONSE_FILE" 2>/dev/null || echo "request failed")
        rm -f "$RESPONSE_FILE" "$HTTP_CODE_FILE"
        echo "error: $ERROR_MSG" >&2
        exit 1
        ;;
    *)
        rm -f "$RESPONSE_FILE" "$HTTP_CODE_FILE"
        echo "error: git proxy returned HTTP $HTTP_CODE" >&2
        exit 1
        ;;
esac

python3 - "$RESPONSE_FILE" "$PARSED_EXIT" "$PARSED_STDOUT" "$PARSED_STDERR" <<'PY'
import base64, json, sys

response_file, exit_file, stdout_file, stderr_file = sys.argv[1:5]
try:
    with open(response_file, "r") as f:
        data = json.load(f)
    exit_code = int(data.get("exit_code", 0))
    stdout = data.get("stdout", "")
    stderr = data.get("stderr", "")
    stdout_b64 = data.get("stdout_b64", "")
    if not stdout and stdout_b64:
        try:
            stdout = base64.b64decode(stdout_b64).decode("utf-8", errors="replace")
        except Exception:
            pass
except Exception as exc:
    print(f"warning: git wrapper: failed to parse proxy response: {exc}", file=sys.stderr)
    exit_code = 1
    stdout = ""
    stderr = ""

with open(exit_file, "w") as f:
    f.write(str(exit_code))
with open(stdout_file, "w") as f:
    f.write(stdout)
with open(stderr_file, "w") as f:
    f.write(stderr)
PY

EXIT_CODE=$(cat "$PARSED_EXIT" 2>/dev/null || echo "1")

if [[ -s "$PARSED_STDOUT" ]]; then
    cat "$PARSED_STDOUT"
fi
if [[ -s "$PARSED_STDERR" ]]; then
    cat "$PARSED_STDERR" >&2
fi

rm -f "$RESPONSE_FILE" "$HTTP_CODE_FILE" "$PARSED_EXIT" "$PARSED_STDOUT" "$PARSED_STDERR"
exit "$EXIT_CODE"
