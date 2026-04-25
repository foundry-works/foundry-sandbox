#!/bin/bash
# Shared test harness for red team modules
# Provides assertions, counters, and structured output formatters

set -u

# Source git-safety environment when running inside a sandbox.
# sbx exec creates non-login shells, so /etc/profile.d/ is not sourced.
if [[ -f /var/lib/foundry/git-safety.env ]]; then
    if command -v python3 >/dev/null 2>&1; then
        while IFS= read -r -d '' _key && IFS= read -r -d '' _val; do
            case "$_key" in
                WORKSPACE_DIR)
                    # sbx may set this to the mount point; foundry stores the
                    # worktree path used by the git wrapper and redteam checks.
                    export "$_key=$_val"
                    ;;
                SANDBOX_ID|GIT_API_HOST|GIT_API_PORT|PIP_USER|PIP_BREAK_SYSTEM_PACKAGES)
                    if [[ -z "${!_key:-}" ]]; then
                        export "$_key=$_val"
                    fi
                    ;;
            esac
        done < <(python3 - /var/lib/foundry/git-safety.env <<'PY'
import shlex
import sys

wanted = {
    "SANDBOX_ID",
    "WORKSPACE_DIR",
    "GIT_API_HOST",
    "GIT_API_PORT",
    "PIP_USER",
    "PIP_BREAK_SYSTEM_PACKAGES",
}
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                tokens = shlex.split(line, comments=True, posix=True)
            except ValueError:
                continue
            if tokens and tokens[0] == "export":
                tokens = tokens[1:]
            for token in tokens:
                if "=" not in token:
                    continue
                key, value = token.split("=", 1)
                if key in wanted:
                    sys.stdout.write(key + "\0" + value + "\0")
except OSError:
    pass
PY
)
    else
        while IFS='=' read -r _key _val; do
            _key="${_key#export }"
            case "$_key" in
                WORKSPACE_DIR)
                    export "$_key=$_val"
                    ;;
                SANDBOX_ID|GIT_API_HOST|GIT_API_PORT|PIP_USER|PIP_BREAK_SYSTEM_PACKAGES)
                    if [[ -z "${!_key:-}" ]]; then
                        export "$_key=$_val"
                    fi
                    ;;
            esac
        done < /var/lib/foundry/git-safety.env
    fi
fi

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Counters ---
PASS=0
FAIL=0
WARN=0
TEST_NUM=0

# --- Output targets (set by runner) ---
TAP_FILE=""
JUNIT_FILE=""

# --- Results accumulator for JUnit ---
declare -a _JUNIT_RESULTS=()
_CURRENT_MODULE=""
_MODULE_START_TIME=""

# --- Assertions ---
header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

test_pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $1"
    ((PASS++))
    _emit_tap "ok" "$1"
    _junit_record "pass" "$1"
}

test_fail() {
    echo -e "  ${RED}✗ FAIL${NC}: $1"
    ((FAIL++))
    _emit_tap "not ok" "$1"
    _junit_record "fail" "$1"
}

test_warn() {
    echo -e "  ${YELLOW}⚠ WARN${NC}: $1"
    ((WARN++))
    _emit_tap "ok" "$1 # TODO warning"
    _junit_record "warn" "$1"
}

info() {
    echo -e "  ${CYAN}ℹ${NC} $1"
}

# --- Workspace helpers ---
workspace_candidates() {
    local seen=":" candidate
    for candidate in "${WORKSPACE_DIR:-}" /workspace "$PWD"; do
        [[ -n "$candidate" ]] || continue
        [[ -d "$candidate" ]] || continue
        case "$seen" in
            *":$candidate:"*) continue ;;
        esac
        seen="${seen}${candidate}:"
        printf '%s\n' "$candidate"
    done
}

foundry_workspace_dir() {
    local candidate
    while IFS= read -r candidate; do
        printf '%s\n' "$candidate"
        return 0
    done < <(workspace_candidates)
    printf '%s\n' "$PWD"
}

# --- Deep-policy proxy helpers ---
deep_policy_available() {
    [[ -n "${GIT_API_HOST:-}" ]] \
        && [[ -n "${GIT_API_PORT:-}" ]] \
        && command -v proxy-sign >/dev/null 2>&1
}

deep_policy_request() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    local headers_file="${4:-}"
    local sign_output proxy
    local X_SANDBOX_ID X_REQUEST_TIMESTAMP X_REQUEST_NONCE X_REQUEST_SIGNATURE

    if ! deep_policy_available; then
        echo "deep-policy proxy unavailable: need GIT_API_HOST, GIT_API_PORT, and proxy-sign" >&2
        return 2
    fi

    if ! sign_output=$(proxy-sign "$method" "$path" "$body" 2>&1); then
        echo "proxy-sign failed: $sign_output" >&2
        return 2
    fi
    eval "$sign_output"

    proxy="${SBX_PROXY:-http://gateway.docker.internal:3128}"
    local curl_args=(
        -s
        --max-time 10
        --proxy "$proxy"
        -w $'\n%{http_code}'
        -X "$method"
        -H "X-Sandbox-Id: $X_SANDBOX_ID"
        -H "X-Request-Signature: $X_REQUEST_SIGNATURE"
        -H "X-Request-Timestamp: $X_REQUEST_TIMESTAMP"
        -H "X-Request-Nonce: $X_REQUEST_NONCE"
    )

    if [[ -n "$headers_file" ]]; then
        curl_args+=(-D "$headers_file")
    fi
    if [[ -n "$body" ]]; then
        curl_args+=(-H "Content-Type: application/json" --data-binary "$body")
    fi

    curl "${curl_args[@]}" "http://${GIT_API_HOST}:${GIT_API_PORT}${path}"
}

http_response_code() {
    printf '%s\n' "$1" | tail -n 1
}

http_response_body() {
    printf '%s\n' "$1" | sed '$d'
}

deep_policy_response_blocked() {
    local http_code="$1"
    local headers_file="$2"
    local body="$3"

    if [[ "$http_code" == "403" ]] \
        && [[ -f "$headers_file" ]] \
        && grep -qi "X-Sandbox-Blocked:[[:space:]]*true" "$headers_file" 2>/dev/null; then
        return 0
    fi

    if [[ "$http_code" =~ ^2 ]]; then
        return 1
    fi

    printf '%s' "$body" | grep -qiE "(BLOCKED|blocked|not allowed|not permitted|policy|self-approving)"
}

assert_deep_policy_blocked() {
    local label="$1"
    local method="$2"
    local path="$3"
    local body="${4:-}"
    local headers response request_exit http_code response_body

    headers=$(mktemp)
    response=$(deep_policy_request "$method" "$path" "$body" "$headers" 2>&1)
    request_exit=$?
    http_code=$(http_response_code "$response")
    response_body=$(http_response_body "$response")

    if [[ $request_exit -ne 0 ]]; then
        rm -f "$headers"
        test_fail "$label request failed before policy: $(printf '%s' "$response" | head -c 200)"
        return 1
    fi

    if deep_policy_response_blocked "$http_code" "$headers" "$response_body"; then
        rm -f "$headers"
        test_pass "$label blocked by deep policy (HTTP $http_code)"
        return 0
    fi

    rm -f "$headers"
    case "$http_code" in
        000)
            test_fail "$label curl failed (HTTP 000)"
            ;;
        401)
            test_fail "$label was rejected by auth instead of policy"
            ;;
        404)
            test_fail "$label was forwarded upstream (HTTP 404)"
            ;;
        2*)
            test_fail "$label was allowed (HTTP $http_code)"
            ;;
        *)
            test_fail "$label was not clearly blocked (HTTP $http_code)"
            ;;
    esac
    return 1
}

assert_deep_policy_allowed() {
    local label="$1"
    local method="$2"
    local path="$3"
    local body="${4:-}"
    local headers response request_exit http_code response_body

    headers=$(mktemp)
    response=$(deep_policy_request "$method" "$path" "$body" "$headers" 2>&1)
    request_exit=$?
    http_code=$(http_response_code "$response")
    response_body=$(http_response_body "$response")

    if [[ $request_exit -ne 0 ]]; then
        rm -f "$headers"
        test_fail "$label request failed before policy: $(printf '%s' "$response" | head -c 200)"
        return 1
    fi

    if deep_policy_response_blocked "$http_code" "$headers" "$response_body"; then
        rm -f "$headers"
        test_fail "$label was blocked by deep policy (HTTP $http_code)"
        return 1
    fi

    if [[ "$http_code" == "401" ]] \
        && printf '%s' "$response_body" | grep -qiE "(authentication headers|HMAC|signature)"; then
        rm -f "$headers"
        test_fail "$label was rejected by proxy auth"
        return 1
    fi

    rm -f "$headers"
    test_pass "$label reached proxy/upstream without policy block (HTTP $http_code)"
    return 0
}

# --- Structured output: TAP ---
_emit_tap() {
    local status="$1" description="$2"
    ((TEST_NUM++))
    if [ -n "$TAP_FILE" ]; then
        echo "${status} ${TEST_NUM} - ${description}" >> "$TAP_FILE"
    fi
}

# --- Structured output: JUnit ---
_junit_record() {
    local status="$1" description="$2"
    _JUNIT_RESULTS+=("${status}|${_CURRENT_MODULE}|${description}")
}

# --- Module timing ---
section_start() {
    _CURRENT_MODULE="${1:-unknown}"
    _MODULE_START_TIME=$(date +%s%N 2>/dev/null || date +%s)
}

section_end() {
    _MODULE_START_TIME=""
}

# --- Summary output ---
print_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}PASSED${NC}: $PASS"
    echo -e "  ${RED}FAILED${NC}: $FAIL"
    echo -e "  ${YELLOW}WARNINGS${NC}: $WARN"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    if [[ $FAIL -gt 0 ]]; then
        echo -e "${RED}⚠ SECURITY ISSUES DETECTED - Review failed tests above${NC}"
    elif [[ $WARN -gt 3 ]]; then
        echo -e "${YELLOW}⚠ Multiple warnings - Review for potential issues${NC}"
    else
        echo -e "${GREEN}✓ Credential isolation appears effective${NC}"
    fi
}

# --- TAP finalization ---
_finalize_tap() {
    if [ -n "$TAP_FILE" ]; then
        # Prepend TAP header
        local tmp
        tmp=$(mktemp)
        {
            echo "TAP version 13"
            echo "1..${TEST_NUM}"
            cat "$TAP_FILE"
        } > "$tmp"
        mv "$tmp" "$TAP_FILE"
    fi
}

# --- JUnit XML generation ---
_emit_junit_summary() {
    if [ -z "$JUNIT_FILE" ]; then
        return
    fi

    local total=$((PASS + FAIL + WARN))
    local failures=$FAIL

    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo "<testsuites tests=\"${total}\" failures=\"${failures}\">"
        echo "  <testsuite name=\"redteam\" tests=\"${total}\" failures=\"${failures}\">"

        for entry in "${_JUNIT_RESULTS[@]}"; do
            local status="${entry%%|*}"
            local rest="${entry#*|}"
            local module="${rest%%|*}"
            local desc="${rest#*|}"

            # Escape XML special characters
            desc="${desc//&/&amp;}"
            desc="${desc//</&lt;}"
            desc="${desc//>/&gt;}"
            desc="${desc//\"/&quot;}"

            echo "    <testcase classname=\"redteam.${module}\" name=\"${desc}\">"
            if [[ "$status" == "fail" ]]; then
                echo "      <failure message=\"${desc}\"/>"
            elif [[ "$status" == "warn" ]]; then
                echo "      <system-out>WARNING: ${desc}</system-out>"
            fi
            echo "    </testcase>"
        done

        echo "  </testsuite>"
        echo "</testsuites>"
    } > "$JUNIT_FILE"
}

# --- Finalize all output ---
finalize_output() {
    _finalize_tap
    _emit_junit_summary
}
