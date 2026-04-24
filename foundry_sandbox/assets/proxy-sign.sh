#!/bin/bash
# HMAC signing helper for sandbox proxy requests.
#
# Used by tools inside the sandbox to authenticate HTTP requests to the
# user services proxy (/proxy/...) and deep policy proxy (/deep-policy/...).
#
# Usage:
#   eval "$(proxy-sign GET /proxy/tavily/v1/search)"
#   curl -H "$X_SANDBOX_ID" -H "$X_REQUEST_SIGNATURE" \
#        -H "$X_REQUEST_TIMESTAMP" -H "$X_REQUEST_NONCE" \
#        "$URL"
#
# Or with a body:
#   eval "$(proxy-sign POST /proxy/tavily/v1/search '{"query":"test"}')"
#
# Prints shell variable assignments:
#   X_SANDBOX_ID=...
#   X_REQUEST_TIMESTAMP=...
#   X_REQUEST_NONCE=...
#   X_REQUEST_SIGNATURE=...

set -euo pipefail

_BODY_FILE=""
cleanup() {
    if [[ -n "${_BODY_FILE:-}" ]]; then
        rm -f "$_BODY_FILE" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

HMAC_SECRET_FILE="${GIT_HMAC_SECRET_FILE:-}"
SANDBOX_ID="${SANDBOX_ID:-${SANDBOX_VM_ID:-}}"

if [[ -z "$HMAC_SECRET_FILE" ]]; then
    if [[ -f "/run/foundry/hmac-secret" ]]; then
        HMAC_SECRET_FILE="/run/foundry/hmac-secret"
    elif [[ -f "/var/lib/foundry/hmac-secret" ]]; then
        HMAC_SECRET_FILE="/var/lib/foundry/hmac-secret"
    else
        echo "error: proxy-sign: HMAC secret file not found" >&2
        exit 1
    fi
fi

if [[ -z "$SANDBOX_ID" ]]; then
    echo "error: proxy-sign: SANDBOX_ID (or SANDBOX_VM_ID) not set" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: proxy-sign: python3 is required but not found in PATH" >&2
    exit 1
fi

if [[ $# -lt 2 ]]; then
    echo "usage: proxy-sign <method> <path> [body]" >&2
    exit 1
fi

METHOD="$1"
PATH_="$2"
BODY="${3:-}"

TIMESTAMP=$(date +%s)
NONCE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')

_BODY_FILE=$(mktemp)
printf '%s' "$BODY" > "$_BODY_FILE"

SIGNATURE=$(python3 - "$METHOD" "$PATH_" "$TIMESTAMP" "$NONCE" "$HMAC_SECRET_FILE" "$_BODY_FILE" <<'PY'
import hashlib, hmac, sys

method = sys.argv[1]
path = sys.argv[2]
timestamp = sys.argv[3]
nonce = sys.argv[4]
secret_file = sys.argv[5]
body_file = sys.argv[6]

with open(body_file, "rb") as f:
    body = f.read()

with open(secret_file, "rb") as f:
    secret = f.read().rstrip(b"\n")

body_hash = hashlib.sha256(body).hexdigest()
canonical = f"{method}\n{path}\n{body_hash}\n{timestamp}\n{nonce}"
sig = hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
print(sig)
PY
)
rm -f "$_BODY_FILE"
_BODY_FILE=""

echo "X_SANDBOX_ID=\"${SANDBOX_ID}\""
echo "X_REQUEST_TIMESTAMP=\"${TIMESTAMP}\""
echo "X_REQUEST_NONCE=\"${NONCE}\""
echo "X_REQUEST_SIGNATURE=\"${SIGNATURE}\""
