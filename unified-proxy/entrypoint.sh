#!/bin/bash
#
# Unified Proxy Entrypoint
#
# Generates CA certificate on first run, copies it to shared volume,
# validates configuration, and starts mitmproxy with all addons.
#
# Features:
# - Dual-mode: HTTP proxy (8080) + DNS filtering (53)
# - All addons loaded in dependency order
# - Graceful shutdown on SIGTERM
# - Readiness probe via file marker

set -euo pipefail

# Paths
MITMPROXY_CA_DIR="${HOME}/.mitmproxy"
MITMPROXY_CA_CERT="${MITMPROXY_CA_DIR}/mitmproxy-ca-cert.pem"
SHARED_CERTS_DIR="/etc/proxy/certs"
ADDON_DIR="/opt/proxy/addons"
LEGACY_ADDON_DIR="/opt/proxy"
READINESS_FILE="/var/run/proxy/ready"
PID_FILE="/var/run/proxy/mitmproxy.pid"

# Legacy addon paths (still used alongside new addons)
GITHUB_FILTER_PATH="${LEGACY_ADDON_DIR}/github-api-filter.py"

# Track child processes for graceful shutdown
MITM_PID=""
SQUID_PID=""
INTERNAL_API_PID=""
GIT_API_PID=""
GATEWAY_PID=""
OPENAI_GATEWAY_PID=""
GITHUB_GATEWAY_PID=""

# MITM mode detection (set by detect_mitm_needed)
MITM_ENABLED="false"

log() {
    echo "[$(date -Iseconds)] $*"
}

log_error() {
    echo "[$(date -Iseconds)] ERROR: $*" >&2
}

drop_privileges_if_needed() {
    if [[ "$(id -u)" -ne 0 ]]; then
        return 0
    fi

    local user="mitmproxy"
    local group="mitmproxy"
    local runtime_dirs=(
        "/var/run/proxy"
        "/var/lib/unified-proxy"
        "/etc/proxy/certs"
        "/etc/proxy/credentials"
    )

    for dir in "${runtime_dirs[@]}"; do
        if [[ -e "${dir}" ]]; then
            chown -R "${user}:${group}" "${dir}" 2>/dev/null || true
        fi
    done

    # Use setpriv with ambient capabilities to preserve NET_BIND_SERVICE
    # across the privilege drop. gosu uses setuid which drops all Linux
    # capabilities, preventing mitmproxy from binding to port 53 (DNS).
    # setpriv --ambient-caps keeps the capability in the ambient set so
    # it is inherited by child processes (mitmdump).
    local uid gid
    uid="$(id -u "${user}")"
    gid="$(id -g "${user}")"

    if command -v setpriv >/dev/null 2>&1; then
        log "Dropping privileges to ${user} (preserving NET_BIND_SERVICE)"
        # setpriv does not update HOME (unlike gosu), so set it explicitly
        # to the target user's home directory before re-executing.
        export HOME
        HOME="$(getent passwd "${user}" | cut -d: -f6)"
        exec setpriv --reuid="${uid}" --regid="${gid}" --init-groups \
            --inh-caps=+net_bind_service --ambient-caps=+net_bind_service \
            -- "$0" "$@"
    elif command -v gosu >/dev/null 2>&1; then
        log_error "setpriv not found; gosu cannot preserve NET_BIND_SERVICE for DNS port 53"
        exit 1
    else
        log_error "Neither setpriv nor gosu found; cannot drop privileges safely"
        exit 1
    fi
}

# Graceful shutdown handler
# shellcheck disable=SC2329  # invoked indirectly via trap
cleanup() {
    log "Received shutdown signal, cleaning up..."

    # Remove readiness marker
    rm -f "${READINESS_FILE}"

    # Stop Squid if running
    if [[ -n "${SQUID_PID}" ]] && kill -0 "${SQUID_PID}" 2>/dev/null; then
        log "Stopping Squid (PID ${SQUID_PID})..."
        kill -TERM "${SQUID_PID}" 2>/dev/null || true

        for i in {1..10}; do
            if ! kill -0 "${SQUID_PID}" 2>/dev/null; then
                log "Squid stopped gracefully"
                break
            fi
            sleep 0.5
        done

        if kill -0 "${SQUID_PID}" 2>/dev/null; then
            log "Force killing Squid..."
            kill -KILL "${SQUID_PID}" 2>/dev/null || true
        fi
    fi

    # Stop API gateway if running
    if [[ -n "${GATEWAY_PID}" ]] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
        log "Stopping API gateway (PID ${GATEWAY_PID})..."
        kill -TERM "${GATEWAY_PID}" 2>/dev/null || true
        wait "${GATEWAY_PID}" 2>/dev/null || true
    fi

    # Stop OpenAI gateway if running
    if [[ -n "${OPENAI_GATEWAY_PID}" ]] && kill -0 "${OPENAI_GATEWAY_PID}" 2>/dev/null; then
        log "Stopping OpenAI gateway (PID ${OPENAI_GATEWAY_PID})..."
        kill -TERM "${OPENAI_GATEWAY_PID}" 2>/dev/null || true
        wait "${OPENAI_GATEWAY_PID}" 2>/dev/null || true
    fi

    # Stop GitHub gateway if running
    if [[ -n "${GITHUB_GATEWAY_PID}" ]] && kill -0 "${GITHUB_GATEWAY_PID}" 2>/dev/null; then
        log "Stopping GitHub gateway (PID ${GITHUB_GATEWAY_PID})..."
        kill -TERM "${GITHUB_GATEWAY_PID}" 2>/dev/null || true
        wait "${GITHUB_GATEWAY_PID}" 2>/dev/null || true
    fi

    # Stop git API if running
    if [[ -n "${GIT_API_PID}" ]] && kill -0 "${GIT_API_PID}" 2>/dev/null; then
        log "Stopping git API (PID ${GIT_API_PID})..."
        kill -TERM "${GIT_API_PID}" 2>/dev/null || true
        wait "${GIT_API_PID}" 2>/dev/null || true
    fi

    # Stop internal API if running
    if [[ -n "${INTERNAL_API_PID}" ]] && kill -0 "${INTERNAL_API_PID}" 2>/dev/null; then
        log "Stopping internal API (PID ${INTERNAL_API_PID})..."
        kill -TERM "${INTERNAL_API_PID}" 2>/dev/null || true
        wait "${INTERNAL_API_PID}" 2>/dev/null || true
    fi

    # Stop mitmproxy gracefully
    if [[ -n "${MITM_PID}" ]] && kill -0 "${MITM_PID}" 2>/dev/null; then
        log "Sending SIGTERM to mitmproxy (PID ${MITM_PID})..."
        kill -TERM "${MITM_PID}" 2>/dev/null || true

        # Wait up to 10 seconds for graceful shutdown
        for i in {1..20}; do
            if ! kill -0 "${MITM_PID}" 2>/dev/null; then
                log "mitmproxy stopped gracefully"
                break
            fi
            sleep 0.5
        done

        # Force kill if still running
        if kill -0 "${MITM_PID}" 2>/dev/null; then
            log "Force killing mitmproxy..."
            kill -KILL "${MITM_PID}" 2>/dev/null || true
        fi
    fi

    rm -f "${PID_FILE}"
    log "Cleanup complete"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT SIGQUIT

generate_ca_cert() {
    log "Generating mitmproxy CA certificate..."

    mkdir -p "${MITMPROXY_CA_DIR}"

    # Start mitmproxy briefly to generate CA cert
    mitmdump --mode transparent --listen-port 0 --set confdir="${MITMPROXY_CA_DIR}" &
    local gen_pid=$!

    for i in {1..30}; do
        if [[ -f "${MITMPROXY_CA_CERT}" ]]; then
            log "CA certificate generated successfully"
            kill "${gen_pid}" 2>/dev/null || true
            wait "${gen_pid}" 2>/dev/null || true
            return 0
        fi
        # Fail fast if mitmdump died before producing the cert
        if ! kill -0 "${gen_pid}" 2>/dev/null; then
            log_error "mitmdump (PID ${gen_pid}) exited before generating CA certificate"
            return 1
        fi
        sleep 0.5
    done

    log_error "Failed to generate CA certificate within 15 seconds"
    kill "${gen_pid}" 2>/dev/null || true
    return 1
}

copy_ca_to_shared_volume() {
    if [[ ! -d "${SHARED_CERTS_DIR}" ]]; then
        log_error "Shared certs directory ${SHARED_CERTS_DIR} not mounted"
        return 1
    fi

    cp "${MITMPROXY_CA_CERT}" "${SHARED_CERTS_DIR}/mitmproxy-ca.pem"
    log "CA certificate copied to ${SHARED_CERTS_DIR}/mitmproxy-ca.pem"
}

# Generate combined CA bundle for sandbox containers.
# Includes system CAs + mitmproxy CA so sandboxes don't need to run
# update-ca-certificates (which requires a writable root filesystem).
generate_combined_ca_bundle() {
    local combined="${SHARED_CERTS_DIR}/ca-certificates.crt"
    local tmp="${combined}.tmp"
    # Write atomically: build in temp file with a single command, then rename.
    # A single cat invocation ensures we never leave a partial bundle (system
    # CAs only, missing mitmproxy CA) if the process is interrupted.
    cat /etc/ssl/certs/ca-certificates.crt "${MITMPROXY_CA_CERT}" > "$tmp"
    mv "$tmp" "$combined"
    log "Combined CA bundle generated at $combined"
}

validate_config() {
    log "Validating configuration..."

    # Check required directories
    for dir in "${ADDON_DIR}" "${LEGACY_ADDON_DIR}" "${SHARED_CERTS_DIR}"; do
        if [[ ! -d "${dir}" ]]; then
            log_error "Required directory not found: ${dir}"
            return 1
        fi
    done

    # Core addons that are always needed
    local required_addons=(
        "container_identity.py"
        "dns_filter.py"
    )

    # MITM-mode addons (only needed when MITM is enabled)
    if [[ "${MITM_ENABLED}" == "true" ]]; then
        required_addons+=(
            "policy_engine.py"
            "credential_injector.py"
        )
    fi

    for addon in "${required_addons[@]}"; do
        if [[ ! -f "${ADDON_DIR}/${addon}" ]]; then
            log_error "Required addon not found: ${ADDON_DIR}/${addon}"
            return 1
        fi
    done

    # Validate Squid config exists
    if [[ ! -f "/etc/squid/squid.conf" ]]; then
        log_error "Squid configuration not found at /etc/squid/squid.conf"
        return 1
    fi

    log "Configuration validated successfully (${#required_addons[@]} addons, Squid config present)"
    return 0
}

start_internal_api() {
    local socket_path="${INTERNAL_API_SOCKET:-/var/run/proxy/internal.sock}"

    log "Starting internal API (socket: ${socket_path})..."
    python3 /opt/proxy/internal_api.py &
    INTERNAL_API_PID=$!

    # Wait briefly for socket to appear
    for i in {1..20}; do
        if [[ -S "${socket_path}" ]]; then
            log "Internal API socket ready"
            return 0
        fi
        sleep 0.25
    done

    log_error "Internal API socket not ready after 5 seconds"
    return 1
}

configure_git_identity() {
    # Set git user identity so commits made via the proxy have correct authorship.
    # Priority: explicit env vars > GitHub API discovery
    local name="${GIT_USER_NAME:-}"
    local email="${GIT_USER_EMAIL:-}"

    # Fallback: discover identity from GitHub API if we have a token
    if [[ -z "${name}" || -z "${email}" ]]; then
        local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
        if [[ -n "${token}" ]]; then
            log "Discovering git identity from GitHub API..."
            local gh_user
            gh_user=$(curl -sf -H "Authorization: token ${token}" \
                "https://api.github.com/user" 2>/dev/null) || true
            if [[ -n "${gh_user}" ]]; then
                if [[ -z "${name}" ]]; then
                    name=$(printf '%s' "${gh_user}" | python3 -c \
                        "import sys,json,re; v=json.load(sys.stdin).get('name',''); print(re.sub(r'[\x00-\x1f\x7f]','',v)[:128])" 2>/dev/null) || true
                fi
                if [[ -z "${email}" ]]; then
                    email=$(printf '%s' "${gh_user}" | python3 -c \
                        "import sys,json,re; v=json.load(sys.stdin).get('email',''); print(re.sub(r'[\x00-\x1f\x7f]','',v)[:128])" 2>/dev/null) || true
                fi
            fi
        fi
    fi

    # Sanitize name and email: strip control characters and truncate to 128 chars.
    # The GitHub API discovery path above applies the same sanitization via Python,
    # but env var values (GIT_USER_NAME/GIT_USER_EMAIL) bypass that code path.
    if [[ -n "${name}" ]]; then
        name=$(printf '%s' "${name}" | python3 -c "import sys,re; print(re.sub(r'[\x00-\x1f\x7f]','',sys.stdin.read())[:128])" 2>/dev/null) || name="${name:0:128}"
    fi
    if [[ -n "${email}" ]]; then
        email=$(printf '%s' "${email}" | python3 -c "import sys,re; print(re.sub(r'[\x00-\x1f\x7f]','',sys.stdin.read())[:128])" 2>/dev/null) || email="${email:0:128}"
    fi

    if [[ -n "${name}" ]]; then
        git config --global user.name "${name}"
        log "Git identity: user.name = ${name}"
    fi
    if [[ -n "${email}" ]]; then
        git config --global user.email "${email}"
        log "Git identity: user.email = ${email}"
    fi
    if [[ -z "${name}" && -z "${email}" ]]; then
        log "Warning: No git identity configured; commits may fail with 'Author identity unknown'"
    fi
}

configure_git_credentials() {
    # Configure git credential helper so the proxy can push/fetch on behalf of sandboxes
    # Uses GITHUB_TOKEN (already available in proxy environment from docker-compose)
    local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

    if [[ -z "${token}" ]]; then
        log "No GITHUB_TOKEN or GH_TOKEN set; git push/fetch will be unauthenticated"
        return 0
    fi

    log "Configuring git credential helper for authenticated push/fetch..."

    # Use a credential helper script that returns the token
    local helper_script="/var/run/proxy/git-credential-helper.sh"
    mkdir -p /var/run/proxy
    chmod 0700 /var/run/proxy
    cat > "${helper_script}" <<'HELPER_EOF'
#!/bin/bash
# Git credential helper that provides GITHUB_TOKEN for GitHub operations
case "$1" in
    get)
        host=""
        protocol=""
        while IFS= read -r line; do
            [[ -z "$line" ]] && break
            case "$line" in
                host=*) host="${line#host=}" ;;
                protocol=*) protocol="${line#protocol=}" ;;
            esac
        done

        # Never return credentials for non-GitHub hosts.
        if [[ "${protocol}" != "https" || "${host}" != "github.com" ]]; then
            exit 0
        fi

        echo "protocol=https"
        echo "host=github.com"
        echo "username=x-access-token"
        echo "password=${FOUNDRY_PROXY_GIT_TOKEN}"
        echo ""
        ;;
esac
HELPER_EOF
    chmod 0700 "${helper_script}"

    # Set the token as an env var for the helper and scope helper to github.com.
    export FOUNDRY_PROXY_GIT_TOKEN="${token}"
    git config --global --unset-all credential.helper 2>/dev/null || true
    git config --global credential.https://github.com.helper "${helper_script}"

    # Rewrite SSH GitHub URLs to HTTPS so the credential helper is used.
    # Bare repos may have SSH remotes (git@github.com:...) but the proxy
    # authenticates via HTTPS token, not SSH keys.
    git config --global --unset-all url."https://github.com/".insteadOf 2>/dev/null || true
    git config --global --add url."https://github.com/".insteadOf "git@github.com:" 2>/dev/null || true
    git config --global --add url."https://github.com/".insteadOf "ssh://git@github.com/" 2>/dev/null || true

    log "Git credential helper configured"
}

start_git_api() {
    if [[ "${GIT_SHADOW_ENABLED:-false}" != "true" ]]; then
        log "Git shadow mode disabled; skipping git API startup"
        return 0
    fi

    log "Starting git API server (port ${GIT_API_PORT:-8083})..."

    # Ensure PYTHONPATH includes the proxy module directory
    export PYTHONPATH="/opt/proxy:${PYTHONPATH:-}"

    python3 /opt/proxy/git_api.py &
    GIT_API_PID=$!

    # Wait briefly for the server to start listening
    local port="${GIT_API_PORT:-8083}"
    for i in {1..20}; do
        if python3 -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', ${port})); s.close()" 2>/dev/null; then
            log "Git API server ready on port ${port} (PID ${GIT_API_PID})"
            return 0
        fi
        sleep 0.25
    done

    log_error "Git API server not ready after 5 seconds"
    return 1
}

start_gateway() {
    # The API gateway provides plaintext HTTP endpoints for providers that
    # support base URL env vars (e.g. ANTHROPIC_BASE_URL). Sandboxes talk
    # HTTP to the gateway; the gateway injects credentials and forwards
    # over HTTPS to the upstream API.
    #
    # Anthropic (port 9848), OpenAI (port 9849), GitHub (port 9850).

    # Only start if an Anthropic credential is available
    if [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]]; then
        log "No Anthropic credential set; skipping API gateway startup"
        return 0
    fi

    local port="${GATEWAY_PORT:-9848}"
    log "Starting API gateway (port ${port})..."

    export PYTHONPATH="/opt/proxy:${PYTHONPATH:-}"

    python3 /opt/proxy/gateway.py &
    GATEWAY_PID=$!

    # Wait for the server to start listening
    for i in {1..20}; do
        if python3 -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', ${port})); s.close()" 2>/dev/null; then
            log "API gateway ready on port ${port} (PID ${GATEWAY_PID})"
            return 0
        fi
        sleep 0.25
    done

    log_error "API gateway not ready after 5 seconds"
    return 1
}

start_openai_gateway() {
    # OpenAI API gateway provides plaintext HTTP endpoint on port 9849.
    # Sandboxes talk HTTP to the gateway; the gateway injects credentials
    # and forwards over HTTPS to https://api.openai.com.

    # Only start if an OpenAI credential is available
    if [[ -z "${OPENAI_API_KEY:-}" ]]; then
        log "No OpenAI credential set; skipping OpenAI gateway startup"
        return 0
    fi

    local port="${OPENAI_GATEWAY_PORT:-9849}"
    log "Starting OpenAI gateway (port ${port})..."

    export PYTHONPATH="/opt/proxy:${PYTHONPATH:-}"

    python3 /opt/proxy/openai_gateway.py &
    OPENAI_GATEWAY_PID=$!

    # Wait for the server to start listening
    for i in {1..20}; do
        if python3 -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', ${port})); s.close()" 2>/dev/null; then
            log "OpenAI gateway ready on port ${port} (PID ${OPENAI_GATEWAY_PID})"
            return 0
        fi
        sleep 0.25
    done

    log_error "OpenAI gateway not ready after 5 seconds"
    return 1
}

start_github_gateway() {
    # GitHub API gateway provides plaintext HTTP endpoint on port 9850.
    # Sandboxes talk HTTP to the gateway; the gateway enforces security
    # policies, injects credentials, and forwards over HTTPS to
    # https://api.github.com.

    # Only start if a GitHub credential is available
    if [[ -z "${GITHUB_TOKEN:-}" && -z "${GH_TOKEN:-}" ]]; then
        log "No GitHub credential set; skipping GitHub gateway startup"
        return 0
    fi

    local port="${GITHUB_GATEWAY_PORT:-9850}"
    log "Starting GitHub gateway (port ${port})..."

    export PYTHONPATH="/opt/proxy:${PYTHONPATH:-}"

    python3 /opt/proxy/github_gateway.py &
    GITHUB_GATEWAY_PID=$!

    # Wait for the server to start listening
    for i in {1..20}; do
        if python3 -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', ${port})); s.close()" 2>/dev/null; then
            log "GitHub gateway ready on port ${port} (PID ${GITHUB_GATEWAY_PID})"
            return 0
        fi
        sleep 0.25
    done

    log_error "GitHub gateway not ready after 5 seconds"
    return 1
}

disable_missing_auth_file() {
    local var_name="$1"
    local auth_path="${!var_name:-}"

    if [[ -n "${auth_path}" && ! -f "${auth_path}" ]]; then
        log "Auth file ${auth_path} not found; disabling ${var_name}"
        unset "${var_name}"
    fi
}

mark_ready() {
    mkdir -p "$(dirname "${READINESS_FILE}")"
    echo "ready" > "${READINESS_FILE}"
    log "Readiness marker created at ${READINESS_FILE}"
}

detect_mitm_needed() {
    # Check if any MITM provider credentials are set.
    # These providers require mitmproxy for TLS interception and credential injection.
    # When no MITM providers are configured and ENABLE_MITM_FALLBACK is false,
    # CA certificate generation is skipped (reduced attack surface).

    if [[ "${ENABLE_MITM_FALLBACK:-true}" == "true" ]]; then
        MITM_ENABLED="true"
        log "MITM mode: enabled (ENABLE_MITM_FALLBACK=true)"
        return 0
    fi

    # Check for MITM provider credentials
    local mitm_vars=(
        GOOGLE_API_KEY
        GEMINI_API_KEY
        TAVILY_API_KEY
        SEMANTIC_SCHOLAR_API_KEY
        PERPLEXITY_API_KEY
        ZHIPU_API_KEY
        CODEX_AUTH_FILE
        GEMINI_OAUTH_FILE
    )

    for var in "${mitm_vars[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            MITM_ENABLED="true"
            log "MITM mode: enabled (${var} is set)"
            return 0
        fi
    done

    MITM_ENABLED="false"
    log "MITM mode: disabled (no MITM provider credentials set)"
    return 0
}

generate_squid_domain_lists() {
    log "Generating Squid domain list files from allowlist.yaml..."
    export PYTHONPATH="/opt/proxy:${PYTHONPATH:-}"
    python3 /opt/proxy/generate_squid_config.py --output-dir /etc/squid
    log "Squid domain lists generated"
}

start_squid() {
    log "Starting Squid forward proxy on port 8080..."

    # Start Squid in foreground mode (non-daemon)
    squid -N -f /etc/squid/squid.conf &
    SQUID_PID=$!

    # Wait for Squid to bind to port 8080
    for i in {1..30}; do
        if python3 -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', 8080)); s.close()" 2>/dev/null; then
            log "Squid ready on port 8080 (PID ${SQUID_PID})"
            return 0
        fi
        if ! kill -0 "${SQUID_PID}" 2>/dev/null; then
            log_error "Squid exited before becoming ready"
            return 1
        fi
        sleep 0.5
    done

    log_error "Squid did not bind to port 8080 within 15 seconds"
    return 1
}

start_mitmproxy() {
    local log_level="${PROXY_LOG_LEVEL:-info}"
    local enable_dns="${PROXY_ENABLE_DNS:-true}"

    # mitmproxy now runs on port 8081 (receives forwarded CONNECT from Squid)
    # and dns@53 (DNS filtering). Squid is the primary forward proxy on port 8080.

    log "Starting mitmproxy (DNS: ${enable_dns}, MITM: ${MITM_ENABLED})..."

    # Ensure addon modules can import from /opt/proxy
    export PYTHONPATH="/opt/proxy:${PYTHONPATH:-}"

    # Build mitmproxy arguments
    local args=(
        --set confdir="${MITMPROXY_CA_DIR}"
        --set block_global=false
        --set connection_strategy=lazy
    )

    # DNS mode (always runs when enabled — independent of MITM)
    if [[ "${enable_dns}" == "true" ]]; then
        args+=(--mode "dns@53")
        log "DNS filtering enabled on port 53"
    fi

    # MITM HTTP proxy mode (receives forwarded CONNECT from Squid cache_peer)
    if [[ "${MITM_ENABLED}" == "true" ]]; then
        args+=(--mode "regular@8081")
        log "MITM proxy enabled on port 8081 (receives from Squid cache_peer)"
    fi

    # Load addons based on MITM mode
    # container_identity and dns_filter always load (needed for DNS)
    # credential_injector and policy_engine only when MITM is active
    local addon_paths=()
    addon_paths+=("${ADDON_DIR}/container_identity.py")

    if [[ "${enable_dns}" == "true" ]]; then
        addon_paths+=("${ADDON_DIR}/dns_filter.py")
    fi

    if [[ "${MITM_ENABLED}" == "true" ]]; then
        addon_paths+=("${ADDON_DIR}/policy_engine.py")
        addon_paths+=("${ADDON_DIR}/credential_injector.py")
    fi

    for addon_path in "${addon_paths[@]}"; do
        args+=(-s "${addon_path}")
    done

    # Flow detail: debug shows full detail
    if [[ "${log_level}" == "debug" ]]; then
        args+=(--set flow_detail=3)
    fi

    log "mitmproxy args: ${args[*]}"

    # Start mitmproxy in background to capture PID
    mitmdump "${args[@]}" &
    MITM_PID=$!
    echo "${MITM_PID}" > "${PID_FILE}"

    log "mitmproxy started with PID ${MITM_PID}"

    # Wait for mitmproxy to be ready.
    # If MITM is enabled, check port 8081. If only DNS, check process health.
    if [[ "${MITM_ENABLED}" == "true" ]]; then
        local mitm_ready=false
        for i in {1..30}; do
            if python3 -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', 8081)); s.close()" 2>/dev/null; then
                log "mitmproxy MITM proxy ready on port 8081"
                mitm_ready=true
                break
            fi
            if ! kill -0 "${MITM_PID}" 2>/dev/null; then
                log_error "mitmproxy exited before becoming ready"
                exit 1
            fi
            sleep 0.5
        done

        if [[ "${mitm_ready}" != "true" ]]; then
            log_error "mitmproxy did not bind to port 8081 within 15 seconds"
            exit 1
        fi
    else
        # DNS-only mode: wait briefly for process to start
        sleep 1
        if ! kill -0 "${MITM_PID}" 2>/dev/null; then
            log_error "mitmproxy (DNS-only) exited immediately"
            exit 1
        fi
        log "mitmproxy DNS-only mode started"
    fi
}

main() {
    drop_privileges_if_needed "$@"

    log "Unified Proxy starting..."

    # 1. Detect if MITM mode is needed (checks provider credentials)
    detect_mitm_needed

    # 2. Generate CA certificate only when MITM is needed
    if [[ "${MITM_ENABLED}" == "true" ]]; then
        if [[ ! -f "${MITMPROXY_CA_CERT}" ]]; then
            generate_ca_cert
        else
            log "Using existing CA certificate"
        fi
        copy_ca_to_shared_volume
        generate_combined_ca_bundle
    else
        log "MITM disabled — skipping CA certificate generation"
        # Still need to generate a CA cert dir for mitmproxy DNS-only mode
        mkdir -p "${MITMPROXY_CA_DIR}"
    fi

    # 3. Generate Squid domain list files from allowlist.yaml
    generate_squid_domain_lists

    # 4. Validate configuration
    validate_config

    # 5. Start internal API for container registration
    if ! start_internal_api; then
        log_error "Failed to start internal API"
        exit 1
    fi

    # 6. Start git API server if git shadow mode is enabled
    configure_git_identity
    configure_git_credentials
    if ! start_git_api; then
        log_error "Failed to start git API server"
        exit 1
    fi

    # Disable OpenCode auth if not explicitly enabled
    if [[ "${SANDBOX_ENABLE_OPENCODE:-0}" != "1" ]]; then
        log "SANDBOX_ENABLE_OPENCODE not set; disabling OpenCode auth"
        unset OPENCODE_AUTH_FILE
    fi

    # 7. Start API gateways
    if ! start_gateway; then
        log_error "Failed to start API gateway"
        exit 1
    fi

    if ! start_openai_gateway; then
        log_error "Failed to start OpenAI gateway"
        exit 1
    fi

    if ! start_github_gateway; then
        log_error "Failed to start GitHub gateway"
        exit 1
    fi

    # Disable auth files that don't exist
    disable_missing_auth_file CODEX_AUTH_FILE
    disable_missing_auth_file OPENCODE_AUTH_FILE
    disable_missing_auth_file GEMINI_OAUTH_FILE

    # 8. Start mitmproxy (port 8081 for MITM + dns@53)
    start_mitmproxy

    # 9. Start Squid forward proxy (port 8080 — primary sandbox proxy)
    if ! start_squid; then
        log_error "Failed to start Squid"
        exit 1
    fi

    # 10. Mark ready (after Squid is listening on port 8080)
    mark_ready

    # Wait for Squid (primary process for signal handling)
    wait "${SQUID_PID}"
    local exit_code=$?

    log "Squid exited with code ${exit_code}"
    rm -f "${READINESS_FILE}" "${PID_FILE}"
    exit ${exit_code}
}

main "$@"
