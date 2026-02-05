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

# Track child process for graceful shutdown
MITM_PID=""
INTERNAL_API_PID=""

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

    if command -v gosu >/dev/null 2>&1; then
        log "Dropping privileges to ${user}"
        exec gosu "${user}" "$0" "$@"
    else
        log_error "gosu not found; continuing as root"
    fi
}

# Graceful shutdown handler
cleanup() {
    log "Received shutdown signal, cleaning up..."

    # Remove readiness marker
    rm -f "${READINESS_FILE}"

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

validate_config() {
    log "Validating configuration..."

    # Check required directories
    for dir in "${ADDON_DIR}" "${LEGACY_ADDON_DIR}" "${SHARED_CERTS_DIR}"; do
        if [[ ! -d "${dir}" ]]; then
            log_error "Required directory not found: ${dir}"
            return 1
        fi
    done

    # Check legacy addons exist
    if [[ ! -f "${GITHUB_FILTER_PATH}" ]]; then
        log_error "GitHub API filter addon not found at ${GITHUB_FILTER_PATH}"
        return 1
    fi

    # Check new addons exist
    local required_addons=(
        "container_identity.py"
        "policy_engine.py"
        "dns_filter.py"
        "credential_injector.py"
        "git_proxy.py"
        "rate_limiter.py"
        "circuit_breaker.py"
        "metrics.py"
    )

    for addon in "${required_addons[@]}"; do
        if [[ ! -f "${ADDON_DIR}/${addon}" ]]; then
            log_error "Required addon not found: ${ADDON_DIR}/${addon}"
            return 1
        fi
    done

    log "Configuration validated successfully"
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

start_mitmproxy() {
    local mode="${PROXY_MODE:-regular}"
    local log_level="${PROXY_LOG_LEVEL:-info}"
    local enable_dns="${PROXY_ENABLE_DNS:-true}"

    log "Starting mitmproxy (HTTP mode: ${mode}, DNS: ${enable_dns})..."

    # Ensure addon modules can import from /opt/proxy
    export PYTHONPATH="/opt/proxy:${PYTHONPATH:-}"

    # Build mitmproxy arguments
    local args=(
        --mode "${mode}@8080"
        --set confdir="${MITMPROXY_CA_DIR}"
        --set block_global=false
        --set connection_strategy=lazy
    )

    # Add DNS mode if enabled
    if [[ "${enable_dns}" == "true" ]]; then
        args+=(--mode "dns@53")
        log "DNS filtering enabled on port 53"
    fi

    # Load addons in dependency order:
    # 1. container_identity - identifies source container (needed by others)
    # 2. policy_engine - enforces security policies
    # 3. dns_filter - filters DNS queries (if DNS mode enabled)
    # 4. credential_injector - injects API credentials
    # 5. git_proxy - filters git protocol operations
    # 6. rate_limiter - enforces rate limits
    # 7. circuit_breaker - handles failures gracefully
    # 8. metrics - collects telemetry (last, observes all)

    args+=(-s "${ADDON_DIR}/container_identity.py")
    args+=(-s "${ADDON_DIR}/policy_engine.py")

    if [[ "${enable_dns}" == "true" ]]; then
        args+=(-s "${ADDON_DIR}/dns_filter.py")
    fi

    args+=(-s "${ADDON_DIR}/credential_injector.py")
    args+=(-s "${ADDON_DIR}/git_proxy.py")
    args+=(-s "${ADDON_DIR}/rate_limiter.py")
    args+=(-s "${ADDON_DIR}/circuit_breaker.py")
    args+=(-s "${ADDON_DIR}/metrics.py")

    # Also load legacy addons for backward compatibility
    args+=(-s "${GITHUB_FILTER_PATH}")

    # Debug logging if requested
    if [[ "${log_level}" == "debug" ]]; then
        args+=(--set flow_detail=3)
    fi

    log "mitmproxy args: ${args[*]}"

    # Mark ready before starting (mitmproxy will be available shortly)
    mark_ready

    # Start mitmproxy in background to capture PID
    mitmdump "${args[@]}" &
    MITM_PID=$!
    echo "${MITM_PID}" > "${PID_FILE}"

    log "mitmproxy started with PID ${MITM_PID}"

    # Wait for mitmproxy (this allows signal handling)
    wait "${MITM_PID}"
    local exit_code=$?

    log "mitmproxy exited with code ${exit_code}"
    rm -f "${READINESS_FILE}" "${PID_FILE}"
    exit ${exit_code}
}

main() {
    drop_privileges_if_needed "$@"

    log "Unified Proxy starting..."

    # Generate CA certificate if needed
    if [[ ! -f "${MITMPROXY_CA_CERT}" ]]; then
        generate_ca_cert
    else
        log "Using existing CA certificate"
    fi

    copy_ca_to_shared_volume

    # Validate configuration
    validate_config

    # Start internal API for container registration
    if ! start_internal_api; then
        log_error "Failed to start internal API"
        exit 1
    fi

    # Disable OpenCode auth if not explicitly enabled
    if [[ "${SANDBOX_ENABLE_OPENCODE:-0}" != "1" ]]; then
        log "SANDBOX_ENABLE_OPENCODE not set; disabling OpenCode auth"
        unset OPENCODE_AUTH_FILE
    fi

    # Disable auth files that don't exist
    disable_missing_auth_file CODEX_AUTH_FILE
    disable_missing_auth_file OPENCODE_AUTH_FILE
    disable_missing_auth_file GEMINI_OAUTH_FILE

    start_mitmproxy
}

main "$@"
