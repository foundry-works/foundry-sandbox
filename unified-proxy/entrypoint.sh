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
INTERNAL_API_PID=""
GIT_API_PID=""

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
        exec setpriv --reuid="${uid}" --regid="${gid}" --init-groups \
            --inh-caps=+net_bind_service --ambient-caps=+net_bind_service \
            -- "$0" "$@"
    elif command -v gosu >/dev/null 2>&1; then
        log "Warning: setpriv not found; falling back to gosu (DNS port 53 may fail)"
        exec gosu "${user}" "$0" "$@"
    else
        log_error "Neither setpriv nor gosu found; continuing as root"
    fi
}

# Graceful shutdown handler
cleanup() {
    log "Received shutdown signal, cleaning up..."

    # Remove readiness marker
    rm -f "${READINESS_FILE}"

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

    # Check legacy addons exist
    if [[ ! -f "${GITHUB_FILTER_PATH}" ]]; then
        log_error "GitHub API filter addon not found at ${GITHUB_FILTER_PATH}"
        return 1
    fi

    # Addon dependency order: each addon may depend on addons loaded before it.
    # This array defines the REQUIRED load order. Addons are loaded in this
    # sequence in start_mitmproxy(). If a new addon is added, it must be placed
    # in the correct position relative to its dependencies.
    #
    # Dependencies:
    #   container_identity - no deps (identifies containers for all other addons)
    #   policy_engine      - depends on: container_identity
    #   dns_filter         - depends on: container_identity (optional, DNS mode)
    #   credential_injector - depends on: container_identity, policy_engine
    #   git_proxy          - depends on: container_identity, policy_engine
    #   rate_limiter       - depends on: container_identity
    #   circuit_breaker    - depends on: container_identity
    #   metrics            - depends on: all above (observes everything, must be last)
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

    log "Configuration validated successfully (${#required_addons[@]} addons in dependency order)"
    return 0
}

validate_addon_load_order() {
    # Verify addons will be loaded in the correct dependency order.
    # This catches mismatches between validate_config() and start_mitmproxy().
    local expected_order=(
        "container_identity.py"
        "policy_engine.py"
        "credential_injector.py"
        "git_proxy.py"
        "rate_limiter.py"
        "circuit_breaker.py"
        "metrics.py"
    )

    local actual_order=("$@")
    local expected_idx=0

    for actual in "${actual_order[@]}"; do
        local basename="${actual##*/}"

        # Skip dns_filter — it's conditionally loaded based on PROXY_ENABLE_DNS
        [[ "${basename}" == "dns_filter.py" ]] && continue
        # Skip legacy addons (not part of dependency chain)
        # Note: can't use "${LEGACY_ADDON_DIR}"* — it matches /opt/proxy/addons/* too
        [[ "${actual}" == "${GITHUB_FILTER_PATH}" ]] && continue

        if [[ ${expected_idx} -ge ${#expected_order[@]} ]]; then
            log_error "Addon load order: unexpected addon '${basename}' after all expected addons"
            return 1
        fi

        if [[ "${basename}" != "${expected_order[${expected_idx}]}" ]]; then
            log_error "Addon load order mismatch at position ${expected_idx}: expected '${expected_order[${expected_idx}]}', got '${basename}'"
            log_error "Required order: ${expected_order[*]}"
            return 1
        fi

        ((expected_idx++))
    done

    if [[ ${expected_idx} -ne ${#expected_order[@]} ]]; then
        log_error "Addon load order: only ${expected_idx} of ${#expected_order[@]} required addons found"
        return 1
    fi

    log "Addon load order validated (${expected_idx} addons in correct sequence)"
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
                        "import sys,json; print(json.load(sys.stdin).get('name',''))" 2>/dev/null) || true
                fi
                if [[ -z "${email}" ]]; then
                    email=$(printf '%s' "${gh_user}" | python3 -c \
                        "import sys,json; print(json.load(sys.stdin).get('email',''))" 2>/dev/null) || true
                fi
            fi
        fi
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
    chmod +x "${helper_script}"

    # Set the token as an env var for the helper and scope helper to github.com.
    export FOUNDRY_PROXY_GIT_TOKEN="${token}"
    git config --global --unset-all credential.helper 2>/dev/null || true
    git config --global credential.https://github.com.helper "${helper_script}"

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

    local addon_paths=()
    addon_paths+=("${ADDON_DIR}/container_identity.py")
    addon_paths+=("${ADDON_DIR}/policy_engine.py")

    if [[ "${enable_dns}" == "true" ]]; then
        addon_paths+=("${ADDON_DIR}/dns_filter.py")
    fi

    addon_paths+=("${ADDON_DIR}/credential_injector.py")
    addon_paths+=("${ADDON_DIR}/git_proxy.py")
    addon_paths+=("${ADDON_DIR}/rate_limiter.py")
    addon_paths+=("${ADDON_DIR}/circuit_breaker.py")
    addon_paths+=("${ADDON_DIR}/metrics.py")

    # Validate load order before starting
    if ! validate_addon_load_order "${addon_paths[@]}"; then
        log_error "Addon load order validation failed — aborting"
        exit 1
    fi

    for addon_path in "${addon_paths[@]}"; do
        args+=(-s "${addon_path}")
    done

    # Also load legacy addons for backward compatibility
    args+=(-s "${GITHUB_FILTER_PATH}")

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

    # Wait for mitmproxy to bind to HTTP proxy port before marking ready.
    # This matches the pattern used by start_internal_api() and start_git_api().
    # Without this check, the health check can pass (via internal API socket)
    # while mitmproxy is still starting or has crashed on port binding.
    local mitm_ready=false
    for i in {1..30}; do
        if python3 -c "import socket; s=socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', 8080)); s.close()" 2>/dev/null; then
            log "mitmproxy HTTP proxy ready on port 8080"
            mark_ready
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
        log_error "mitmproxy did not bind to port 8080 within 15 seconds"
        exit 1
    fi

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
    generate_combined_ca_bundle

    # Validate configuration
    validate_config

    # Start internal API for container registration
    if ! start_internal_api; then
        log_error "Failed to start internal API"
        exit 1
    fi

    # Start git API server if git shadow mode is enabled
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

    # Disable auth files that don't exist
    disable_missing_auth_file CODEX_AUTH_FILE
    disable_missing_auth_file OPENCODE_AUTH_FILE
    disable_missing_auth_file GEMINI_OAUTH_FILE

    start_mitmproxy
}

main "$@"
