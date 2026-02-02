#!/bin/bash
#
# API Proxy Entrypoint
#
# Generates CA certificate on first run, copies it to shared volume,
# and starts mitmproxy with credential injection.

set -euo pipefail

MITMPROXY_CA_DIR="${HOME}/.mitmproxy"
MITMPROXY_CA_CERT="${MITMPROXY_CA_DIR}/mitmproxy-ca-cert.pem"
SHARED_CERTS_DIR="/etc/proxy/certs"
ADDON_PATH="/opt/proxy/inject-credentials.py"
GITHUB_FILTER_PATH="/opt/proxy/github-api-filter.py"

log() {
    echo "[$(date -Iseconds)] $*"
}

generate_ca_cert() {
    log "Generating mitmproxy CA certificate..."

    mkdir -p "${MITMPROXY_CA_DIR}"

    mitmdump --mode transparent --listen-port 0 --set confdir="${MITMPROXY_CA_DIR}" &
    MITM_PID=$!

    for i in {1..30}; do
        if [[ -f "${MITMPROXY_CA_CERT}" ]]; then
            log "CA certificate generated successfully"
            kill "${MITM_PID}" 2>/dev/null || true
            wait "${MITM_PID}" 2>/dev/null || true
            return 0
        fi
        sleep 0.5
    done

    log "ERROR: Failed to generate CA certificate within 15 seconds"
    kill "${MITM_PID}" 2>/dev/null || true
    return 1
}

copy_ca_to_shared_volume() {
    if [[ ! -d "${SHARED_CERTS_DIR}" ]]; then
        log "ERROR: Shared certs directory ${SHARED_CERTS_DIR} not mounted"
        return 1
    fi

    cp "${MITMPROXY_CA_CERT}" "${SHARED_CERTS_DIR}/mitmproxy-ca.pem"
    log "CA certificate copied to ${SHARED_CERTS_DIR}/mitmproxy-ca.pem"
}

verify_addon() {
    if [[ ! -f "${ADDON_PATH}" ]]; then
        log "ERROR: Credential injection addon not found at ${ADDON_PATH}"
        return 1
    fi
    log "Credential injection addon found"

    if [[ ! -f "${GITHUB_FILTER_PATH}" ]]; then
        log "ERROR: GitHub API filter addon not found at ${GITHUB_FILTER_PATH}"
        return 1
    fi
    log "GitHub API filter addon found"
}

disable_missing_auth_file() {
    local var_name="$1"
    local auth_path="${!var_name:-}"

    if [[ -n "${auth_path}" && ! -f "${auth_path}" ]]; then
        log "Auth file ${auth_path} not found; disabling ${var_name}"
        unset "${var_name}"
    fi
}

start_mitmproxy() {
    local mode="${PROXY_MODE:-regular}"
    local log_level="${PROXY_LOG_LEVEL:-info}"
    log "Starting mitmproxy in ${mode} mode (web UI disabled)..."

    local args=(
        --mode "${mode}"
        --listen-port 8080
        --set confdir="${MITMPROXY_CA_DIR}"
        --set block_global=false
        --set connection_strategy=lazy
        -s "${GITHUB_FILTER_PATH}"
        -s "${ADDON_PATH}"
    )

    if [[ "${log_level}" == "debug" ]]; then
        args+=(--set flow_detail=3)
    fi

    log "mitmproxy args: ${args[*]}"
    exec mitmdump "${args[@]}"
}

main() {
    log "API Proxy starting..."

    if [[ ! -f "${MITMPROXY_CA_CERT}" ]]; then
        generate_ca_cert
    else
        log "Using existing CA certificate"
    fi

    copy_ca_to_shared_volume

    verify_addon
    disable_missing_auth_file CODEX_AUTH_FILE
    disable_missing_auth_file OPENCODE_AUTH_FILE
    disable_missing_auth_file GEMINI_OAUTH_FILE

    start_mitmproxy
}

main "$@"
