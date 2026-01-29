#!/bin/bash
#
# Credential Proxy Initialization
#
# Configures the sandbox to route API traffic through the credential isolation
# proxy. Installs CA certificate, sets up iptables rules, and configures
# environment variables for CA trust.
#
# Requires: CREDENTIAL_ISOLATION=1 environment variable to enable
# Expects: CA certificate at /certs/mitmproxy-ca.pem (from shared volume)
#

set -euo pipefail

SHARED_CA_PATH="/certs/mitmproxy-ca.pem"
SYSTEM_CA_DIR="/usr/local/share/ca-certificates"
SYSTEM_CA_NAME="mitmproxy-ca.crt"
PROXY_PORT="${CREDENTIAL_PROXY_PORT:-8080}"

log() {
    echo "[credential-proxy-init] $*"
}

log_error() {
    echo "[credential-proxy-init] ERROR: $*" >&2
}

check_enabled() {
    if [[ "${CREDENTIAL_ISOLATION:-0}" != "1" ]]; then
        log "CREDENTIAL_ISOLATION not set, skipping proxy init"
        return 1
    fi
    return 0
}

wait_for_ca_cert() {
    local max_wait=30
    local waited=0

    log "Waiting for CA certificate at ${SHARED_CA_PATH}..."

    while [[ ! -f "${SHARED_CA_PATH}" ]]; do
        if [[ $waited -ge $max_wait ]]; then
            log_error "CA certificate not found after ${max_wait} seconds"
            return 1
        fi
        sleep 1
        ((waited++))
    done

    log "CA certificate found"
}

install_system_ca() {
    log "Installing CA certificate to system trust store..."

    if [[ ! -d "${SYSTEM_CA_DIR}" ]]; then
        mkdir -p "${SYSTEM_CA_DIR}"
    fi

    cp "${SHARED_CA_PATH}" "${SYSTEM_CA_DIR}/${SYSTEM_CA_NAME}"

    if command -v update-ca-certificates &>/dev/null; then
        update-ca-certificates
        log "System CA store updated"
    else
        log_error "update-ca-certificates not found, CA may not be trusted by all tools"
    fi
}

setup_environment_variables() {
    log "Setting up CA environment variables..."

    export NODE_EXTRA_CA_CERTS="${SHARED_CA_PATH}"
    export REQUESTS_CA_BUNDLE="${SHARED_CA_PATH}"
    export SSL_CERT_FILE="${SHARED_CA_PATH}"
    export CURL_CA_BUNDLE="${SHARED_CA_PATH}"

    log "Environment variables set:"
    log "  NODE_EXTRA_CA_CERTS=${NODE_EXTRA_CA_CERTS}"
    log "  REQUESTS_CA_BUNDLE=${REQUESTS_CA_BUNDLE}"
    log "  SSL_CERT_FILE=${SSL_CERT_FILE}"
    log "  CURL_CA_BUNDLE=${CURL_CA_BUNDLE}"
}

setup_iptables_redirect() {
    log "Configuring iptables to redirect HTTPS traffic to proxy..."

    if ! command -v iptables &>/dev/null; then
        log_error "iptables not found, cannot configure traffic redirection"
        return 1
    fi

    iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port "${PROXY_PORT}"
    log "TCP port 443 redirected to proxy port ${PROXY_PORT}"

    iptables -A OUTPUT -p udp --dport 443 -j DROP
    log "UDP port 443 blocked (QUIC disabled to force TCP)"
}

verify_setup() {
    log "Verifying credential proxy setup..."

    local errors=0

    if [[ ! -f "${SYSTEM_CA_DIR}/${SYSTEM_CA_NAME}" ]]; then
        log_error "CA certificate not installed to system store"
        ((errors++))
    fi

    if [[ -z "${NODE_EXTRA_CA_CERTS:-}" ]]; then
        log_error "NODE_EXTRA_CA_CERTS not set"
        ((errors++))
    fi

    if [[ -z "${REQUESTS_CA_BUNDLE:-}" ]]; then
        log_error "REQUESTS_CA_BUNDLE not set"
        ((errors++))
    fi

    if ! iptables -t nat -C OUTPUT -p tcp --dport 443 -j REDIRECT --to-port "${PROXY_PORT}" 2>/dev/null; then
        log_error "iptables REDIRECT rule not active"
        ((errors++))
    fi

    if ! iptables -C OUTPUT -p udp --dport 443 -j DROP 2>/dev/null; then
        log_error "iptables UDP DROP rule not active"
        ((errors++))
    fi

    if [[ $errors -gt 0 ]]; then
        log_error "Verification failed with ${errors} error(s)"
        return 1
    fi

    log "Verification passed - credential proxy is active"
}

main() {
    if ! check_enabled; then
        return 0
    fi

    log "Initializing credential proxy..."

    wait_for_ca_cert
    install_system_ca
    setup_environment_variables
    setup_iptables_redirect
    verify_setup

    log "Credential proxy initialization complete"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
