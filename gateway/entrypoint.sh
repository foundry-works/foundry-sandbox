#!/bin/bash
# Entrypoint script for credential isolation gateway
# Starts dnsmasq for DNS routing (as root) and Gunicorn bound to both TCP and Unix socket (as appuser)

set -e

# Create Unix socket directory with proper permissions
SOCKET_DIR="/var/run/gateway"
SOCKET_PATH="${SOCKET_DIR}/gateway.sock"
RUN_USER="${GATEWAY_USER:-appuser}"

echo "Creating socket directory: ${SOCKET_DIR}"
mkdir -p "${SOCKET_DIR}"
chmod 755 "${SOCKET_DIR}"
chown "${RUN_USER}:${RUN_USER}" "${SOCKET_DIR}" 2>/dev/null || true

# Start dnsmasq for DNS routing (if configured)
# This allows the gateway to control DNS resolution for sandboxed containers
# dnsmasq needs to bind to port 53, which requires root privileges
# It will drop privileges after binding if configured with user= in dnsmasq.conf
if [ -f /etc/dnsmasq.conf ] && [ "${GATEWAY_ENABLE_DNS:-false}" = "true" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        echo "Starting dnsmasq for DNS routing..."
        dnsmasq --keep-in-foreground &
        DNSMASQ_PID=$!
        echo "dnsmasq started with PID: ${DNSMASQ_PID}"
    else
        echo "WARNING: dnsmasq requires root privileges to bind port 53, skipping DNS routing"
        echo "To enable DNS routing, run the container with GATEWAY_ENABLE_DNS=true and as root"
    fi
else
    echo "DNS routing disabled (set GATEWAY_ENABLE_DNS=true to enable)"
fi

# Cleanup function for graceful shutdown
cleanup() {
    echo "Shutting down gateway services..."

    # Stop dnsmasq if running
    if [ -n "${DNSMASQ_PID:-}" ] && kill -0 "${DNSMASQ_PID}" 2>/dev/null; then
        echo "Stopping dnsmasq (PID: ${DNSMASQ_PID})..."
        kill -TERM "${DNSMASQ_PID}" 2>/dev/null || true
        wait "${DNSMASQ_PID}" 2>/dev/null || true
    fi

    # Remove socket file
    if [ -S "${SOCKET_PATH}" ]; then
        echo "Removing socket file: ${SOCKET_PATH}"
        rm -f "${SOCKET_PATH}"
    fi

    echo "Gateway shutdown complete"
    exit 0
}

# Register cleanup handler for graceful shutdown
trap cleanup SIGTERM SIGINT SIGQUIT

# Start Gunicorn bound to BOTH TCP port and Unix socket
# - TCP 8080: For external HTTP traffic (git operations)
# - Unix socket: For local session management (create/destroy)
# Using single worker to ensure session store consistency (Issue #4)
echo "Starting Gunicorn on TCP :8080 and Unix socket ${SOCKET_PATH}..."

# If running as root, drop privileges to appuser for Gunicorn
# This provides defense-in-depth: dnsmasq runs as root (for port 53),
# but the main application runs as non-root
if [ "$(id -u)" -eq 0 ] && command -v gosu >/dev/null 2>&1; then
    echo "Dropping privileges to user: ${RUN_USER}"
    exec gosu "${RUN_USER}" gunicorn \
        --bind "0.0.0.0:8080" \
        --bind "unix:${SOCKET_PATH}" \
        --workers 1 \
        --worker-class sync \
        --timeout 60 \
        --access-logfile - \
        --error-logfile - \
        --capture-output \
        gateway:app
else
    exec gunicorn \
        --bind "0.0.0.0:8080" \
        --bind "unix:${SOCKET_PATH}" \
        --workers 1 \
        --worker-class sync \
        --timeout 60 \
        --access-logfile - \
        --error-logfile - \
        --capture-output \
        gateway:app
fi
