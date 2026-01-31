#!/bin/bash
# Entrypoint script for credential isolation gateway
# Starts dnsmasq for DNS routing and Gunicorn bound to both TCP and Unix socket

set -e

# Create Unix socket directory with proper permissions
SOCKET_DIR="/var/run/gateway"
SOCKET_PATH="${SOCKET_DIR}/gateway.sock"

echo "Creating socket directory: ${SOCKET_DIR}"
mkdir -p "${SOCKET_DIR}"
chmod 755 "${SOCKET_DIR}"

# Start dnsmasq for DNS routing (if configured)
# This allows the gateway to control DNS resolution for sandboxed containers
if [ -f /etc/dnsmasq.conf ]; then
    echo "Starting dnsmasq for DNS routing..."
    dnsmasq --keep-in-foreground &
    DNSMASQ_PID=$!
    echo "dnsmasq started with PID: ${DNSMASQ_PID}"
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
