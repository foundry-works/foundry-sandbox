#!/bin/bash
# Root entrypoint wrapper for credential isolation
# Configures DNS before dropping privileges to the sandbox user
#
# This script runs as root to write /etc/resolv.conf (read-only filesystem)
# then exec's to the regular entrypoint as the sandbox user.

set -e

# Get the target user (default: ubuntu)
TARGET_USER="${SANDBOX_USER:-ubuntu}"

# Configure DNS to use unified-proxy when in credential isolation mode
# Must run as root because /etc/resolv.conf is read-only for non-root
if [ "$SANDBOX_GATEWAY_ENABLED" = "true" ]; then
    echo "Configuring DNS to use unified-proxy (as root)..."

    # IMPORTANT: Resolve internal service IPs using Docker's DNS BEFORE changing resolv.conf
    # unified-proxy is multi-homed (internal + egress), so we pin the internal IP
    PROXY_IP=$(getent hosts unified-proxy | awk '{print $1}' | head -1)

    if [ -n "$PROXY_IP" ]; then
        echo "Unified proxy IP: $PROXY_IP"

        # Add internal service to /etc/hosts so it resolves correctly
        # /etc/hosts takes precedence over DNS, ensuring we use the right network IP
        echo "Adding internal services to /etc/hosts..."
        echo "$PROXY_IP unified-proxy" >> /etc/hosts

        # Configure resolv.conf to use unified-proxy DNS filter
        # External domains will be filtered by the allowlist
        echo "nameserver $PROXY_IP" > /etc/resolv.conf
        echo "DNS configured to use unified-proxy at $PROXY_IP"

        # Block DNS bypass - only allow DNS to unified-proxy
        # This prevents dig @8.8.8.8 and similar direct DNS queries to external resolvers
        echo "Setting up DNS firewall rules..."
        iptables -A OUTPUT -p udp --dport 53 -d "$PROXY_IP" -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -d "$PROXY_IP" -j ACCEPT
        # Block DNS to all other destinations
        iptables -A OUTPUT -p udp --dport 53 -j DROP
        iptables -A OUTPUT -p tcp --dport 53 -j DROP
        echo "DNS firewall rules applied"
        # Note: /proc/kcore masking requires SYS_ADMIN (too dangerous to grant)
        # Network isolation (internal: true) is the primary security boundary
    else
        echo "Warning: Could not resolve unified-proxy hostname, using default DNS"
    fi
fi

# Add mitmproxy CA to system trust store (must run as root)
# This is needed for git (which uses GnuTLS and the system CA bundle)
if [ -f "/certs/mitmproxy-ca.pem" ]; then
    echo "Adding mitmproxy CA to system trust store..."
    cp "/certs/mitmproxy-ca.pem" "/usr/local/share/ca-certificates/mitmproxy-ca.crt" 2>/dev/null || true
    update-ca-certificates >/dev/null 2>&1 || true
fi

# Drop privileges and run the regular entrypoint
exec gosu "$TARGET_USER" /usr/local/bin/entrypoint.sh "$@"
