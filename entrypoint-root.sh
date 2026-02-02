#!/bin/bash
# Root entrypoint wrapper for credential isolation
# Configures DNS before dropping privileges to the sandbox user
#
# This script runs as root to write /etc/resolv.conf (read-only filesystem)
# then exec's to the regular entrypoint as the sandbox user.

set -e

# Get the target user (default: ubuntu)
TARGET_USER="${SANDBOX_USER:-ubuntu}"

# Configure DNS to use gateway's dnsmasq when in gateway mode
# Must run as root because /etc/resolv.conf is read-only for non-root
if [ "$SANDBOX_GATEWAY_ENABLED" = "true" ]; then
    echo "Configuring DNS to use gateway (as root)..."

    # IMPORTANT: Resolve internal service IPs using Docker's DNS BEFORE changing resolv.conf
    # This is needed because gateway's dnsmasq returns the wrong IP for multi-homed containers
    # (returns proxy-egress network IP instead of credential-isolation network IP)
    GATEWAY_IP=$(getent hosts gateway | awk '{print $1}' | head -1)
    API_PROXY_IP=$(getent hosts api-proxy | awk '{print $1}' | head -1)

    if [ -n "$GATEWAY_IP" ]; then
        echo "Gateway IP: $GATEWAY_IP"

        # Add internal services to /etc/hosts so they resolve correctly
        # /etc/hosts takes precedence over DNS, ensuring we use the right network IPs
        echo "Adding internal services to /etc/hosts..."
        echo "$GATEWAY_IP gateway" >> /etc/hosts
        if [ -n "$API_PROXY_IP" ]; then
            echo "API Proxy IP: $API_PROXY_IP"
            echo "$API_PROXY_IP api-proxy" >> /etc/hosts
        fi

        # Now configure resolv.conf to use gateway's dnsmasq for external domains
        # External domains will be filtered by the allowlist
        echo "nameserver $GATEWAY_IP" > /etc/resolv.conf
        echo "DNS configured to use gateway at $GATEWAY_IP"

        # Block DNS bypass - only allow DNS to gateway
        # This prevents dig @8.8.8.8 and similar direct DNS queries to external resolvers
        echo "Setting up DNS firewall rules..."
        iptables -A OUTPUT -p udp --dport 53 -d "$GATEWAY_IP" -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -d "$GATEWAY_IP" -j ACCEPT
        # Block DNS to all other destinations
        iptables -A OUTPUT -p udp --dport 53 -j DROP
        iptables -A OUTPUT -p tcp --dport 53 -j DROP
        echo "DNS firewall rules applied"
        # Note: /proc/kcore masking requires SYS_ADMIN (too dangerous to grant)
        # Network isolation (internal: true) is the primary security boundary
    else
        echo "Warning: Could not resolve gateway hostname, using default DNS"
    fi
fi

# Drop privileges and run the regular entrypoint
exec gosu "$TARGET_USER" /usr/local/bin/entrypoint.sh "$@"
