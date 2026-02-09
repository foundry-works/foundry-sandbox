#!/bin/bash
# Root entrypoint wrapper for credential isolation
# Sets up DNS firewall rules before dropping privileges to the sandbox user.
#
# DNS configuration (resolv.conf, /etc/hosts) is handled at compose level
# via dns: and extra_hosts: directives, because Docker 29+ makes these
# files read-only when read_only:true is set.
#
# This script adds iptables rules for defense-in-depth (block DNS bypass),
# then exec's to the regular entrypoint as the sandbox user.

set -e

# Get the target user (default: ubuntu)
TARGET_USER="${SANDBOX_USER:-ubuntu}"

# Set up DNS firewall when in credential isolation mode
if [ "$SANDBOX_GATEWAY_ENABLED" = "true" ]; then
    # Resolve the proxy IP (DNS is pre-configured via compose dns:/extra_hosts:)
    PROXY_IP=$(getent hosts unified-proxy | awk '{print $1}' | head -1)

    if [ -n "$PROXY_IP" ]; then
        echo "Unified proxy IP: $PROXY_IP"

        # Block DNS bypass - only allow DNS to unified-proxy
        # This prevents dig @8.8.8.8 and similar direct DNS queries to external resolvers
        echo "Setting up DNS firewall rules..."
        iptables -A OUTPUT -p udp --dport 53 -d "$PROXY_IP" -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -d "$PROXY_IP" -j ACCEPT
        # Block DNS to all other destinations (including Docker's 127.0.0.11)
        iptables -A OUTPUT -p udp --dport 53 -j DROP
        iptables -A OUTPUT -p tcp --dport 53 -j DROP
        echo "DNS firewall rules applied"
    else
        echo "Warning: Could not resolve unified-proxy hostname, using default DNS"
    fi
fi

# Drop privileges and run the regular entrypoint
exec gosu "$TARGET_USER" /usr/local/bin/entrypoint.sh "$@"
