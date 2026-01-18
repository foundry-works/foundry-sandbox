#!/bin/bash
#
# Network Firewall for Limited Mode
#
# Sets up iptables rules to whitelist specific domains while blocking all
# other outbound traffic. Used in "limited" network mode.
#
# Whitelisted domains by default:
# - github.com, api.github.com (code hosting)
# - registry.npmjs.org (npm packages)
# - pypi.org, files.pythonhosted.org (Python packages)
# - api.anthropic.com (Claude API)
# - generativelanguage.googleapis.com (Gemini API)
# - api.openai.com (OpenAI API)
#

set -e

# Default whitelisted domains for AI development workflows
DEFAULT_DOMAINS=(
    # GitHub
    "github.com"
    "api.github.com"
    "raw.githubusercontent.com"
    "objects.githubusercontent.com"
    "codeload.github.com"

    # NPM Registry
    "registry.npmjs.org"

    # PyPI
    "pypi.org"
    "files.pythonhosted.org"

    # Go modules
    "proxy.golang.org"
    "sum.golang.org"

    # AI APIs
    "api.anthropic.com"
    "generativelanguage.googleapis.com"
    "api.openai.com"

    # Docker Hub (for pulling images if needed)
    "registry-1.docker.io"
    "auth.docker.io"
    "production.cloudflare.docker.com"
)

# Parse additional domains from environment variable
EXTRA_DOMAINS=()
if [ -n "$SANDBOX_ALLOWED_DOMAINS" ]; then
    IFS=',' read -ra EXTRA_DOMAINS <<< "$SANDBOX_ALLOWED_DOMAINS"
fi

# Combine default and extra domains
ALL_DOMAINS=("${DEFAULT_DOMAINS[@]}" "${EXTRA_DOMAINS[@]}")

echo "Setting up firewall for limited network mode..."
echo "Whitelisted domains: ${ALL_DOMAINS[*]}"

# Flush existing OUTPUT rules
iptables -F OUTPUT

# Allow loopback traffic
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections (responses to allowed outbound)
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow DNS queries only to Docker gateway (prevents DNS exfiltration)
# Resolve gateway first (needed for DNS rules)
GATEWAY=$(ip route | grep default | awk '{print $3}' || true)
if [ -n "$GATEWAY" ]; then
    echo "  Restricting DNS to Docker gateway: $GATEWAY"
    iptables -A OUTPUT -p udp --dport 53 -d "$GATEWAY" -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d "$GATEWAY" -j ACCEPT
    # Block DNS to all other destinations
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP
else
    echo "  Warning: Could not determine gateway, allowing all DNS"
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
fi

# Function to resolve domain and add rules
allow_domain() {
    local domain="$1"
    echo "  Allowing: $domain"

    # Resolve domain to IP addresses (may return multiple)
    local ips
    ips=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' || true)

    # Also try AAAA records for IPv6
    local ipv6s
    ipv6s=$(dig +short "$domain" AAAA 2>/dev/null | grep -E '^[0-9a-f:]+' || true)

    if [ -z "$ips" ] && [ -z "$ipv6s" ]; then
        echo "    Warning: Could not resolve $domain"
        return
    fi

    # Add rules for each resolved IP
    for ip in $ips; do
        iptables -A OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || true
    done

    # Add rules for IPv6 if ip6tables is available
    if command -v ip6tables &>/dev/null; then
        for ip in $ipv6s; do
            ip6tables -A OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || true
        done
    fi
}

# Allow traffic to whitelisted domains
for domain in "${ALL_DOMAINS[@]}"; do
    allow_domain "$domain"
done

# Allow Docker gateway (for host communication)
# Note: GATEWAY was already resolved earlier for DNS rules
if [ -n "$GATEWAY" ]; then
    echo "  Allowing Docker gateway: $GATEWAY"
    iptables -A OUTPUT -d "$GATEWAY" -j ACCEPT
fi

# Drop all other outbound traffic
iptables -A OUTPUT -j DROP

# Also set up IPv6 rules if available
if command -v ip6tables &>/dev/null; then
    ip6tables -F OUTPUT 2>/dev/null || true
    ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    ip6tables -A OUTPUT -j DROP 2>/dev/null || true
fi

echo "Firewall rules applied successfully."
echo "Allowed: ${#ALL_DOMAINS[@]} domains + Docker gateway + DNS (gateway only) + loopback"
echo "All other outbound traffic is blocked."
