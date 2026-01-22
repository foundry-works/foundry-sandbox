#!/bin/bash
#
# Network Firewall for Limited Mode
#
# Sets up iptables rules to whitelist specific domains while blocking all
# other outbound traffic. Used in "limited" network mode.
#
# Whitelisted domains by default:
# - GitHub: github.com, api.github.com, gist.github.com, etc.
# - Package registries: npm, pypi, go, cargo
# - AI APIs: Anthropic, OpenAI, Google (Gemini)
# - AI Tools: Cursor
# - Research: Tavily, Perplexity, Semantic Scholar, Google CSE
# - Docker Hub
#
# Add custom domains via: SANDBOX_ALLOWED_DOMAINS="domain1.com,domain2.com"
#

set -e

# Use ipset for efficient allowlists when available.
IPSET_V4="sandbox_allow_v4"
IPSET_V6="sandbox_allow_v6"
USE_IPSET=false

# Default whitelisted domains for AI development workflows
DEFAULT_DOMAINS=(
    # GitHub
    "github.com"
    "api.github.com"
    "raw.githubusercontent.com"
    "objects.githubusercontent.com"
    "codeload.github.com"
    "gist.github.com"
    "gist.githubusercontent.com"

    # NPM Registry
    "registry.npmjs.org"

    # PyPI
    "pypi.org"
    "files.pythonhosted.org"

    # Go modules
    "proxy.golang.org"
    "sum.golang.org"

    # Rust/Cargo
    "crates.io"
    "static.crates.io"

    # AI Provider APIs (major)
    "api.anthropic.com"
    "generativelanguage.googleapis.com"
    "api.openai.com"

    # OpenAI OAuth (needed for Codex CLI)
    "auth.openai.com"
    "auth.openai.com"
    "platform.openai.com"
    "chatgpt.com"

    # Claude Code OAuth
    "claude.ai"
    "console.anthropic.com"

    # Google OAuth (needed for Gemini CLI auth)
    "accounts.google.com"
    "oauth2.googleapis.com"

    # Azure OpenAI
    "openai.azure.com"
    "cognitiveservices.azure.com"

    # AI Provider APIs (alternative)
    "api.groq.com"
    "api.mistral.ai"
    "api.deepseek.com"
    "api.together.xyz"
    "api.cohere.com"
    "api.fireworks.ai"
    "openrouter.ai"

    # Z.AI / Zhipu (GLM models)
    "api.z.ai"
    "open.bigmodel.cn"

    # AI Coding Tools - Cursor (expanded)
    "cursor.com"
    "www.cursor.com"
    "api.cursor.com"
    "api2.cursor.sh"
    "api3.cursor.sh"
    "api4.cursor.sh"
    "api5.cursor.sh"
    "api6.cursor.sh"
    "api7.cursor.sh"
    "api8.cursor.sh"
    "agent.api5.cursor.sh"
    "www2.cursor.sh"
    "authenticate.cursor.sh"
    "authenticator.cursor.sh"
    "prod.authentication.cursor.sh"
    "us-asia.gcpp.cursor.sh"
    "us-eu.gcpp.cursor.sh"
    "us-only.gcpp.cursor.sh"
    "repo42.cursor.sh"
    "marketplace.cursorapi.com"
    "cursor-cdn.com"
    "downloads.cursor.com"
    "download.todesktop.com"
    "opencode.ai"
    "models.dev"
    "opncd.ai"
    "api.githubcopilot.com"

    # Deep Research APIs (content extraction handled server-side)
    "api.tavily.com"
    "api.perplexity.ai"
    "api.semanticscholar.org"
    "www.googleapis.com"

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

# Initialize ipset allowlists if available
if command -v ipset &>/dev/null; then
    if ipset create "$IPSET_V4" hash:ip family inet maxelem 65535 -exist 2>/dev/null && \
       ipset create "$IPSET_V6" hash:ip family inet6 maxelem 65535 -exist 2>/dev/null; then
        ipset flush "$IPSET_V4" 2>/dev/null || true
        ipset flush "$IPSET_V6" 2>/dev/null || true
        if iptables -I OUTPUT -m set --match-set "$IPSET_V4" dst -j ACCEPT 2>/dev/null; then
            iptables -D OUTPUT -m set --match-set "$IPSET_V4" dst -j ACCEPT 2>/dev/null || true
            USE_IPSET=true
            echo "Using ipset allowlists."
        else
            echo "Warning: ipset kernel match unavailable, falling back to per-IP iptables rules."
            ipset destroy "$IPSET_V4" "$IPSET_V6" 2>/dev/null || true
        fi
    else
        echo "Warning: ipset unavailable, falling back to per-IP iptables rules."
    fi
else
    echo "Warning: ipset not installed, falling back to per-IP iptables rules."
fi

# Flush existing OUTPUT rules
iptables -F OUTPUT

# Allow loopback traffic
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections (responses to allowed outbound)
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow DNS queries only to resolvers from /etc/resolv.conf (or gateway fallback).
# Resolve gateway first (needed for DNS rules)
GATEWAY=$(ip route | grep default | awk '{print $3}' || true)
DNS_SERVERS_V4=()
DNS_SERVERS_V6=()
declare -A DNS_SEEN_V4
declare -A DNS_SEEN_V6
DNS_LOOPBACK_ONLY=true

add_dns_server() {
    local ns="$1"
    [ -z "$ns" ] && return
    # Handle Docker Desktop format: host(192.168.65.7) -> 192.168.65.7
    local docker_dns_pattern='^host\(([^)]+)\)$'
    if [[ "$ns" =~ $docker_dns_pattern ]]; then
        ns="${BASH_REMATCH[1]}"
    fi
    if [[ "$ns" == *:* ]]; then
        if [ -z "${DNS_SEEN_V6[$ns]:-}" ]; then
            DNS_SERVERS_V6+=("$ns")
            DNS_SEEN_V6[$ns]=1
        fi
        if [ "$ns" != "::1" ] && [ "$ns" != "0:0:0:0:0:0:0:1" ]; then
            DNS_LOOPBACK_ONLY=false
        fi
    else
        if [ -z "${DNS_SEEN_V4[$ns]:-}" ]; then
            DNS_SERVERS_V4+=("$ns")
            DNS_SEEN_V4[$ns]=1
        fi
        case "$ns" in
            127.*) ;;
            *) DNS_LOOPBACK_ONLY=false ;;
        esac
    fi
}

if [ -f /etc/resolv.conf ]; then
    while IFS= read -r ns; do
        add_dns_server "$ns"
    done < <(awk '/^nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null | sort -u)

    # Docker resolv.conf exposes upstream DNS servers in a comment.
    while IFS= read -r ext; do
        for ns in $(echo "$ext" | tr ', ' '\n'); do
            add_dns_server "$ns"
        done
    done < <(awk -F'[][]' '/ExtServers:/ {print $2}' /etc/resolv.conf 2>/dev/null)
fi

if [ "$DNS_LOOPBACK_ONLY" = "true" ] && [ -n "$GATEWAY" ]; then
    add_dns_server "$GATEWAY"
fi

if [ ${#DNS_SERVERS_V4[@]} -gt 0 ] || [ ${#DNS_SERVERS_V6[@]} -gt 0 ]; then
    echo "  Restricting DNS to resolvers: ${DNS_SERVERS_V4[*]} ${DNS_SERVERS_V6[*]}"
    for dns in "${DNS_SERVERS_V4[@]}"; do
        iptables -A OUTPUT -p udp --dport 53 -d "$dns" -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -d "$dns" -j ACCEPT
    done
    # Block DNS to all other IPv4 destinations
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP
elif [ -n "$GATEWAY" ]; then
    echo "  Restricting DNS to Docker gateway: $GATEWAY"
    iptables -A OUTPUT -p udp --dport 53 -d "$GATEWAY" -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d "$GATEWAY" -j ACCEPT
    # Block DNS to all other destinations
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP
else
    echo "  Warning: Could not determine resolvers or gateway, allowing all DNS"
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
fi

# Domains that use load balancer IP rotation (resolve multiple times)
ROTATING_IP_DOMAINS=(
    "api2.cursor.sh"
    "api3.cursor.sh"
    "api4.cursor.sh"
    "api5.cursor.sh"
    "api6.cursor.sh"
    "api7.cursor.sh"
    "api8.cursor.sh"
)

# Known IPs for domains that don't resolve via public DNS
# (e.g., api5.cursor.sh uses hardcoded IPs in the agent binary)
KNOWN_IPS=(
    # Cursor Agent backends (AWS us-east-1)
    "44.197.141.31"   # api5.cursor.sh
    "184.73.249.78"   # api2.cursor.sh
)

# Cloudflare IP ranges (Cursor uses CF as proxy)
# Source: https://www.cloudflare.com/ips-v4
CLOUDFLARE_CIDRS=(
    "173.245.48.0/20"
    "103.21.244.0/22"
    "103.22.200.0/22"
    "103.31.4.0/22"
    "141.101.64.0/18"
    "108.162.192.0/18"
    "190.93.240.0/20"
    "188.114.96.0/20"
    "197.234.240.0/22"
    "198.41.128.0/17"
    "162.158.0.0/15"
    "104.16.0.0/13"
    "104.24.0.0/14"
    "172.64.0.0/13"
    "131.0.72.0/22"
)

# Track already-added IPs to avoid duplicates
declare -A ADDED_IPS

# Function to add a single IP to firewall (with deduplication)
add_ip_rule() {
    local ip="$1"
    if [ "$USE_IPSET" = "true" ]; then
        ipset add -exist "$IPSET_V4" "$ip" 2>/dev/null || true
        return 0
    fi
    if [ -z "${ADDED_IPS[$ip]:-}" ]; then
        iptables -A OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || true
        ADDED_IPS[$ip]=1
    fi
}

# Function to add a single IPv6 to firewall (with deduplication)
add_ipv6_rule() {
    local ip="$1"
    if [ "$USE_IPSET" = "true" ]; then
        ipset add -exist "$IPSET_V6" "$ip" 2>/dev/null || true
        return 0
    fi
    if command -v ip6tables &>/dev/null && [ -z "${ADDED_IPS[$ip]:-}" ]; then
        ip6tables -A OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || true
        ADDED_IPS[$ip]=1
    fi
}

# Function to add CIDR range to firewall
add_cidr_rule() {
    local cidr="$1"
    iptables -A OUTPUT -d "$cidr" -j ACCEPT 2>/dev/null || true
}

# Function to resolve domain and add rules
allow_domain() {
    local domain="$1"
    echo "  Allowing: $domain"

    # Check if this domain uses rotating IPs
    local is_rotating=false
    for rotating in "${ROTATING_IP_DOMAINS[@]}"; do
        if [ "$domain" = "$rotating" ]; then
            is_rotating=true
            break
        fi
    done

    if [ "$is_rotating" = true ]; then
        # Resolve multiple times to capture more IPs from the rotation pool
        echo "    (rotating IP domain - resolving multiple times)"
        local all_ips=""
        for i in {1..5}; do
            local ips
            ips=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' || true)
            all_ips="$all_ips $ips"
            sleep 0.2
        done
        # Deduplicate and add
        local unique_ips
        unique_ips=$(echo "$all_ips" | tr ' ' '\n' | sort -u | grep -E '^[0-9]+\.' || true)
        local ip_count=0
        for ip in $unique_ips; do
            add_ip_rule "$ip"
            ((ip_count++)) || true
        done
        echo "    Added $ip_count unique IPs"
    else
        # Standard single resolution
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
            add_ip_rule "$ip"
        done

        # Add rules for IPv6
        for ip in $ipv6s; do
            add_ipv6_rule "$ip"
        done
    fi
}

# Allow traffic to whitelisted domains
for domain in "${ALL_DOMAINS[@]}"; do
    allow_domain "$domain"
done

# Add known IPs that don't resolve via public DNS
echo "  Adding known IPs (non-DNS resolved)..."
for ip in "${KNOWN_IPS[@]}"; do
    add_ip_rule "$ip"
    echo "    Added: $ip"
done

# Allow Cloudflare IP ranges (Cursor uses CF as proxy)
echo "  Adding Cloudflare CIDR ranges..."
for cidr in "${CLOUDFLARE_CIDRS[@]}"; do
    add_cidr_rule "$cidr"
done
echo "    Added ${#CLOUDFLARE_CIDRS[@]} CIDR blocks"

# Allow Docker gateway (for host communication)
# Note: GATEWAY was already resolved earlier for DNS rules
if [ -n "$GATEWAY" ]; then
    echo "  Allowing Docker gateway: $GATEWAY"
    iptables -A OUTPUT -d "$GATEWAY" -j ACCEPT
fi

# Allow traffic to ipset allowlists
if [ "$USE_IPSET" = "true" ]; then
    iptables -A OUTPUT -m set --match-set "$IPSET_V4" dst -j ACCEPT
fi

# Drop all other outbound traffic
iptables -A OUTPUT -j DROP

# Also set up IPv6 rules if available
if command -v ip6tables &>/dev/null; then
    ip6tables -F OUTPUT 2>/dev/null || true
    ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    if [ ${#DNS_SERVERS_V6[@]} -gt 0 ]; then
        for dns in "${DNS_SERVERS_V6[@]}"; do
            ip6tables -A OUTPUT -p udp --dport 53 -d "$dns" -j ACCEPT 2>/dev/null || true
            ip6tables -A OUTPUT -p tcp --dport 53 -d "$dns" -j ACCEPT 2>/dev/null || true
        done
    fi
    if [ "$USE_IPSET" = "true" ]; then
        ip6tables -A OUTPUT -m set --match-set "$IPSET_V6" dst -j ACCEPT 2>/dev/null || true
    fi
    ip6tables -A OUTPUT -j DROP 2>/dev/null || true
fi

echo "Firewall rules applied successfully."
echo "Allowed: ${#ALL_DOMAINS[@]} domains + ${#CLOUDFLARE_CIDRS[@]} Cloudflare CIDRs + Docker gateway + DNS (resolvers/gateway) + loopback"
echo "All other outbound traffic is blocked."

# Function to refresh rotating domain IPs (can be called separately)
refresh_rotating_ips() {
    echo "Refreshing IPs for rotating domains..."
    for domain in "${ROTATING_IP_DOMAINS[@]}"; do
        echo "  Refreshing: $domain"
        for i in {1..5}; do
            local ips
            ips=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' || true)
            for ip in $ips; do
                if [ "$USE_IPSET" = "true" ]; then
                    ipset add -exist "$IPSET_V4" "$ip" 2>/dev/null || true
                else
                    # Add rule if not already present (iptables will just fail silently on duplicate)
                    iptables -C OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || \
                        iptables -I OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || true
                fi
            done
            sleep 0.2
        done
    done
    echo "Refresh complete."
}

# If called with "refresh" argument, just refresh rotating IPs
if [ "${1:-}" = "refresh" ]; then
    refresh_rotating_ips
fi
