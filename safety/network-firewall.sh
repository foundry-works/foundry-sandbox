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

# Helper function to log only when SANDBOX_DEBUG=1
log_verbose() {
    [ "$SANDBOX_DEBUG" = "1" ] && echo "$@" || true
}

# Domains that use load balancer IP rotation (resolve multiple times)
# NOTE: This array is defined early so it's available for refresh_rotating_ips()
ROTATING_IP_DOMAINS=(
    "api2.cursor.sh"
    "api3.cursor.sh"
    "api4.cursor.sh"
    "api5.cursor.sh"
    "api6.cursor.sh"
    "api7.cursor.sh"
    "api8.cursor.sh"
)

# Function to refresh rotating domain IPs (can be called separately)
# NOTE: Defined early so we can exit early when called with "refresh"
refresh_rotating_ips() {
    log_verbose "Refreshing IPs for rotating domains..."
    for domain in "${ROTATING_IP_DOMAINS[@]}"; do
        log_verbose "  Refreshing: $domain"
        for i in {1..5}; do
            local ips
            ips=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' || true)
            for ip in $ips; do
                if command -v ipset &>/dev/null && ipset list sandbox_allow_v4 &>/dev/null; then
                    ipset add -exist sandbox_allow_v4 "$ip" 2>/dev/null || true
                else
                    # Add rule if not already present (iptables will just fail silently on duplicate)
                    iptables -C OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || \
                        iptables -I OUTPUT -d "$ip" -j ACCEPT 2>/dev/null || true
                fi
            done
            sleep 0.2
        done
    done
    log_verbose "Refresh complete."
}

# Handle refresh-only mode (must come before full setup)
# This avoids resolving rotating domains twice when called from attach.sh
if [ "${1:-}" = "refresh" ]; then
    refresh_rotating_ips
    exit 0
fi

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
    "auth0.openai.com"
    "platform.openai.com"
    "chatgpt.com"

    # Claude Code OAuth
    "claude.ai"
    "console.anthropic.com"

    # Google OAuth (needed for Gemini CLI auth)
    "accounts.google.com"
    "oauth2.googleapis.com"

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

log_verbose "Setting up firewall for limited network mode..."
log_verbose "Whitelisted domains: ${ALL_DOMAINS[*]}"

# Initialize ipset allowlists if available
if command -v ipset &>/dev/null; then
    if ipset create "$IPSET_V4" hash:ip family inet maxelem 65535 -exist 2>/dev/null && \
       ipset create "$IPSET_V6" hash:ip family inet6 maxelem 65535 -exist 2>/dev/null; then
        ipset flush "$IPSET_V4" 2>/dev/null || true
        ipset flush "$IPSET_V6" 2>/dev/null || true
        if iptables -I OUTPUT -m set --match-set "$IPSET_V4" dst -j ACCEPT 2>/dev/null; then
            iptables -D OUTPUT -m set --match-set "$IPSET_V4" dst -j ACCEPT 2>/dev/null || true
            USE_IPSET=true
            log_verbose "Using ipset allowlists."
        else
            log_verbose "Warning: ipset kernel match unavailable, falling back to per-IP iptables rules."
            ipset destroy "$IPSET_V4" "$IPSET_V6" 2>/dev/null || true
        fi
    else
        log_verbose "Warning: ipset unavailable, falling back to per-IP iptables rules."
    fi
else
    log_verbose "Warning: ipset not installed, falling back to per-IP iptables rules."
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
    log_verbose "  Restricting DNS to resolvers: ${DNS_SERVERS_V4[*]} ${DNS_SERVERS_V6[*]}"
    for dns in "${DNS_SERVERS_V4[@]}"; do
        iptables -A OUTPUT -p udp --dport 53 -d "$dns" -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -d "$dns" -j ACCEPT
    done
    # Block DNS to all other IPv4 destinations
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP
elif [ -n "$GATEWAY" ]; then
    log_verbose "  Restricting DNS to Docker gateway: $GATEWAY"
    iptables -A OUTPUT -p udp --dport 53 -d "$GATEWAY" -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d "$GATEWAY" -j ACCEPT
    # Block DNS to all other destinations
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP
else
    log_verbose "  Warning: Could not determine resolvers or gateway, allowing all DNS"
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
fi

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

# GitHub IP ranges (from https://api.github.com/meta)
# Covers web, api, git, and pages endpoints
GITHUB_CIDRS=(
    "140.82.112.0/20"    # Primary GitHub servers
    "192.30.252.0/22"    # Legacy GitHub
    "185.199.108.0/22"   # GitHub Pages / raw content
    "143.55.64.0/20"     # Additional infrastructure
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
    log_verbose "  Allowing: $domain"

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
        log_verbose "    (rotating IP domain - resolving multiple times)"
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
        log_verbose "    Added $ip_count unique IPs"
    else
        # Standard single resolution
        local ips
        ips=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' || true)

        # Also try AAAA records for IPv6
        local ipv6s
        ipv6s=$(dig +short "$domain" AAAA 2>/dev/null | grep -E '^[0-9a-f:]+' || true)

        if [ -z "$ips" ] && [ -z "$ipv6s" ]; then
            log_verbose "    Warning: Could not resolve $domain"
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
log_verbose "  Adding known IPs (non-DNS resolved)..."
for ip in "${KNOWN_IPS[@]}"; do
    add_ip_rule "$ip"
    log_verbose "    Added: $ip"
done

# Allow Cloudflare IP ranges (Cursor uses CF as proxy)
log_verbose "  Adding Cloudflare CIDR ranges..."
for cidr in "${CLOUDFLARE_CIDRS[@]}"; do
    add_cidr_rule "$cidr"
done
log_verbose "    Added ${#CLOUDFLARE_CIDRS[@]} Cloudflare CIDR blocks"

# Allow GitHub IP ranges
log_verbose "  Adding GitHub CIDR ranges..."
for cidr in "${GITHUB_CIDRS[@]}"; do
    add_cidr_rule "$cidr"
done
log_verbose "    Added ${#GITHUB_CIDRS[@]} GitHub CIDR blocks"

# Allow Docker gateway (for host communication)
# Note: GATEWAY was already resolved earlier for DNS rules
if [ -n "$GATEWAY" ]; then
    log_verbose "  Allowing Docker gateway: $GATEWAY"
    iptables -A OUTPUT -d "$GATEWAY" -j ACCEPT
fi

# ============================================================================
# Sandbox Isolation Rules (defense-in-depth)
# ============================================================================
# These rules complement ICC=false on the credential-isolation network.
# They explicitly allow sandbox -> gateway and sandbox -> api-proxy
# while ensuring sandbox -> sandbox is blocked.
#
# Container names are resolved via Docker DNS when running inside the network.
# ============================================================================

# Allow traffic to credential-isolation gateway (for git operations)
# The gateway holds GitHub credentials and proxies git requests
if [ -n "${GATEWAY_HOST:-}" ]; then
    GATEWAY_IP=$(getent hosts "$GATEWAY_HOST" 2>/dev/null | awk '{print $1}' || true)
    if [ -n "$GATEWAY_IP" ]; then
        log_verbose "  Allowing credential gateway: $GATEWAY_HOST ($GATEWAY_IP)"
        iptables -A OUTPUT -d "$GATEWAY_IP" -j ACCEPT
    fi
elif getent hosts gateway &>/dev/null; then
    GATEWAY_IP=$(getent hosts gateway | awk '{print $1}')
    log_verbose "  Allowing credential gateway: gateway ($GATEWAY_IP)"
    iptables -A OUTPUT -d "$GATEWAY_IP" -j ACCEPT
fi

# Allow traffic to api-proxy (for HTTPS API requests)
# The api-proxy holds API credentials and injects them into requests
if [ -n "${API_PROXY_HOST:-}" ]; then
    API_PROXY_IP=$(getent hosts "$API_PROXY_HOST" 2>/dev/null | awk '{print $1}' || true)
    if [ -n "$API_PROXY_IP" ]; then
        log_verbose "  Allowing API proxy: $API_PROXY_HOST ($API_PROXY_IP)"
        iptables -A OUTPUT -d "$API_PROXY_IP" -j ACCEPT
    fi
elif getent hosts api-proxy &>/dev/null; then
    API_PROXY_IP=$(getent hosts api-proxy | awk '{print $1}')
    log_verbose "  Allowing API proxy: api-proxy ($API_PROXY_IP)"
    iptables -A OUTPUT -d "$API_PROXY_IP" -j ACCEPT
fi

# Note: Sandbox-to-sandbox blocking is handled by ICC=false on the
# credential-isolation network. These iptables rules are defense-in-depth.

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

# ============================================================================
# DOCKER-USER Chain Rules (host-level defense-in-depth)
# ============================================================================
# The DOCKER-USER chain is processed BEFORE Docker's own rules for FORWARD
# traffic. These rules provide host-level enforcement that cannot be bypassed
# by container configuration.
#
# Use case: Run on the Docker host to enforce network isolation even if
# container networking is misconfigured.
# ============================================================================

setup_docker_user_rules() {
    log_verbose "Setting up DOCKER-USER chain rules..."

    # Get the credential-isolation network subnet (if available)
    local SANDBOX_SUBNET=""
    if command -v docker &>/dev/null; then
        SANDBOX_SUBNET=$(docker network inspect credential-isolation --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true)
    fi

    # Get gateway container IP
    local GATEWAY_CONTAINER_IP=""
    if command -v docker &>/dev/null; then
        GATEWAY_CONTAINER_IP=$(docker inspect gateway --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null | head -1 || true)
    fi

    # Get api-proxy container IP
    local API_PROXY_CONTAINER_IP=""
    if command -v docker &>/dev/null; then
        API_PROXY_CONTAINER_IP=$(docker inspect api-proxy --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null | head -1 || true)
    fi

    if [ -z "$SANDBOX_SUBNET" ]; then
        log_verbose "  Warning: Could not determine sandbox subnet, skipping DOCKER-USER rules"
        return
    fi

    log_verbose "  Sandbox subnet: $SANDBOX_SUBNET"
    log_verbose "  Gateway IP: ${GATEWAY_CONTAINER_IP:-unknown}"
    log_verbose "  API Proxy IP: ${API_PROXY_CONTAINER_IP:-unknown}"

    # Flush existing DOCKER-USER rules (but keep the default RETURN)
    iptables -F DOCKER-USER 2>/dev/null || true

    # Allow established connections
    iptables -I DOCKER-USER -m state --state ESTABLISHED,RELATED -j RETURN

    # Allow sandbox -> gateway (for git operations)
    if [ -n "$GATEWAY_CONTAINER_IP" ]; then
        iptables -I DOCKER-USER -s "$SANDBOX_SUBNET" -d "$GATEWAY_CONTAINER_IP" -j RETURN
        log_verbose "  Allowing sandbox -> gateway ($GATEWAY_CONTAINER_IP)"
    fi

    # Allow sandbox -> api-proxy (for HTTPS API requests)
    if [ -n "$API_PROXY_CONTAINER_IP" ]; then
        iptables -I DOCKER-USER -s "$SANDBOX_SUBNET" -d "$API_PROXY_CONTAINER_IP" -j RETURN
        log_verbose "  Allowing sandbox -> api-proxy ($API_PROXY_CONTAINER_IP)"
    fi

    # Allow DNS (port 53) only to gateway (for dnsmasq)
    if [ -n "$GATEWAY_CONTAINER_IP" ]; then
        iptables -I DOCKER-USER -s "$SANDBOX_SUBNET" -d "$GATEWAY_CONTAINER_IP" -p udp --dport 53 -j RETURN
        iptables -I DOCKER-USER -s "$SANDBOX_SUBNET" -d "$GATEWAY_CONTAINER_IP" -p tcp --dport 53 -j RETURN
        log_verbose "  Allowing DNS to gateway only"
    fi

    # Block all other DNS from sandbox (prevent DNS bypass)
    iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -p udp --dport 53 -j DROP
    iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -p tcp --dport 53 -j DROP
    log_verbose "  Blocking DNS to non-gateway destinations"

    # Block direct egress from sandbox to external networks
    # (traffic should go through gateway or api-proxy)
    iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" ! -d 172.16.0.0/12 -j DROP
    log_verbose "  Blocking direct external egress from sandbox"

    # Final RETURN for other traffic (Docker's default behavior)
    iptables -A DOCKER-USER -j RETURN

    log_verbose "  DOCKER-USER rules applied"
}

# Only run DOCKER-USER setup if we're on the host (have docker access)
# and explicitly requested via SETUP_DOCKER_USER=1
if [ "${SETUP_DOCKER_USER:-}" = "1" ] && command -v docker &>/dev/null; then
    setup_docker_user_rules
fi

log_verbose "Firewall rules applied successfully."
log_verbose "Allowed: ${#ALL_DOMAINS[@]} domains + ${#CLOUDFLARE_CIDRS[@]} Cloudflare CIDRs + ${#GITHUB_CIDRS[@]} GitHub CIDRs + Docker gateway + DNS (resolvers/gateway) + loopback"
log_verbose "All other outbound traffic is blocked."
