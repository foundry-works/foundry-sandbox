#!/bin/bash
#
# Network Firewall for Limited Mode
#
# Sets up iptables rules to whitelist specific domains while blocking all
# other outbound traffic. Used in "limited" network mode.
#
# Whitelisted domains by default (see gateway/allowlist.conf for full list):
# - GitHub: github.com, api.github.com, gist.github.com, etc.
# - AI APIs: Anthropic, OpenAI, Google (Gemini), Z.AI
# - AI Tools: OpenCode
# - Research: Tavily, Perplexity, Semantic Scholar
#
# Add custom domains via: SANDBOX_ALLOWED_DOMAINS="domain1.com,domain2.com"
#
# Wildcard Mode:
# ==============
# When wildcard domains (*.openai.com, etc.) are configured, the firewall
# opens ports 80/443 to any destination. Security is maintained through:
# 1. DNS filtering (dnsmasq only resolves allowlisted domains)
# 2. Gateway hostname validation (blocks requests to non-allowlisted hosts)
#
# For non-wildcard domains, IPs are resolved ONCE at startup. If external
# services change their IPs, restart the sandbox to re-resolve.
#

set -e

# Helper function to log only when SANDBOX_DEBUG=1
log_verbose() {
    [ "$SANDBOX_DEBUG" = "1" ] && echo "$@" || true
}

# Use ipset for efficient allowlists when available.
IPSET_V4="sandbox_allow_v4"
IPSET_V6="sandbox_allow_v6"
USE_IPSET=false

# Parse additional domains from environment variable
EXTRA_DOMAINS=()
if [ -n "${SANDBOX_ALLOWED_DOMAINS:-}" ]; then
    IFS=',' read -ra EXTRA_DOMAINS <<< "$SANDBOX_ALLOWED_DOMAINS"
fi

# Initialize domain arrays (will be populated from generated file)
ALLOWLIST_DOMAINS=()
ALL_DOMAINS=()

# ============================================================================
# Domain Allowlist Configuration
# ============================================================================
# Domains are loaded from the generated allowlist file (gateway/firewall-allowlist.generated)
# which is the single source of truth derived from gateway/allowlist.conf.
#
# When wildcard domains (*.example.com) are configured, we cannot pre-resolve
# IPs at firewall setup time. Instead, we:
# 1. Open egress on ports 80/443 (HTTP/HTTPS)
# 2. Rely on DNS filtering (dnsmasq) to restrict domain resolution
# 3. Rely on gateway hostname validation to enforce allowlist
# ============================================================================
WILDCARD_DOMAINS=()
FIREWALL_ALLOWLIST_FILE="${SCRIPT_DIR:-/workspace/gateway}/firewall-allowlist.generated"
if [ -z "${SCRIPT_DIR:-}" ]; then
    # Try relative path from this script's location
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    FIREWALL_ALLOWLIST_FILE="$SCRIPT_DIR/../gateway/firewall-allowlist.generated"
fi

if [ -f "$FIREWALL_ALLOWLIST_FILE" ]; then
    # Source the file to get ALLOWLIST_DOMAINS and WILDCARD_DOMAINS arrays
    # shellcheck source=/dev/null
    source "$FIREWALL_ALLOWLIST_FILE"
    log_verbose "Loaded firewall allowlist: ${#ALLOWLIST_DOMAINS[@]} domains, ${#WILDCARD_DOMAINS[@]} wildcards"
else
    log_verbose "Warning: Firewall allowlist not found at $FIREWALL_ALLOWLIST_FILE"
    log_verbose "         Using empty allowlist - only DNS and gateway traffic will be allowed"
fi

# Combine allowlist domains with any extra domains from environment
ALL_DOMAINS=("${ALLOWLIST_DOMAINS[@]}" "${EXTRA_DOMAINS[@]}")

# Check if wildcard mode should be enabled
WILDCARD_MODE=false
if [ ${#WILDCARD_DOMAINS[@]} -gt 0 ]; then
    WILDCARD_MODE=true
    log_verbose "Wildcard mode enabled - will open egress ports 80/443"
fi

log_verbose "Setting up firewall for limited network mode..."
log_verbose "Whitelisted domains: ${#ALL_DOMAINS[@]} explicit + ${#WILDCARD_DOMAINS[@]} wildcards"

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

# Function to resolve domain and add rules
allow_domain() {
    local domain="$1"
    log_verbose "  Allowing: $domain"

    # Resolve domain to IPv4 addresses
    local ips_raw ip
    ips_raw=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' || true)

    # Also try AAAA records for IPv6
    local ipv6s_raw
    ipv6s_raw=$(dig +short "$domain" AAAA 2>/dev/null | grep -E '^[0-9a-f:]+' || true)

    if [ -z "$ips_raw" ] && [ -z "$ipv6s_raw" ]; then
        log_verbose "    Warning: Could not resolve $domain"
        return
    fi

    # Add rules for each resolved IP using safe read loop
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        add_ip_rule "$ip"
    done <<< "$ips_raw"

    # Add rules for IPv6 using safe read loop
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        add_ipv6_rule "$ip"
    done <<< "$ipv6s_raw"
}

# Allow traffic to whitelisted domains (non-wildcard domains only)
# Wildcard domains are handled by opening ports 80/443 in wildcard mode
for domain in "${ALL_DOMAINS[@]}"; do
    allow_domain "$domain"
done

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

# ============================================================================
# Wildcard Mode: Open HTTP/HTTPS egress
# ============================================================================
# When wildcard domains are configured, we cannot pre-resolve IPs.
# Security is enforced at:
# 1. DNS layer: dnsmasq only resolves allowlisted domains
# 2. Gateway layer: validates hostname matches wildcard patterns
# 3. IP literals are still blocked (requests must use DNS)
# ============================================================================
if [ "$WILDCARD_MODE" = "true" ]; then
    log_verbose "Wildcard mode: allowing egress on ports 80/443"
    log_verbose "  Wildcards: ${WILDCARD_DOMAINS[*]}"
    # Allow HTTP/HTTPS to any destination (DNS and gateway enforce security)
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
fi

# Drop all other outbound traffic
iptables -A OUTPUT -j DROP

# ============================================================================
# IPv6 Firewall Rules
# ============================================================================
# SECURITY: IPv6 must be properly firewalled or disabled. Without ip6tables,
# sandboxes could bypass all network isolation via IPv6 connections.
#
# Strategy:
# 1. If ip6tables is available, apply matching IPv6 rules
# 2. If ip6tables is unavailable, check if IPv6 is disabled at kernel level
# 3. If IPv6 is enabled but ip6tables unavailable, FAIL FAST to prevent bypass
# ============================================================================

if command -v ip6tables &>/dev/null; then
    # ip6tables available - apply matching IPv6 firewall rules
    ip6tables -F OUTPUT 2>/dev/null || true
    ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

    # DNS restrictions for IPv6
    if [ ${#DNS_SERVERS_V6[@]} -gt 0 ]; then
        for dns in "${DNS_SERVERS_V6[@]}"; do
            ip6tables -A OUTPUT -p udp --dport 53 -d "$dns" -j ACCEPT 2>/dev/null || true
            ip6tables -A OUTPUT -p tcp --dport 53 -d "$dns" -j ACCEPT 2>/dev/null || true
        done
        # Block DNS to all other IPv6 destinations (mirrors IPv4 behavior)
        ip6tables -A OUTPUT -p udp --dport 53 -j DROP 2>/dev/null || true
        ip6tables -A OUTPUT -p tcp --dport 53 -j DROP 2>/dev/null || true
    fi

    # Allow traffic to credential-isolation gateway (IPv6) - mirrors IPv4 rules
    if [ -n "${GATEWAY_HOST:-}" ]; then
        GATEWAY_IP6=$(getent ahostsv6 "$GATEWAY_HOST" 2>/dev/null | awk '{print $1}' | head -1 || true)
        if [ -n "$GATEWAY_IP6" ]; then
            log_verbose "  Allowing credential gateway (IPv6): $GATEWAY_HOST ($GATEWAY_IP6)"
            ip6tables -A OUTPUT -d "$GATEWAY_IP6" -j ACCEPT 2>/dev/null || true
        fi
    elif getent ahostsv6 gateway &>/dev/null 2>&1; then
        GATEWAY_IP6=$(getent ahostsv6 gateway 2>/dev/null | awk '{print $1}' | head -1 || true)
        if [ -n "$GATEWAY_IP6" ]; then
            log_verbose "  Allowing credential gateway (IPv6): gateway ($GATEWAY_IP6)"
            ip6tables -A OUTPUT -d "$GATEWAY_IP6" -j ACCEPT 2>/dev/null || true
        fi
    fi

    # Allow traffic to api-proxy (IPv6) - mirrors IPv4 rules
    if [ -n "${API_PROXY_HOST:-}" ]; then
        API_PROXY_IP6=$(getent ahostsv6 "$API_PROXY_HOST" 2>/dev/null | awk '{print $1}' | head -1 || true)
        if [ -n "$API_PROXY_IP6" ]; then
            log_verbose "  Allowing API proxy (IPv6): $API_PROXY_HOST ($API_PROXY_IP6)"
            ip6tables -A OUTPUT -d "$API_PROXY_IP6" -j ACCEPT 2>/dev/null || true
        fi
    elif getent ahostsv6 api-proxy &>/dev/null 2>&1; then
        API_PROXY_IP6=$(getent ahostsv6 api-proxy 2>/dev/null | awk '{print $1}' | head -1 || true)
        if [ -n "$API_PROXY_IP6" ]; then
            log_verbose "  Allowing API proxy (IPv6): api-proxy ($API_PROXY_IP6)"
            ip6tables -A OUTPUT -d "$API_PROXY_IP6" -j ACCEPT 2>/dev/null || true
        fi
    fi

    if [ "$USE_IPSET" = "true" ]; then
        ip6tables -A OUTPUT -m set --match-set "$IPSET_V6" dst -j ACCEPT 2>/dev/null || true
    fi

    # Wildcard mode: allow IPv6 HTTP/HTTPS egress (mirrors IPv4)
    if [ "$WILDCARD_MODE" = "true" ]; then
        log_verbose "Wildcard mode (IPv6): allowing egress on ports 80/443"
        ip6tables -A OUTPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
        ip6tables -A OUTPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    fi

    ip6tables -A OUTPUT -j DROP 2>/dev/null || true
    log_verbose "IPv6 firewall rules applied successfully."
else
    # ip6tables not available - check if IPv6 is disabled at kernel level
    # This is safe because disabled IPv6 means no IPv6 bypass is possible
    IPV6_DISABLED=false

    # Check multiple indicators that IPv6 is disabled
    if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
        if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" = "1" ]; then
            IPV6_DISABLED=true
        fi
    fi

    # Also check if there are any IPv6 addresses on interfaces (excluding loopback)
    if [ "$IPV6_DISABLED" = "false" ]; then
        # If no non-loopback IPv6 addresses exist, treat as effectively disabled
        if ! ip -6 addr show 2>/dev/null | grep -v '::1' | grep -q 'inet6'; then
            IPV6_DISABLED=true
        fi
    fi

    if [ "$IPV6_DISABLED" = "true" ]; then
        log_verbose "Warning: ip6tables unavailable, but IPv6 is disabled at kernel level - safe to continue."
    else
        # SECURITY CRITICAL: IPv6 is enabled but we cannot firewall it
        # This is a bypass risk - fail fast to prevent unfiltered IPv6 egress
        echo "FATAL: ip6tables is unavailable but IPv6 is enabled." >&2
        echo "       Sandboxes could bypass network isolation via IPv6." >&2
        echo "       Either install ip6tables or disable IPv6:" >&2
        echo "         sysctl -w net.ipv6.conf.all.disable_ipv6=1" >&2
        echo "         sysctl -w net.ipv6.conf.default.disable_ipv6=1" >&2
        exit 1
    fi
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

    # ===========================================================================
    # DOCKER-USER Rule Ordering (explicit append order for predictability)
    # ===========================================================================
    # Rules are processed in order: first match wins.
    # Order: ESTABLISHED -> DNS allow -> service allow -> DNS block -> egress block -> RETURN
    # Using consistent -A (append) for predictable ordering.
    # ===========================================================================

    # 1. Allow established connections (fastest path for existing flows)
    iptables -A DOCKER-USER -m state --state ESTABLISHED,RELATED -j RETURN
    log_verbose "  [1] Allowing established connections"

    # 2. Allow DNS (port 53) only to gateway (for dnsmasq) - BEFORE general gateway rule
    if [ -n "$GATEWAY_CONTAINER_IP" ]; then
        iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -d "$GATEWAY_CONTAINER_IP" -p udp --dport 53 -j RETURN
        iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -d "$GATEWAY_CONTAINER_IP" -p tcp --dport 53 -j RETURN
        log_verbose "  [2] Allowing DNS to gateway only"
    fi

    # 3. Block all other DNS from sandbox (prevent DNS bypass) - BEFORE service allows
    iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -p udp --dport 53 -j DROP
    iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -p tcp --dport 53 -j DROP
    log_verbose "  [3] Blocking DNS to non-gateway destinations"

    # 4. Allow sandbox -> gateway (for git operations)
    if [ -n "$GATEWAY_CONTAINER_IP" ]; then
        iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -d "$GATEWAY_CONTAINER_IP" -j RETURN
        log_verbose "  [4] Allowing sandbox -> gateway ($GATEWAY_CONTAINER_IP)"
    fi

    # 5. Allow sandbox -> api-proxy (for HTTPS API requests)
    if [ -n "$API_PROXY_CONTAINER_IP" ]; then
        iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -d "$API_PROXY_CONTAINER_IP" -j RETURN
        log_verbose "  [5] Allowing sandbox -> api-proxy ($API_PROXY_CONTAINER_IP)"
    fi

    # 6. Block direct egress from sandbox to external networks
    # Traffic should go through gateway or api-proxy.
    # We allow traffic to RFC1918 private ranges (where our services live):
    # - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    # And block all public (non-private) destinations.
    # Note: Traffic to gateway/api-proxy is already allowed by rules 4-5 above.
    # This rule catches any remaining traffic to public IPs.
    #
    # Using ipset or multiple rules to match "not RFC1918" is complex.
    # Instead, we use a simpler approach: since gateway/api-proxy allow rules
    # come first, this final DROP catches traffic to any other destination.
    # We explicitly allow the Docker bridge network ranges first.
    iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -d 10.0.0.0/8 -j RETURN
    iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -d 172.16.0.0/12 -j RETURN
    iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -d 192.168.0.0/16 -j RETURN
    # Block everything else from sandbox (public IPs)
    iptables -A DOCKER-USER -s "$SANDBOX_SUBNET" -j DROP
    log_verbose "  [6] Blocking direct external egress from sandbox (public IPs)"

    # 7. Final RETURN for other traffic (Docker's default behavior)
    iptables -A DOCKER-USER -j RETURN
    log_verbose "  [7] Final RETURN rule"

    log_verbose "  DOCKER-USER rules applied (7 rule groups)"
}

# Only run DOCKER-USER setup if we're on the host (have docker access)
# and explicitly requested via SETUP_DOCKER_USER=1
if [ "${SETUP_DOCKER_USER:-}" = "1" ] && command -v docker &>/dev/null; then
    setup_docker_user_rules
fi

log_verbose "Firewall rules applied successfully."
if [ "$WILDCARD_MODE" = "true" ]; then
    log_verbose "Allowed: ${#ALL_DOMAINS[@]} explicit domains + ${#WILDCARD_DOMAINS[@]} wildcard patterns + ports 80/443 (wildcard mode) + Docker gateway + DNS + loopback"
else
    log_verbose "Allowed: ${#ALL_DOMAINS[@]} domains + Docker gateway + DNS (resolvers/gateway) + loopback"
fi
log_verbose "All other outbound traffic is blocked."
