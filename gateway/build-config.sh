#!/bin/bash
# Generate dnsmasq.conf and tinyproxy filter from allowlist.conf
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ALLOWLIST="${SCRIPT_DIR}/allowlist.conf"
OUTPUT_DIR="${1:-/etc/gateway}"

mkdir -p "$OUTPUT_DIR"

# Parse allowlist
ALLOWED_DOMAINS=()
BLOCKED_DOMAINS=()
WILDCARD_DOMAINS=()

while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// /}" ]] && continue

    # Extract domain and type
    domain=$(echo "$line" | awk '{print $1}')

    if [[ "$domain" == !* ]]; then
        # Blocked domain (strip ! prefix)
        BLOCKED_DOMAINS+=("${domain#!}")
    elif [[ "$domain" == \*.* ]]; then
        # Wildcard domain (keep as-is for ALLOWED_DOMAINS, but track for WILDCARD_DOMAINS)
        WILDCARD_DOMAINS+=("${domain#\*.}")
        ALLOWED_DOMAINS+=("$domain")
    else
        ALLOWED_DOMAINS+=("$domain")
    fi
done < "$ALLOWLIST"

# Generate dnsmasq.conf
generate_dnsmasq() {
    local conf="$OUTPUT_DIR/dnsmasq.conf"
    cat > "$conf" <<'HEADER'
# Auto-generated from allowlist.conf - DO NOT EDIT
# Regenerate with: build-config.sh

# Listen on localhost only
listen-address=127.0.0.1
port=53
bind-interfaces

# Use upstream DNS
no-resolv
server=8.8.8.8
server=8.8.4.4

# Cache settings
cache-size=1000

HEADER

    echo "# Blocked domains (return NXDOMAIN)" >> "$conf"
    for domain in "${BLOCKED_DOMAINS[@]}"; do
        echo "address=/${domain}/" >> "$conf"
    done

    echo "" >> "$conf"
    echo "# Allowed domains are resolved normally via upstream" >> "$conf"
    echo "# No explicit entries needed - dnsmasq forwards by default" >> "$conf"
}

# Generate tinyproxy filter
generate_tinyproxy_filter() {
    local filter="$OUTPUT_DIR/tinyproxy-filter"
    cat > "$filter" <<'HEADER'
# Auto-generated from allowlist.conf - DO NOT EDIT
# Regenerate with: build-config.sh
# Format: regex patterns matching allowed URLs
HEADER

    for domain in "${ALLOWED_DOMAINS[@]}"; do
        if [[ "$domain" == \*.* ]]; then
            # Wildcard: *.example.com -> match any subdomain
            local base="${domain#\*.}"
            local escaped="${base//./\\.}"
            echo "^[a-zA-Z0-9._-]+\\.${escaped}" >> "$filter"
        else
            # Exact domain
            local escaped="${domain//./\\.}"
            echo "^${escaped}" >> "$filter"
        fi
    done
}

generate_dnsmasq
generate_tinyproxy_filter

echo "Generated configs in $OUTPUT_DIR:"
echo "  dnsmasq.conf (${#BLOCKED_DOMAINS[@]} blocked domains)"
echo "  tinyproxy-filter (${#ALLOWED_DOMAINS[@]} allowed domains)"
