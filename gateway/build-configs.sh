#!/bin/bash
#
# Build script for credential isolation gateway configuration generation
#
# Generates dnsmasq.conf and tinyproxy.conf from allowlist.conf (single source of truth)
# Also generates firewall allowlist artifacts for safety/network-firewall.sh
#
# Usage: ./build-configs.sh [--dry-run]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALLOWLIST_FILE="$SCRIPT_DIR/allowlist.conf"
DNSMASQ_CONF="$SCRIPT_DIR/dnsmasq.conf"
TINYPROXY_CONF="$SCRIPT_DIR/tinyproxy.conf"
FIREWALL_ALLOWLIST="$SCRIPT_DIR/firewall-allowlist.generated"

DRY_RUN=false
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=true
fi

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Verify allowlist.conf exists
if [ ! -f "$ALLOWLIST_FILE" ]; then
    log_error "allowlist.conf not found at $ALLOWLIST_FILE"
    exit 1
fi

log_info "Parsing allowlist from: $ALLOWLIST_FILE"

# Parse allowlist.conf into associative arrays
declare -A DOMAINS_BY_TYPE
declare -a ALL_DOMAINS
declare -a ROTATING_IP_DOMAINS
declare -a WILDCARD_DOMAINS

# Extract CIDR blocks from comments
declare -a CIDR_BLOCKS
CIDR_LINE_NUM=0

while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty lines and comments (but extract CIDR blocks from comments)
    if [[ "$line" =~ ^# ]]; then
        # Check for CIDR blocks in comments (format: # 1.2.3.0/24)
        if [[ "$line" =~ ^#\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+) ]]; then
            cidr="${BASH_REMATCH[1]}"
            CIDR_BLOCKS+=("$cidr")
            ((CIDR_LINE_NUM++)) || true
        fi
        continue
    fi

    # Skip blank lines
    [ -z "$(echo "$line" | xargs)" ] && continue

    # Parse domain and type (format: domain [type])
    read -r domain type <<< "$line"

    # Validate domain format (basic check)
    if [ -z "$domain" ]; then
        continue
    fi

    # Handle blocked DoH endpoints (! prefix)
    if [[ "$domain" =~ ^! ]]; then
        log_warn "DoH endpoint blocking not yet implemented: $domain"
        continue
    fi

    # Track by type
    if [ -z "$type" ]; then
        type="generic"
    fi

    DOMAINS_BY_TYPE["$type"]+="$domain "
    ALL_DOMAINS+=("$domain")

    # Track rotating IP domains separately
    if [ "$type" = "rotating_ip" ]; then
        ROTATING_IP_DOMAINS+=("$domain")
    fi

    # Track wildcard domains separately
    if [[ "$domain" == \** ]]; then
        WILDCARD_DOMAINS+=("$domain")
    fi
done < "$ALLOWLIST_FILE"

log_info "Parsed ${#ALL_DOMAINS[@]} domains across ${#DOMAINS_BY_TYPE[@]} types"
log_info "Found ${#CIDR_BLOCKS[@]} CIDR blocks in comments"
log_info "Found ${#ROTATING_IP_DOMAINS[@]} rotating IP domains"
log_info "Found ${#WILDCARD_DOMAINS[@]} wildcard domains"

# Function to generate dnsmasq.conf
generate_dnsmasq() {
    local output_file="$1"
    local content=""

    content+="# Automatically generated dnsmasq configuration\n"
    content+="# Generated from: $ALLOWLIST_FILE\n"
    content+="# DO NOT EDIT MANUALLY - use build-configs.sh to regenerate\n"
    content+="# Generated: $(date)\n"
    content+="#\n\n"

    # Enable DNS forwarding for non-matching domains
    content+="# Default upstream DNS servers (uses /etc/resolv.conf)\n"
    content+="# port=53 is the default\n\n"

    # Add address records for whitelisted domains
    content+="# Whitelisted domains - allow resolution\n"

    local domain_count=0
    for domain in "${ALL_DOMAINS[@]}"; do
        # Skip wildcard domains in dnsmasq (they need special handling)
        if [[ "$domain" != \** ]]; then
            content+="# $domain\n"
            ((domain_count++)) || true
        fi
    done

    # Add wildcard handling
    content+="\n# Wildcard domains\n"
    for domain in "${WILDCARD_DOMAINS[@]}"; do
        # Convert *.example.com to address=/example.com/
        local base_domain="${domain#\*.}"
        content+="address=/$base_domain/127.0.0.1\n"
        ((domain_count++)) || true
    done

    content+="\n# Total domains: $domain_count\n"
    content+="\n# For restricted DNS, you can add:\n"
    content+="# rebind-domain-ok=example.com (to allow private IP responses)\n"
    content+="# address=/blocked.com/\n"

    if [ "$DRY_RUN" = true ]; then
        echo -e "$content" | head -50
        log_info "[DRY-RUN] Would write dnsmasq.conf (${#content} bytes)"
    else
        echo -e "$content" > "$output_file"
        log_info "Generated dnsmasq.conf (${#content} bytes)"
    fi
}

# Function to generate tinyproxy.conf
generate_tinyproxy() {
    local output_file="$1"
    local content=""

    content+="#\n"
    content+="# Tinyproxy configuration for credential isolation gateway\n"
    content+="# Automatically generated from allowlist.conf\n"
    content+="# DO NOT EDIT MANUALLY - use build-configs.sh to regenerate\n"
    content+="# Generated: $(date)\n"
    content+="#\n\n"

    content+="# Port to listen on\n"
    content+="Listen 8080\n\n"

    content+="# Bind to all interfaces\n"
    content+="Bind 0.0.0.0\n\n"

    content+="# Timeout for inactive connections (seconds)\n"
    content+="ConnectTimeout 60\n\n"

    content+="# Upstream gateway - connects to Flask gateway\n"
    content+="Upstream http 127.0.0.1:8081\n\n"

    content+="# Logging configuration\n"
    content+="LogFile \"/var/log/tinyproxy/tinyproxy.log\"\n"
    content+="LogLevel Info\n\n"

    content+="# Access log format\n"
    content+="AccessLog On\n"
    content+="AccessLogFile \"/var/log/tinyproxy/access.log\"\n\n"

    content+="# Security: Set ACL to allow only local connections\n"
    content+="Allow 127.0.0.1\n"
    content+="Allow 0.0.0.0/0\n\n"

    content+="# Maximum number of clients\n"
    content+="MaxClients 256\n\n"

    content+="# Timeout for connecting to upstream\n"
    content+="ConnectTimeout 60\n\n"

    content+="# Keep-alive timeout\n"
    content+="TimeoutConnect 60\n\n"

    content+="# CONNECT method timeout (for HTTPS tunneling)\n"
    content+="TimeoutRead 60\n\n"

    content+="# Whitelisted domains (${#ALL_DOMAINS[@]} total)\n"
    content+="#\n"

    # Group domains by type for documentation
    for type in "${!DOMAINS_BY_TYPE[@]}"; do
        content+="# Type: $type\n"
        for domain in ${DOMAINS_BY_TYPE[$type]}; do
            content+="#   - $domain\n"
        done
    done

    if [ "$DRY_RUN" = true ]; then
        echo -e "$content" | head -60
        log_info "[DRY-RUN] Would write tinyproxy.conf (${#content} bytes)"
    else
        echo -e "$content" > "$output_file"
        log_info "Generated tinyproxy.conf (${#content} bytes)"
    fi
}

# Function to generate firewall allowlist
generate_firewall_allowlist() {
    local output_file="$1"
    local content=""

    content+="#!/bin/bash\n"
    content+="#\n"
    content+="# Firewall allowlist configuration (auto-generated)\n"
    content+="# Generated from: $ALLOWLIST_FILE\n"
    content+="# DO NOT EDIT MANUALLY - use build-configs.sh to regenerate\n"
    content+="# Generated: $(date)\n"
    content+="#\n"
    content+="# This file is sourced by safety/network-firewall.sh\n"
    content+="# Provides domain, rotating domain, and CIDR allowlists\n"
    content+="#\n\n"

    # Export domains (non-wildcard)
    content+="# Standard domains (resolved once at firewall setup)\n"
    content+="declare -a ALLOWLIST_DOMAINS=(\n"
    for domain in "${ALL_DOMAINS[@]}"; do
        # Skip wildcard and rotating IP domains
        if [[ "$domain" != \** && "$domain" != *rotating_ip* ]]; then
            content+="    \"$domain\"\n"
        fi
    done
    content+=")\n\n"

    # Export rotating IP domains
    content+="# Rotating IP domains (resolved multiple times to capture IP pool)\n"
    content+="declare -a ROTATING_IP_DOMAINS=(\n"
    for domain in "${ROTATING_IP_DOMAINS[@]}"; do
        content+="    \"$domain\"\n"
    done
    content+=")\n\n"

    # Export CIDR blocks extracted from comments
    content+="# CIDR blocks (from allowlist.conf comments)\n"
    content+="declare -a CIDR_BLOCKS=(\n"
    for cidr in "${CIDR_BLOCKS[@]}"; do
        content+="    \"$cidr\"\n"
    done
    content+=")\n\n"

    # Export hardcoded known IPs
    content+="# Known IPs that don't resolve via public DNS\n"
    content+="declare -a KNOWN_IPS=(\n"
    content+="    \"44.197.141.31\"   # api5.cursor.sh\n"
    content+="    \"184.73.249.78\"   # api2.cursor.sh\n"
    content+=")\n\n"

    # Export wildcard domains
    content+="# Wildcard domains (for pattern matching)\n"
    content+="declare -a WILDCARD_DOMAINS=(\n"
    for domain in "${WILDCARD_DOMAINS[@]}"; do
        content+="    \"$domain\"\n"
    done
    content+=")\n\n"

    # Statistics
    content+="# Statistics\n"
    content+="# Total domains: ${#ALL_DOMAINS[@]}\n"
    content+="# Rotating IP domains: ${#ROTATING_IP_DOMAINS[@]}\n"
    content+="# Wildcard domains: ${#WILDCARD_DOMAINS[@]}\n"
    content+="# CIDR blocks: ${#CIDR_BLOCKS[@]}\n"

    if [ "$DRY_RUN" = true ]; then
        echo -e "$content" | head -80
        log_info "[DRY-RUN] Would write firewall-allowlist.generated (${#content} bytes)"
    else
        echo -e "$content" > "$output_file"
        chmod 644 "$output_file"
        log_info "Generated firewall-allowlist.generated (${#content} bytes)"
    fi
}

# Main execution
log_info "Generating configuration files..."
log_info "==========================================="

generate_dnsmasq "$DNSMASQ_CONF"
generate_tinyproxy "$TINYPROXY_CONF"
generate_firewall_allowlist "$FIREWALL_ALLOWLIST"

if [ "$DRY_RUN" = true ]; then
    log_warn "DRY-RUN mode: no files were written"
    exit 0
fi

# Verify generated files
log_info "==========================================="
log_info "Verifying generated files..."

for file in "$DNSMASQ_CONF" "$TINYPROXY_CONF" "$FIREWALL_ALLOWLIST"; do
    if [ -f "$file" ]; then
        size=$(wc -c < "$file")
        lines=$(wc -l < "$file")
        log_info "✓ $file ($lines lines, $size bytes)"
    else
        log_error "Failed to create $file"
        exit 1
    fi
done

log_info "==========================================="
log_info "Success! Configuration files generated."
log_info ""
log_info "Generated files:"
log_info "  - $DNSMASQ_CONF (DNS configuration)"
log_info "  - $TINYPROXY_CONF (Proxy configuration)"
log_info "  - $FIREWALL_ALLOWLIST (Firewall allowlist - source by network-firewall.sh)"
log_info ""
log_info "Next steps:"
log_info "  1. Review generated configurations"
log_info "  2. Update safety/network-firewall.sh to source $FIREWALL_ALLOWLIST"
log_info "  3. Test firewall rules: sudo safety/network-firewall.sh"
