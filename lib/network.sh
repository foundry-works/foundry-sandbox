#!/bin/bash
#
# Network mode management for sandbox containers
#
# Supported modes:
#   full       - Unrestricted network access (default)
#   limited    - Whitelist only (github, npm, pypi, AI APIs)
#   host-only  - Local network only (Docker gateway, private subnets)
#   none       - Complete block (loopback only)
#

# Validate network mode
validate_network_mode() {
    local mode="$1"
    case "$mode" in
        full|limited|host-only|none)
            return 0
            ;;
        *)
            die "Invalid network mode: $mode (use: full, limited, host-only, none)"
            ;;
    esac
}

# Generate network config for docker-compose override
# Appends configuration to the override file for network mode settings
generate_network_config() {
    local mode="$1"
    local override_file="$2"

    case "$mode" in
        none)
            # True Docker network isolation - no network interface at all
            echo "    network_mode: \"none\"" >> "$override_file"
            ;;
        full)
            # Full mode: still need capabilities for runtime switching
            cat >> "$override_file" <<EOF
    cap_add:
      - NET_ADMIN
      - NET_RAW
    environment:
      - SANDBOX_NETWORK_MODE=full
EOF
            ;;
        limited|host-only)
            # Limited/host-only: use bridge network + iptables
            # Add capabilities for iptables
            cat >> "$override_file" <<EOF
    cap_add:
      - NET_ADMIN
      - NET_RAW
    environment:
      - SANDBOX_NETWORK_MODE=${mode}
EOF
            ;;
    esac
}

# Initialize override file with services/dev header if needed
ensure_override_header() {
    local override_file="$1"

    if [ ! -f "$override_file" ]; then
        cat > "$override_file" <<EOF
services:
  dev:
EOF
    elif ! grep -q "^services:" "$override_file"; then
        # File exists but missing header
        local content
        content=$(cat "$override_file")
        cat > "$override_file" <<EOF
services:
  dev:
${content}
EOF
    fi
}

# Add network configuration to an existing or new override file
add_network_to_override() {
    local mode="$1"
    local override_file="$2"

    ensure_override_header "$override_file"
    generate_network_config "$mode" "$override_file"
}
