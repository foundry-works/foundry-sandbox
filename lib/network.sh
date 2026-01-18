#!/bin/bash
#
# Network mode management for sandbox containers
#
# Supported modes:
#   full       - Unrestricted network access (default)
#   limited    - Whitelist only (github, npm, pypi, AI APIs, deep research APIs)
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

# Remove previously injected network config to keep override idempotent.
strip_network_config() {
    local override_file="$1"

    if [ ! -f "$override_file" ]; then
        return 0
    fi

    local tmp_file
    tmp_file="$(mktemp)"
    awk '
        {
            if (cap_add) {
                if ($0 ~ /^[[:space:]]+-[[:space:]]*/ ) {
                    if ($0 ~ /NET_ADMIN/ || $0 ~ /NET_RAW/) {
                        next
                    }
                    if (!cap_add_printed) {
                        print cap_add_header
                        cap_add_printed=1
                    }
                    print
                    next
                }
                cap_add=0
            }
            if ($0 ~ /^[[:space:]]*cap_add:[[:space:]]*$/) {
                cap_add=1
                cap_add_header=$0
                cap_add_printed=0
                next
            }
            if (env) {
                if ($0 ~ /^[[:space:]]+-[[:space:]]*/ ) {
                    if ($0 ~ /SANDBOX_NETWORK_MODE=/) {
                        next
                    }
                    if (!env_printed) {
                        print env_header
                        env_printed=1
                    }
                    print
                    next
                }
                env=0
            }
            if ($0 ~ /^[[:space:]]*environment:[[:space:]]*$/) {
                env=1
                env_header=$0
                env_printed=0
                next
            }
            print
        }
    ' "$override_file" > "$tmp_file" && mv "$tmp_file" "$override_file"
}

# Add network configuration to an existing or new override file
add_network_to_override() {
    local mode="$1"
    local override_file="$2"

    ensure_override_header "$override_file"
    strip_network_config "$override_file"
    generate_network_config "$mode" "$override_file"
}
