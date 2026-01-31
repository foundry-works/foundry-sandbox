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
            # SYS_ADMIN needed for cursor-agent's internal namespace sandbox
            cat >> "$override_file" <<EOF
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    environment:
      - SANDBOX_NETWORK_MODE=full
EOF
            ;;
        limited|host-only)
            # Limited/host-only: use bridge network + iptables
            # Add capabilities for iptables and cursor-agent's namespace sandbox
            cat >> "$override_file" <<EOF
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
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
                    if ($0 ~ /NET_ADMIN/ || $0 ~ /NET_RAW/ || $0 ~ /SYS_ADMIN/) {
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

strip_ssh_agent_config() {
    local override_file="$1"

    if [ ! -f "$override_file" ]; then
        return 0
    fi

    local tmp_file
    tmp_file="$(mktemp)"
    awk -v sock="$SSH_AGENT_CONTAINER_SOCK" '
        {
            if (vol) {
                if ($0 ~ /^[[:space:]]{6}-[[:space:]]*/) {
                    if (index($0, ":" sock) > 0) {
                        next
                    }
                    if (!vol_printed) {
                        print vol_header
                        vol_printed=1
                    }
                    print
                    next
                }
                vol=0
            }
            if ($0 ~ /^[[:space:]]{4}volumes:[[:space:]]*$/) {
                vol=1
                vol_header=$0
                vol_printed=0
                next
            }
            if (grp) {
                if ($0 ~ /^[[:space:]]{6}-[[:space:]]*/) {
                    if ($0 ~ /^[[:space:]]{6}-[[:space:]]*["]?0["]?[[:space:]]*$/) {
                        next
                    }
                    if (!grp_printed) {
                        print grp_header
                        grp_printed=1
                    }
                    print
                    next
                }
                grp=0
            }
            if ($0 ~ /^[[:space:]]{4}group_add:[[:space:]]*$/) {
                grp=1
                grp_header=$0
                grp_printed=0
                next
            }
            if (env) {
                if ($0 ~ /^[[:space:]]{6}-[[:space:]]*/) {
                    if ($0 ~ /SSH_AUTH_SOCK=/) {
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
            if ($0 ~ /^[[:space:]]{4}environment:[[:space:]]*$/) {
                env=1
                env_header=$0
                env_printed=0
                next
            }
            print
        }
    ' "$override_file" > "$tmp_file" && mv "$tmp_file" "$override_file"
}

strip_claude_home_config() {
    local override_file="$1"

    if [ ! -f "$override_file" ]; then
        return 0
    fi

    local tmp_file
    tmp_file="$(mktemp)"
    awk -v target="/home/ubuntu/.claude" '
        {
            if (vol) {
                if ($0 ~ /^[[:space:]]{6}-[[:space:]]*/) {
                    if (index($0, ":" target) > 0) {
                        next
                    }
                    if (!vol_printed) {
                        print vol_header
                        vol_printed=1
                    }
                    print
                    next
                }
                vol=0
            }
            if ($0 ~ /^[[:space:]]{4}volumes:[[:space:]]*$/) {
                vol=1
                vol_header=$0
                vol_printed=0
                next
            }
            print
        }
    ' "$override_file" > "$tmp_file" && mv "$tmp_file" "$override_file"
}

strip_timezone_config() {
    local override_file="$1"

    if [ ! -f "$override_file" ]; then
        return 0
    fi

    local tmp_file
    tmp_file="$(mktemp)"
    awk '
        {
            if (vol) {
                if ($0 ~ /^[[:space:]]{6}-[[:space:]]*/) {
                    if (index($0, ":/etc/localtime") > 0 || index($0, ":/etc/timezone") > 0) {
                        next
                    }
                    if (!vol_printed) {
                        print vol_header
                        vol_printed=1
                    }
                    print
                    next
                }
                vol=0
            }
            if ($0 ~ /^[[:space:]]{4}volumes:[[:space:]]*$/) {
                vol=1
                vol_header=$0
                vol_printed=0
                next
            }
            if (env) {
                if ($0 ~ /^[[:space:]]{6}-[[:space:]]*/) {
                    if ($0 ~ /TZ=/) {
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
            if ($0 ~ /^[[:space:]]{4}environment:[[:space:]]*$/) {
                env=1
                env_header=$0
                env_printed=0
                next
            }
            print
        }
    ' "$override_file" > "$tmp_file" && mv "$tmp_file" "$override_file"
}

append_override_list_item() {
    local override_file="$1"
    local key="$2"
    local item="$3"

    local tmp_file
    tmp_file="$(mktemp)"
    awk -v key="$key" -v item="$item" '
        BEGIN {
            key_re="^[[:space:]]{4}" key ":[[:space:]]*$"
            item_indent="      - "
            inserted=0
            in_list=0
        }
        {
            if ($0 ~ key_re) {
                in_list=1
                print
                next
            }
            if (in_list) {
                if ($0 ~ /^[[:space:]]{6}-[[:space:]]*/) {
                    print
                    next
                }
                if (!inserted) {
                    print item_indent item
                    inserted=1
                }
                in_list=0
            }
            print
        }
        END {
            if (in_list && !inserted) {
                print item_indent item
                inserted=1
            }
            if (!inserted) {
                print "    " key ":"
                print item_indent item
            }
        }
    ' "$override_file" > "$tmp_file" && mv "$tmp_file" "$override_file"
}

add_claude_home_to_override() {
    local override_file="$1"
    local claude_home="$2"

    ensure_override_header "$override_file"
    strip_claude_home_config "$override_file"

    if [ -z "$claude_home" ]; then
        return 0
    fi

    local mount_entry
    mount_entry="\"$claude_home:/home/ubuntu/.claude\""
    append_override_list_item "$override_file" "volumes" "$mount_entry"
}

add_ssh_agent_to_override() {
    local override_file="$1"
    local agent_sock="$2"

    ensure_override_header "$override_file"
    strip_ssh_agent_config "$override_file"

    if [ -z "$agent_sock" ]; then
        return 0
    fi

    local mount_entry
    mount_entry="\"$agent_sock:$SSH_AGENT_CONTAINER_SOCK\""
    append_override_list_item "$override_file" "volumes" "$mount_entry"
    append_override_list_item "$override_file" "environment" "SSH_AUTH_SOCK=$SSH_AGENT_CONTAINER_SOCK"
}

add_timezone_to_override() {
    local override_file="$1"

    ensure_override_header "$override_file"
    strip_timezone_config "$override_file"

    if [ -r /etc/localtime ]; then
        append_override_list_item "$override_file" "volumes" "\"/etc/localtime:/etc/localtime:ro\""
    fi

    if [ -r /etc/timezone ]; then
        append_override_list_item "$override_file" "volumes" "\"/etc/timezone:/etc/timezone:ro\""
    fi

    local host_tz=""
    host_tz=$(detect_host_timezone) || host_tz=""
    if [ -n "$host_tz" ]; then
        append_override_list_item "$override_file" "environment" "TZ=$host_tz"
    fi
}

# Add network configuration to an existing or new override file
add_network_to_override() {
    local mode="$1"
    local override_file="$2"

    ensure_override_header "$override_file"
    strip_network_config "$override_file"
    generate_network_config "$mode" "$override_file"
}

# Conditionally add ANTHROPIC_API_KEY placeholder for credential isolation
# Only sets the placeholder when OAuth is NOT available on the host
# This prevents the "Detected custom API key" prompt in Claude Code when OAuth is configured
add_anthropic_credential_to_override() {
    local override_file="$1"

    # If OAuth token is available, don't set ANTHROPIC_API_KEY
    # The proxy will inject the OAuth token instead
    if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
        return 0
    fi

    # No OAuth - set the placeholder for API key auth
    ensure_override_header "$override_file"
    append_override_list_item "$override_file" "environment" "ANTHROPIC_API_KEY=CREDENTIAL_PROXY_PLACEHOLDER"
}

# Add Gemini credential placeholder for credential isolation
# Prefers OAuth if ~/.gemini/oauth_creds.json exists, otherwise falls back to API key
add_gemini_credential_to_override() {
    local override_file="$1"

    # Check if OAuth credentials exist - prefer OAuth over API key
    if [ -f "$HOME/.gemini/oauth_creds.json" ]; then
        log_info "Using Gemini OAuth credentials (oauth_creds.json found)"
        # Don't add GEMINI_API_KEY - OAuth will be used via proxy
        return 0
    fi

    # Fallback to API key if no OAuth credentials
    log_info "Using Gemini API key (no oauth_creds.json found)"
    ensure_override_header "$override_file"
    append_override_list_item "$override_file" "environment" "GEMINI_API_KEY=CREDENTIAL_PROXY_PLACEHOLDER"
}
