#!/bin/bash
# Gateway session management functions for credential isolation

# Gateway URL for session management (TCP-based)
# Set by docker.sh after container starts via setup_gateway_url()
# No default - must be set before calling gateway functions

# Create a gateway session for a container
# Args:
#   $1 - container_id: The container ID
#   $2 - container_ip: The container's IP address
#   $3 - repos: Optional comma-separated list of repos (owner/repo format)
# Returns:
#   0 on success, 1 on failure
#   Sets GATEWAY_TOKEN and GATEWAY_SECRET on success
create_gateway_session() {
    local container_id="$1"
    local container_ip="$2"
    local repos="${3:-}"

    if [ -z "$GATEWAY_URL" ]; then
        log_error "create_gateway_session: GATEWAY_URL not set - call setup_gateway_url first"
        return 1
    fi

    if [ -z "$container_id" ] || [ -z "$container_ip" ]; then
        log_error "create_gateway_session: container_id and container_ip required"
        return 1
    fi

    # Build JSON request body using jq for safe escaping
    local json_body
    if [ -n "$repos" ]; then
        # Convert comma-separated repos to JSON array using jq for proper escaping
        local repos_json
        repos_json=$(echo "$repos" | tr ',' '\n' | jq -R . | jq -s .)
        json_body=$(jq -n \
            --arg cid "$container_id" \
            --arg cip "$container_ip" \
            --argjson repos "$repos_json" \
            '{container_id: $cid, container_ip: $cip, repos: $repos}')
    else
        json_body=$(jq -n \
            --arg cid "$container_id" \
            --arg cip "$container_ip" \
            '{container_id: $cid, container_ip: $cip}')
    fi

    # Call gateway API via TCP
    local response
    local curl_args=(-s -X POST -H "Content-Type: application/json" -d "$json_body")

    # Add session management key header if set
    if [ -n "$GATEWAY_SESSION_MGMT_KEY" ]; then
        curl_args+=(-H "X-Session-Mgmt-Key: $GATEWAY_SESSION_MGMT_KEY")
    fi

    response=$(curl "${curl_args[@]}" "${GATEWAY_URL}/session/create" 2>&1)

    local curl_exit=$?
    if [ $curl_exit -ne 0 ]; then
        log_error "Gateway session creation failed: curl error $curl_exit"
        return 1
    fi

    # Parse response - extract token and secret
    GATEWAY_TOKEN=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)
    GATEWAY_SECRET=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('secret',''))" 2>/dev/null)

    if [ -z "$GATEWAY_TOKEN" ] || [ -z "$GATEWAY_SECRET" ]; then
        local error
        error=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','Unknown error'))" 2>/dev/null)
        log_error "Gateway session creation failed: $error"
        log_error "Remediation steps:"
        log_error "  1. Check gateway logs: docker logs <gateway-container>"
        log_error "  2. Verify GitHub token is configured for gateway"
        log_error "  3. Check if repo access is authorized in gateway config"
        return 1
    fi

    return 0
}

# Destroy a gateway session
# Args:
#   $1 - token: The session token to destroy
# Returns:
#   0 on success, 1 on failure
destroy_gateway_session() {
    local token="$1"

    if [ -z "$token" ]; then
        log_error "destroy_gateway_session: token required"
        return 1
    fi

    local response
    local curl_args=(-s -X DELETE)

    # Add session management key header if set
    if [ -n "$GATEWAY_SESSION_MGMT_KEY" ]; then
        curl_args+=(-H "X-Session-Mgmt-Key: $GATEWAY_SESSION_MGMT_KEY")
    fi

    response=$(curl "${curl_args[@]}" "${GATEWAY_URL}/session/$token" 2>&1)

    local curl_exit=$?
    if [ $curl_exit -ne 0 ]; then
        log_warn "Gateway session destruction failed: curl error $curl_exit"
        return 1
    fi

    return 0
}

# Wait for gateway health check
# Args:
#   $1 - timeout_seconds: Max time to wait (default: 30)
# Returns:
#   0 if healthy, 1 if timeout
wait_for_gateway_health() {
    local timeout="${1:-30}"
    local elapsed=0

    if [ -z "$GATEWAY_URL" ]; then
        log_error "wait_for_gateway_health: GATEWAY_URL not set - call setup_gateway_url first"
        return 1
    fi

    log_debug "Waiting for gateway health at ${GATEWAY_URL}..."

    while [ $elapsed -lt "$timeout" ]; do
        if curl -s "${GATEWAY_URL}/health" | grep -q '"status".*"healthy"'; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_error "Gateway health check timed out after ${timeout}s (URL: ${GATEWAY_URL})"
    log_error "Remediation steps:"
    log_error "  1. Check if gateway container is running: docker ps | grep gateway"
    log_error "  2. View gateway logs: docker logs <gateway-container>"
    log_error "  3. Restart gateway: docker-compose -f docker-compose.credential-isolation.yml restart gateway"
    return 1
}

# Write gateway token to container's /run/secrets/gateway_token
# Args:
#   $1 - container_id: Docker container ID
#   $2 - token: Session token
#   $3 - secret: Session secret
# Returns:
#   0 on success, 1 on failure
write_gateway_token_to_container() {
    local container_id="$1"
    local token="$2"
    local secret="$3"

    if [ -z "$container_id" ] || [ -z "$token" ] || [ -z "$secret" ]; then
        log_error "write_gateway_token_to_container: container_id, token, and secret required"
        return 1
    fi

    # Combined token:secret format for credential helper
    local combined="${token}:${secret}"

    # Create /run/secrets directory and write token with secure permissions
    # Security: Use pipe instead of embedding variable in shell string to prevent injection
    # Even though tokens are generated securely via secrets.token_urlsafe(32), this pattern
    # is safer as defense-in-depth against any future changes to token generation
    # Note: Run as root (-u 0) because /run is owned by root
    local write_output
    write_output=$(echo "$combined" | docker exec -i -u 0 "$container_id" sh -c '
        set -e
        mkdir -p /run/secrets
        cat > /run/secrets/gateway_token
        # Make readable by sandbox user (ubuntu, uid 1000) but not world-readable
        chown 1000:1000 /run/secrets/gateway_token
        chmod 0400 /run/secrets/gateway_token
        # Verify permissions were applied correctly
        perms=$(stat -c "%a" /run/secrets/gateway_token 2>/dev/null || stat -f "%Lp" /run/secrets/gateway_token 2>/dev/null)
        if [ "$perms" != "400" ]; then
            echo "ERROR: Failed to set permissions (got $perms, expected 400)" >&2
            exit 1
        fi
    ' 2>&1)

    if [ $? -ne 0 ]; then
        log_error "Failed to write gateway token to container: $write_output"
        log_error "Remediation steps:"
        log_error "  1. Check container is running: docker ps"
        log_error "  2. Verify /run/secrets is writable in container"
        return 1
    fi

    return 0
}

# Get container IP address
# Args:
#   $1 - container_id: Docker container ID
#   $2 - network: Network name (optional, default: credential-isolation)
# Returns:
#   Prints IP address to stdout
get_container_ip() {
    local container_id="$1"
    local network="${2:-credential-isolation}"

    # Use index function for network names with special characters (hyphens, underscores)
    docker inspect -f "{{(index .NetworkSettings.Networks \"${network}\").IPAddress}}" "$container_id" 2>/dev/null
}

# Setup gateway session for a container
# This is the main entry point for new.sh integration
# Args:
#   $1 - container_id: Docker container ID
#   $2 - repos: Optional comma-separated list of repos
# Returns:
#   0 on success, 1 on failure
setup_gateway_session() {
    local container_id="$1"
    local repos="${2:-}"

    log_info "Setting up gateway session for container $container_id..."

    # Wait for gateway to be healthy
    if ! wait_for_gateway_health 30; then
        return 1
    fi

    # Get container IP on credential-isolation network
    local container_ip
    container_ip=$(get_container_ip "$container_id" "credential-isolation")

    if [ -z "$container_ip" ]; then
        # Try default network name pattern
        container_ip=$(get_container_ip "$container_id" "${container_id%-dev-1}_credential-isolation")
    fi

    if [ -z "$container_ip" ]; then
        log_error "Could not determine container IP address on credential-isolation network"
        log_error "Remediation steps:"
        log_error "  1. Verify container is connected to credential-isolation network"
        log_error "  2. Check docker-compose.credential-isolation.yml network configuration"
        log_error "  3. Try: docker network inspect credential-isolation"
        return 1
    fi

    log_debug "Container IP: $container_ip"

    # Create session via gateway API
    if ! create_gateway_session "$container_id" "$container_ip" "$repos"; then
        return 1
    fi

    # Write token to container
    if ! write_gateway_token_to_container "$container_id" "$GATEWAY_TOKEN" "$GATEWAY_SECRET"; then
        # Clean up session on failure
        destroy_gateway_session "$GATEWAY_TOKEN"
        return 1
    fi

    log_info "Gateway session created successfully"
    return 0
}

# Cleanup gateway session for a container being destroyed
# Reads the token from the container and destroys the session
# Gracefully handles missing tokens or failed destruction
# Args:
#   $1 - container_id: Docker container ID
# Returns:
#   0 always (cleanup should not block destroy)
cleanup_gateway_session() {
    local container_id="$1"

    if [ -z "$container_id" ]; then
        return 0
    fi

    # Check if gateway URL is configured (credential isolation enabled)
    if [ -z "$GATEWAY_URL" ]; then
        log_debug "Gateway URL not configured - skipping session cleanup"
        return 0
    fi

    # Try to read token from container
    local token_data
    token_data=$(docker exec "$container_id" cat /run/secrets/gateway_token 2>/dev/null || true)

    if [ -z "$token_data" ]; then
        log_debug "No gateway token found in container - skipping session cleanup"
        return 0
    fi

    # Token format is "token:secret" - extract just the token part
    local token="${token_data%%:*}"

    if [ -z "$token" ]; then
        log_debug "Invalid gateway token format - skipping session cleanup"
        return 0
    fi

    log_info "Cleaning up gateway session..."

    # Destroy session - ignore failures (session may already be expired)
    if destroy_gateway_session "$token"; then
        log_debug "Gateway session destroyed"
    else
        log_debug "Gateway session destruction returned error (may be already expired)"
    fi

    return 0
}
