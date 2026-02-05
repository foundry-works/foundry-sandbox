#!/bin/bash
# Proxy interaction functions for container registration
#
# This module provides shell functions to interact with the unified proxy's
# internal API for container registration and lifecycle management.
#
# Security Model:
# - Communicates with proxy via Unix socket only
# - Used by container lifecycle scripts (new.sh, destroy.sh)
# - Not exposed to containers themselves
#
# Environment:
# - PROXY_SOCKET_PATH: Full path to proxy internal API socket (host-side)
# - PROXY_CONTAINER_NAME: Explicit unified-proxy container name
# - PROXY_URL: Alternative HTTP URL for proxy (for development/testing)
#     If set, uses HTTP instead of Unix socket

proxy_container_name() {
    if [ -n "${PROXY_CONTAINER_NAME:-}" ]; then
        echo "$PROXY_CONTAINER_NAME"
        return
    fi
    if [ -n "${CONTAINER_NAME:-}" ]; then
        echo "${CONTAINER_NAME}-unified-proxy-1"
        return
    fi
}

proxy_curl() {
    local method="$1"
    local path="$2"
    local data="${3:-}"

    if [ -n "${PROXY_URL:-}" ]; then
        if [ -n "$data" ]; then
            curl -s -X "$method" -H "Content-Type: application/json" -d "$data" "${PROXY_URL}${path}"
        else
            curl -s -X "$method" "${PROXY_URL}${path}"
        fi
        return $?
    fi

    # Prefer host socket if explicitly provided
    if [ -n "${PROXY_SOCKET_PATH:-}" ]; then
        if [ -n "$data" ]; then
            curl -s --unix-socket "$PROXY_SOCKET_PATH" -X "$method" -H "Content-Type: application/json" -d "$data" "http://localhost${path}"
        else
            curl -s --unix-socket "$PROXY_SOCKET_PATH" -X "$method" "http://localhost${path}"
        fi
        return $?
    fi

    # Fallback: exec into unified-proxy container and use its Unix socket
    local proxy_container
    proxy_container="$(proxy_container_name)"
    if [ -z "$proxy_container" ]; then
        log_error "proxy_curl: PROXY_CONTAINER_NAME or CONTAINER_NAME required"
        return 1
    fi

    if [ -n "$data" ]; then
        docker exec "$proxy_container" curl -s \
            --unix-socket /var/run/proxy/internal.sock \
            -X "$method" -H "Content-Type: application/json" -d "$data" \
            "http://localhost${path}"
    else
        docker exec "$proxy_container" curl -s \
            --unix-socket /var/run/proxy/internal.sock \
            -X "$method" \
            "http://localhost${path}"
    fi
}

# Register a container with the proxy
# Args:
#   $1 - container_id: The container ID
#   $2 - ip_address: The container's IP address
#   $3 - ttl_seconds: Optional TTL in seconds (default: 86400 = 24 hours)
#   $4 - metadata_json: Optional metadata as JSON object
# Returns:
#   0 on success, 1 on failure
#   Outputs registration response to stdout on success
proxy_register() {
    local container_id="$1"
    local ip_address="$2"
    local ttl_seconds="${3:-86400}"
    local metadata_json="${4:-}"

    if [ -z "$container_id" ] || [ -z "$ip_address" ]; then
        log_error "proxy_register: container_id and ip_address required"
        return 1
    fi

    # Build JSON request body using jq for safe escaping
    local json_body
    if [ -n "$metadata_json" ]; then
        json_body=$(jq -n \
            --arg cid "$container_id" \
            --arg ip "$ip_address" \
            --argjson ttl "$ttl_seconds" \
            --argjson meta "$metadata_json" \
            '{container_id: $cid, ip_address: $ip, ttl_seconds: $ttl, metadata: $meta}')
    else
        json_body=$(jq -n \
            --arg cid "$container_id" \
            --arg ip "$ip_address" \
            --argjson ttl "$ttl_seconds" \
            '{container_id: $cid, ip_address: $ip, ttl_seconds: $ttl}')
    fi

    local response
    local curl_exit

    response=$(proxy_curl "POST" "/internal/containers" "$json_body" 2>&1)
    curl_exit=$?

    if [ $curl_exit -ne 0 ]; then
        log_error "proxy_register: curl error $curl_exit"
        return 1
    fi

    # Check for error in response
    local status
    status=$(echo "$response" | jq -r '.status // empty' 2>/dev/null)

    if [ "$status" = "registered" ]; then
        log_debug "Registered container $container_id with IP $ip_address"
        echo "$response"
        return 0
    fi

    # Extract and log error
    local error_msg
    error_msg=$(echo "$response" | jq -r '.message // .error // "Unknown error"' 2>/dev/null)
    log_error "proxy_register: Failed to register container: $error_msg"
    return 1
}

# Unregister a container from the proxy
# Args:
#   $1 - container_id: The container ID to unregister
# Returns:
#   0 on success (or if container not found - idempotent)
#   1 on communication failure
proxy_unregister() {
    local container_id="$1"

    if [ -z "$container_id" ]; then
        log_error "proxy_unregister: container_id required"
        return 1
    fi

    local response
    local curl_exit
    local http_code

    if [ -n "${PROXY_URL:-}" ]; then
        response=$(curl -s -w "\n%{http_code}" \
            -X DELETE \
            "${PROXY_URL}/internal/containers/$container_id" 2>&1)
        curl_exit=$?
    elif [ -n "${PROXY_SOCKET_PATH:-}" ]; then
        response=$(curl -s -w "\n%{http_code}" \
            --unix-socket "$PROXY_SOCKET_PATH" \
            -X DELETE \
            "http://localhost/internal/containers/$container_id" 2>&1)
        curl_exit=$?
    else
        local proxy_container
        proxy_container="$(proxy_container_name)"
        if [ -z "$proxy_container" ]; then
            log_debug "proxy_unregister: proxy container not available"
            return 0
        fi
        response=$(docker exec "$proxy_container" curl -s -w "\n%{http_code}" \
            --unix-socket /var/run/proxy/internal.sock \
            -X DELETE \
            "http://localhost/internal/containers/$container_id" 2>&1)
        curl_exit=$?
    fi

    if [ $curl_exit -ne 0 ]; then
        log_warn "proxy_unregister: curl error $curl_exit (may be expected if proxy stopped)"
        return 0  # Don't fail destroy on proxy communication errors
    fi

    # Extract HTTP code from last line
    http_code=$(echo "$response" | tail -n1)
    response=$(echo "$response" | sed '$d')

    case "$http_code" in
        200)
            log_debug "Unregistered container $container_id"
            return 0
            ;;
        404)
            log_debug "Container $container_id not found (already unregistered)"
            return 0  # Idempotent - not found is success
            ;;
        *)
            local error_msg
            error_msg=$(echo "$response" | jq -r '.message // .error // "Unknown error"' 2>/dev/null)
            log_warn "proxy_unregister: Unexpected response ($http_code): $error_msg"
            return 0  # Don't fail destroy on unexpected responses
            ;;
    esac
}

# Wait for proxy to be ready with exponential backoff
# Args:
#   $1 - timeout_seconds: Maximum time to wait (default: 30)
# Returns:
#   0 if proxy is healthy within timeout
#   1 if timeout reached
proxy_wait_ready() {
    local timeout="${1:-30}"
    local elapsed=0
    local delay=1
    local max_delay=8

    log_debug "Waiting for proxy to be ready (timeout: ${timeout}s)..."

    while [ $elapsed -lt "$timeout" ]; do
        local response
        local http_code
        local curl_exit

        if [ -n "${PROXY_URL:-}" ]; then
            response=$(curl -s -w "\n%{http_code}" "${PROXY_URL}/internal/health" 2>&1)
            curl_exit=$?
        elif [ -n "${PROXY_SOCKET_PATH:-}" ]; then
            response=$(curl -s -w "\n%{http_code}" \
                --unix-socket "$PROXY_SOCKET_PATH" \
                "http://localhost/internal/health" 2>&1)
            curl_exit=$?
        else
            local proxy_container
            proxy_container="$(proxy_container_name)"
            if [ -z "$proxy_container" ]; then
                curl_exit=1
            else
                response=$(docker exec "$proxy_container" curl -s -w "\n%{http_code}" \
                    --unix-socket /var/run/proxy/internal.sock \
                    "http://localhost/internal/health" 2>&1)
                curl_exit=$?
            fi
        fi

        if [ $curl_exit -eq 0 ]; then
            http_code=$(echo "$response" | tail -n1)
            response=$(echo "$response" | sed '$d')

            if [ "$http_code" = "200" ]; then
                local status
                status=$(echo "$response" | jq -r '.status // empty' 2>/dev/null)
                if [ "$status" = "healthy" ]; then
                    log_debug "Proxy is ready (took ${elapsed}s)"
                    return 0
                fi
            fi
        fi

        # Exponential backoff: 1, 2, 4, 8, 8, 8... seconds
        if [ $((elapsed + delay)) -gt "$timeout" ]; then
            delay=$((timeout - elapsed))
        fi

        sleep "$delay"
        elapsed=$((elapsed + delay))

        # Increase delay for next iteration (exponential backoff)
        if [ $delay -lt $max_delay ]; then
            delay=$((delay * 2))
            if [ $delay -gt $max_delay ]; then
                delay=$max_delay
            fi
        fi
    done

    log_error "Proxy health check timed out after ${timeout}s"
    log_error "Remediation steps:"
    log_error "  1. Check if proxy container is running: docker ps | grep unified-proxy"
    log_error "  2. View proxy logs: docker logs <proxy-container>"
    log_error "  3. Check internal API: docker exec <proxy-container> curl --unix-socket /var/run/proxy/internal.sock http://localhost/internal/health"
    return 1
}

# Get container IP address on the credential-isolation network
# Args:
#   $1 - container_id: Docker container ID
#   $2 - network: Network name (default: credential-isolation)
# Returns:
#   Prints IP address to stdout, empty if not found
proxy_get_container_ip() {
    local container_id="$1"
    local network="${2:-credential-isolation}"

    # Use index function for network names with special characters
    docker inspect -f "{{(index .NetworkSettings.Networks \"${network}\").IPAddress}}" "$container_id" 2>/dev/null
}

# Setup proxy registration for a container
# This is the main entry point for integration with sandbox startup
# Handles the full registration lifecycle with proper error handling
# Args:
#   $1 - container_id: Docker container ID
#   $2 - metadata_json: Optional JSON metadata (default: empty)
# Returns:
#   0 on success, 1 on failure (fails sandbox start)
setup_proxy_registration() {
    local container_id="$1"
    local metadata_json="${2:-}"

    log_debug "Setting up proxy registration for container $container_id..."

    # Wait for proxy to be ready (with 30s timeout)
    if ! proxy_wait_ready 30; then
        return 1
    fi

    # Get container IP on credential-isolation network
    local container_ip
    container_ip=$(proxy_get_container_ip "$container_id" "credential-isolation")

    if [ -z "$container_ip" ]; then
        # Try with project prefix pattern (e.g., myproject_credential-isolation)
        local project_prefix="${container_id%-dev-1}"
        container_ip=$(proxy_get_container_ip "$container_id" "${project_prefix}_credential-isolation")
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

    # Register with proxy
    if ! proxy_register "$container_id" "$container_ip" 86400 "$metadata_json" > /dev/null; then
        return 1
    fi

    log_debug "Proxy registration complete"
    return 0
}

# Cleanup proxy registration for a container being destroyed
# Best-effort cleanup - should not block sandbox destruction
# Args:
#   $1 - container_id: Docker container ID
# Returns:
#   0 always (cleanup should not block destroy)
cleanup_proxy_registration() {
    local container_id="$1"

    if [ -z "$container_id" ]; then
        return 0
    fi

    log_info "Cleaning up proxy registration..."

    # Unregister - ignore failures (proxy may be stopped)
    proxy_unregister "$container_id" || true

    return 0
}

# Check if a container is registered with the proxy
# Args:
#   $1 - container_id: Docker container ID
# Returns:
#   0 if registered, 1 if not registered or error
proxy_is_registered() {
    local container_id="$1"

    if [ -z "$container_id" ]; then
        return 1
    fi

    local response
    local http_code
    local curl_exit

    if [ -n "${PROXY_URL:-}" ]; then
        response=$(curl -s -w "\n%{http_code}" \
            "${PROXY_URL}/internal/containers/$container_id" 2>&1)
        curl_exit=$?
    elif [ -n "${PROXY_SOCKET_PATH:-}" ]; then
        response=$(curl -s -w "\n%{http_code}" \
            --unix-socket "$PROXY_SOCKET_PATH" \
            "http://localhost/internal/containers/$container_id" 2>&1)
        curl_exit=$?
    else
        local proxy_container
        proxy_container="$(proxy_container_name)"
        if [ -z "$proxy_container" ]; then
            return 1
        fi
        response=$(docker exec "$proxy_container" curl -s -w "\n%{http_code}" \
            --unix-socket /var/run/proxy/internal.sock \
            "http://localhost/internal/containers/$container_id" 2>&1)
        curl_exit=$?
    fi

    if [ $curl_exit -ne 0 ]; then
        return 1
    fi

    http_code=$(echo "$response" | tail -n1)

    if [ "$http_code" = "200" ]; then
        return 0
    else
        return 1
    fi
}
