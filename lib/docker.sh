#!/bin/bash

# Detect host auth configuration and export appropriate sandbox env vars
# This determines which placeholder credentials to use based on what's configured on the host
setup_credential_placeholders() {
    # Claude: Use OAuth placeholder if CLAUDE_CODE_OAUTH_TOKEN is set on host
    if [ -n "$CLAUDE_CODE_OAUTH_TOKEN" ]; then
        export SANDBOX_ANTHROPIC_API_KEY=""  # Don't set API key
        export SANDBOX_CLAUDE_OAUTH="CREDENTIAL_PROXY_PLACEHOLDER"
    else
        export SANDBOX_ANTHROPIC_API_KEY="CREDENTIAL_PROXY_PLACEHOLDER"
        export SANDBOX_CLAUDE_OAUTH=""
    fi

    # Gemini: Check selectedType in settings file
    local gemini_settings="$HOME/.gemini/settings.json"
    if [ -f "$gemini_settings" ] && grep -q '"selectedType".*"oauth-personal"' "$gemini_settings"; then
        export SANDBOX_GEMINI_API_KEY=""  # Don't set API key (OAuth in use)
    else
        export SANDBOX_GEMINI_API_KEY="CREDENTIAL_PROXY_PLACEHOLDER"
    fi
}

get_compose_command() {
    local override_file="$1"
    local isolate_credentials="${2:-false}"
    local compose_cmd="docker compose -f $SCRIPT_DIR/docker-compose.yml"
    # Add credential isolation compose file if enabled
    if [ "$isolate_credentials" = "true" ]; then
        compose_cmd="$compose_cmd -f $SCRIPT_DIR/docker-compose.credential-isolation.yml"
    fi
    if [ -n "$override_file" ] && [ -f "$override_file" ]; then
        compose_cmd="$compose_cmd -f $override_file"
    fi
    echo "$compose_cmd"
}

compose_up() {
    local worktree_path="$1"
    local claude_config_path="$2"
    local container="$3"
    local override_file="$4"
    local isolate_credentials="${5:-false}"

    export WORKSPACE_PATH="$worktree_path"
    export CLAUDE_CONFIG_PATH="$claude_config_path"
    export CONTAINER_NAME="$container"

    # For credential isolation, set up placeholders and generate session management key
    if [ "$isolate_credentials" = "true" ]; then
        # Detect host auth config and set appropriate placeholder env vars
        setup_credential_placeholders
        # Generate a random session management key for this sandbox
        export GATEWAY_SESSION_MGMT_KEY=$(openssl rand -base64 32)
        # Populate stubs volume (avoids Docker Desktop bind mount staleness)
        populate_stubs_volume "$container"
        export STUBS_VOLUME_NAME="${container}_stubs"
    fi

    local compose_cmd
    compose_cmd=$(get_compose_command "$override_file" "$isolate_credentials")
    run_cmd $compose_cmd -p "$container" up -d
}

compose_down() {
    local worktree_path="$1"
    local claude_config_path="$2"
    local container="$3"
    local override_file="$4"
    local remove_volumes="$5"
    local isolate_credentials="${6:-false}"

    export WORKSPACE_PATH="$worktree_path"
    export CLAUDE_CONFIG_PATH="$claude_config_path"
    export CONTAINER_NAME="$container"

    local compose_cmd
    if [ "$isolate_credentials" != "true" ]; then
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}-api-proxy-"; then
            isolate_credentials="true"
        fi
    fi

    compose_cmd=$(get_compose_command "$override_file" "$isolate_credentials")
    if [ "$remove_volumes" = "true" ]; then
        run_cmd $compose_cmd -p "$container" down -v
    else
        run_cmd $compose_cmd -p "$container" down
    fi
}

container_is_running() {
    local container="$1"
    docker ps --filter "name=^${container}-dev" --format "{{.Names}}" | grep -q .
}

# Get the gateway host port for a container (credential isolation)
# Args:
#   $1 - container: The container project name
# Returns:
#   Prints the host port to stdout, or empty if not found
get_gateway_host_port() {
    local container="$1"
    local gateway_container="${container}-gateway-1"

    # Get the host port mapped to container port 8080
    docker port "$gateway_container" 8080 2>/dev/null | head -1 | sed 's/.*://'
}

# Set up GATEWAY_URL after containers start
# Args:
#   $1 - container: The container project name
# Returns:
#   0 on success, 1 on failure
#   Sets GATEWAY_URL environment variable
setup_gateway_url() {
    local container="$1"
    local port

    port=$(get_gateway_host_port "$container")
    if [ -z "$port" ]; then
        return 1
    fi

    export GATEWAY_URL="http://127.0.0.1:${port}"
    return 0
}

exec_in_container() {
    local container_id="$1"
    shift
    run_cmd docker exec "$container_id" "$@"
}

copy_to_container() {
    local src="$1"
    local container_id="$2"
    local dst="$3"
    run_cmd docker cp "$src" "$container_id:$dst"
}

# Populate the stubs volume for credential isolation
# Uses a temporary alpine container to copy stub files into the volume
# This avoids Docker Desktop's VirtioFS/gRPC-FUSE file sync staleness issues
populate_stubs_volume() {
    local container="$1"
    local volume_name="${container}_stubs"

    docker volume create "$volume_name" >/dev/null 2>&1 || true

    docker run --rm \
        -v "$SCRIPT_DIR/api-proxy:/src:ro" \
        -v "${volume_name}:/stubs" \
        alpine:latest \
        sh -c 'cp /src/stub-*.json /src/stub-*.yml /stubs/ 2>/dev/null || cp /src/stub-*.json /stubs/' || return 1
}

# Remove the stubs volume for a sandbox
remove_stubs_volume() {
    local container="$1"
    docker volume rm "${container}_stubs" 2>/dev/null || true
}
