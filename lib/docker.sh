#!/bin/bash

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

    # Set up gateway socket directory for credential isolation
    if [ "$isolate_credentials" = "true" ]; then
        export GATEWAY_SOCKET_DIR="/tmp/foundry-gateway-${container}"
        mkdir -p "$GATEWAY_SOCKET_DIR"
        chmod 700 "$GATEWAY_SOCKET_DIR"
        # Export for gateway.sh to use
        export GATEWAY_SOCKET_PATH="${GATEWAY_SOCKET_DIR}/gateway.sock"
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

    # Set gateway socket path for credential isolation
    if [ "$isolate_credentials" = "true" ]; then
        export GATEWAY_SOCKET_DIR="/tmp/foundry-gateway-${container}"
        export GATEWAY_SOCKET_PATH="${GATEWAY_SOCKET_DIR}/gateway.sock"
    fi

    compose_cmd=$(get_compose_command "$override_file" "$isolate_credentials")
    if [ "$remove_volumes" = "true" ]; then
        run_cmd $compose_cmd -p "$container" down -v
        # Clean up gateway socket directory
        if [ -d "/tmp/foundry-gateway-${container}" ]; then
            rm -rf "/tmp/foundry-gateway-${container}" 2>/dev/null || true
        fi
    else
        run_cmd $compose_cmd -p "$container" down
    fi
}

container_is_running() {
    local container="$1"
    docker ps --filter "name=^${container}-dev" --format "{{.Names}}" | grep -q .
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
