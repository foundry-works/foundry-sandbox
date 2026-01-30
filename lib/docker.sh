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

# Copy and sanitize Gemini settings.json to container
# Removes tools section to start fresh in sandbox, preserving auth preferences
copy_gemini_settings_to_container() {
    local container_id="$1"
    local settings_file="${HOME}/.gemini/settings.json"
    local dest_path="/home/ubuntu/.gemini/settings.json"

    # Skip if settings.json doesn't exist on host
    if [ ! -f "$settings_file" ]; then
        return 0
    fi

    # Check if jq is available
    if ! command -v jq &>/dev/null; then
        log_warn "jq not available; skipping Gemini settings.json sanitization"
        return 0
    fi

    # Read, sanitize (remove tools section), and copy
    local sanitized
    sanitized=$(jq 'del(.tools)' "$settings_file" 2>/dev/null) || return 0

    # Write to temp file and copy to container
    local tmp_file
    tmp_file=$(mktemp)
    echo "$sanitized" > "$tmp_file"

    # Ensure .gemini directory exists and copy file
    docker exec "$container_id" mkdir -p "$(dirname "$dest_path")" 2>/dev/null || true
    docker cp "$tmp_file" "$container_id:$dest_path" 2>/dev/null || true
    docker exec "$container_id" chown ubuntu:ubuntu "$dest_path" 2>/dev/null || true

    rm -f "$tmp_file"
}
