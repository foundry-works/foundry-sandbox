#!/bin/bash

get_compose_command() {
    local override_file="$1"
    local compose_cmd="docker compose -f $SCRIPT_DIR/docker-compose.yml"
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

    export WORKSPACE_PATH="$worktree_path"
    export CLAUDE_CONFIG_PATH="$claude_config_path"
    export CONTAINER_NAME="$container"

    local compose_cmd
    compose_cmd=$(get_compose_command "$override_file")
    run_cmd $compose_cmd -p "$container" up -d
}

compose_down() {
    local worktree_path="$1"
    local claude_config_path="$2"
    local container="$3"
    local override_file="$4"
    local remove_volumes="$5"

    export WORKSPACE_PATH="$worktree_path"
    export CLAUDE_CONFIG_PATH="$claude_config_path"
    export CONTAINER_NAME="$container"

    local compose_cmd
    compose_cmd=$(get_compose_command "$override_file")
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
