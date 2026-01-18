#!/bin/bash

path_worktree() {
    local name="$1"
    echo "$WORKTREES_DIR/$name"
}

path_claude_config() {
    local name="$1"
    echo "$CLAUDE_CONFIGS_DIR/$name"
}

path_override_file() {
    local name="$1"
    echo "$CLAUDE_CONFIGS_DIR/$name/docker-compose.override.yml"
}

path_metadata_file() {
    local name="$1"
    echo "$CLAUDE_CONFIGS_DIR/$name/metadata.env"
}

# Sets DERIVED_* globals using the path helpers.
derive_sandbox_paths() {
    local name="$1"
    DERIVED_WORKTREE_PATH="$(path_worktree "$name")"
    DERIVED_CONTAINER_NAME="$(container_name "$name")"
    DERIVED_CLAUDE_CONFIG_PATH="$(path_claude_config "$name")"
    DERIVED_OVERRIDE_FILE="$(path_override_file "$name")"
}
