#!/bin/bash

path_worktree() {
    local name="$1"
    echo "$WORKTREES_DIR/$name"
}

path_claude_config() {
    local name="$1"
    echo "$CLAUDE_CONFIGS_DIR/$name"
}

path_claude_home() {
    local name="$1"
    echo "$CLAUDE_CONFIGS_DIR/$name/claude"
}

path_override_file() {
    local name="$1"
    echo "$CLAUDE_CONFIGS_DIR/$name/docker-compose.override.yml"
}

path_metadata_file() {
    local name="$1"
    echo "$CLAUDE_CONFIGS_DIR/$name/metadata.json"
}

path_metadata_legacy_file() {
    local name="$1"
    echo "$CLAUDE_CONFIGS_DIR/$name/metadata.env"
}

path_opencode_plugins_marker() {
    local name="$1"
    echo "$CLAUDE_CONFIGS_DIR/$name/opencode-plugins.synced"
}

# Preset and history paths
path_last_cast_new() {
    echo "$SANDBOX_HOME/.last-cast-new.json"
}

path_last_attach() {
    echo "$SANDBOX_HOME/.last-attach.json"
}

path_presets_dir() {
    echo "$SANDBOX_HOME/presets"
}

path_preset_file() {
    local name="$1"
    echo "$SANDBOX_HOME/presets/${name}.json"
}

# Sets DERIVED_* globals using the path helpers.
derive_sandbox_paths() {
    local name="$1"
    DERIVED_WORKTREE_PATH="$(path_worktree "$name")"
    DERIVED_CONTAINER_NAME="$(container_name "$name")"
    DERIVED_CLAUDE_CONFIG_PATH="$(path_claude_config "$name")"
    DERIVED_CLAUDE_HOME_PATH="$(path_claude_home "$name")"
    DERIVED_OVERRIDE_FILE="$(path_override_file "$name")"
}
