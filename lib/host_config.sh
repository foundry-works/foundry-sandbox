#!/bin/bash

setup_claude_config() {
    local claude_config_path="$1"

    ensure_dir "$claude_config_path"
    cp "$HOME/.claude/.claude.json" "$claude_config_path/" 2>/dev/null || true
    cp "$HOME/.claude/settings.json" "$claude_config_path/" 2>/dev/null || true
    cp "$HOME/.claude/settings.local.json" "$claude_config_path/" 2>/dev/null || true
    cp "$HOME/.claude/.credentials.json" "$claude_config_path/" 2>/dev/null || true
    cp -rL "$HOME/.claude/plugins" "$claude_config_path/" 2>/dev/null || true

    fix_plugin_paths "$claude_config_path"
}

fix_plugin_paths() {
    local claude_config_path="$1"
    for f in "$claude_config_path/plugins/installed_plugins.json" "$claude_config_path/plugins/known_marketplaces.json"; do
        file_exists "$f" && sed_inplace "s|$HOME/.claude|$CONTAINER_HOME/.claude|g" "$f"
    done
}
