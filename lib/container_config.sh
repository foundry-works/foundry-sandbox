#!/bin/bash

copy_configs_to_container() {
    local container_id="$1"
    local claude_config_path="$2"

    log_info "Copying config files into container..."

    run_cmd docker exec "$container_id" mkdir -p \
        "$CONTAINER_HOME/.claude" \
        "$CONTAINER_HOME/.config/gh" \
        "$CONTAINER_HOME/.config/ccstatusline" \
        "$CONTAINER_HOME/.gemini" \
        "$CONTAINER_HOME/.config/opencode" \
        "$CONTAINER_HOME/.local/share/opencode" \
        "$CONTAINER_HOME/.cursor" \
        "$CONTAINER_HOME/.codex" \
        "$CONTAINER_HOME/.ssh"

    dir_exists "$claude_config_path" && run_cmd docker cp "$claude_config_path/." "$container_id:$CONTAINER_HOME/.claude/"
    dir_exists ~/.config/gh && run_cmd docker cp ~/.config/gh/. "$container_id:$CONTAINER_HOME/.config/gh/"
    dir_exists ~/.config/ccstatusline && run_cmd docker cp ~/.config/ccstatusline/. "$container_id:$CONTAINER_HOME/.config/ccstatusline/"
    dir_exists ~/.gemini && run_cmd docker cp ~/.gemini/. "$container_id:$CONTAINER_HOME/.gemini/"
    dir_exists ~/.config/opencode && run_cmd docker cp ~/.config/opencode/. "$container_id:$CONTAINER_HOME/.config/opencode/"
    file_exists ~/.local/share/opencode/auth.json && run_cmd docker cp ~/.local/share/opencode/auth.json "$container_id:$CONTAINER_HOME/.local/share/opencode/auth.json"
    dir_exists ~/.cursor && run_cmd docker cp ~/.cursor/. "$container_id:$CONTAINER_HOME/.cursor/"
    dir_exists ~/.codex && run_cmd docker cp ~/.codex/. "$container_id:$CONTAINER_HOME/.codex/"
    file_exists ~/.gitconfig && run_cmd docker cp ~/.gitconfig "$container_id:$CONTAINER_HOME/.gitconfig"
    dir_exists ~/.ssh && run_cmd docker cp ~/.ssh/. "$container_id:$CONTAINER_HOME/.ssh/"
    file_exists ~/.api_keys && run_cmd docker cp ~/.api_keys "$container_id:$CONTAINER_HOME/.api_keys"

    if dir_exists ~/.sandboxes/repos; then
        run_cmd docker exec "$container_id" mkdir -p "$CONTAINER_HOME/.sandboxes"
        run_cmd docker cp ~/.sandboxes/repos/. "$container_id:$CONTAINER_HOME/.sandboxes/repos/"
    fi

    log_info "Fixing ownership..."
    run_cmd docker exec "$container_id" sh -c "
        chown -R $CONTAINER_USER:$CONTAINER_USER \
            $CONTAINER_HOME/.claude \
            $CONTAINER_HOME/.config \
            $CONTAINER_HOME/.gemini \
            $CONTAINER_HOME/.cursor \
            $CONTAINER_HOME/.codex \
            $CONTAINER_HOME/.ssh \
            $CONTAINER_HOME/.sandboxes \
            $CONTAINER_HOME/.local/share/opencode \
            2>/dev/null
        chown $CONTAINER_USER:$CONTAINER_USER $CONTAINER_HOME/.gitconfig $CONTAINER_HOME/.api_keys 2>/dev/null
        chmod 700 $CONTAINER_HOME/.ssh 2>/dev/null
        chmod 600 $CONTAINER_HOME/.ssh/* 2>/dev/null
    " || true
}

sync_runtime_credentials() {
    local container_id="$1"
    local claude_config_path="$2"

    cp "$HOME/.claude/.credentials.json" "$claude_config_path/" 2>/dev/null || true
    run_cmd docker cp "$claude_config_path/.credentials.json" "$container_id:$CONTAINER_HOME/.claude/.credentials.json" 2>/dev/null || true

    dir_exists ~/.codex && run_cmd docker cp ~/.codex/. "$container_id:$CONTAINER_HOME/.codex/" 2>/dev/null
    dir_exists ~/.config/gh && run_cmd docker cp ~/.config/gh/. "$container_id:$CONTAINER_HOME/.config/gh/" 2>/dev/null
    dir_exists ~/.gemini && run_cmd docker cp ~/.gemini/. "$container_id:$CONTAINER_HOME/.gemini/" 2>/dev/null
    dir_exists ~/.config/opencode && run_cmd docker cp ~/.config/opencode/. "$container_id:$CONTAINER_HOME/.config/opencode/" 2>/dev/null
    file_exists ~/.local/share/opencode/auth.json && run_cmd docker cp ~/.local/share/opencode/auth.json "$container_id:$CONTAINER_HOME/.local/share/opencode/auth.json" 2>/dev/null
    dir_exists ~/.cursor && run_cmd docker cp ~/.cursor/. "$container_id:$CONTAINER_HOME/.cursor/" 2>/dev/null
    file_exists ~/.api_keys && run_cmd docker cp ~/.api_keys "$container_id:$CONTAINER_HOME/.api_keys" 2>/dev/null
}
