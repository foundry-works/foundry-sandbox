#!/bin/bash

copy_configs_to_container() {
    local container_id="$1"

    log_info "Copying config files into container..."

    # Home is tmpfs; wait briefly for it to be ready before copying.
    local attempts=0
    while ! docker exec "$container_id" test -d "$CONTAINER_HOME/.config" 2>/dev/null; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 5 ]; then
            break
        fi
        sleep 0.2
    done

    run_cmd docker exec "$container_id" mkdir -p \
        "$CONTAINER_HOME/.config/gh" \
        "$CONTAINER_HOME/.config/ccstatusline" \
        "$CONTAINER_HOME/.gemini" \
        "$CONTAINER_HOME/.config/opencode" \
        "$CONTAINER_HOME/.local/share/opencode" \
        "$CONTAINER_HOME/.cursor" \
        "$CONTAINER_HOME/.codex" \
        "$CONTAINER_HOME/.ssh"

    # Claude plugin is pre-baked into Docker image; auth via CLAUDE_CODE_OAUTH_TOKEN in ~/.api_keys
    dir_exists ~/.config/gh && copy_dir_to_container "$container_id" ~/.config/gh "$CONTAINER_HOME/.config/gh"
    dir_exists ~/.config/ccstatusline && copy_dir_to_container "$container_id" ~/.config/ccstatusline "$CONTAINER_HOME/.config/ccstatusline"
    # Gemini CLI OAuth credentials (created via `gemini auth` on host)
    dir_exists ~/.gemini && copy_dir_to_container "$container_id" ~/.gemini "$CONTAINER_HOME/.gemini"
    dir_exists ~/.config/opencode && copy_dir_to_container "$container_id" ~/.config/opencode "$CONTAINER_HOME/.config/opencode"
    file_exists ~/.local/share/opencode/auth.json && copy_file_to_container "$container_id" ~/.local/share/opencode/auth.json "$CONTAINER_HOME/.local/share/opencode/auth.json"
    dir_exists ~/.cursor && copy_dir_to_container "$container_id" ~/.cursor "$CONTAINER_HOME/.cursor"
    dir_exists ~/.codex && copy_dir_to_container "$container_id" ~/.codex "$CONTAINER_HOME/.codex"
    file_exists ~/.gitconfig && copy_file_to_container "$container_id" ~/.gitconfig "$CONTAINER_HOME/.gitconfig"
    dir_exists ~/.ssh && copy_dir_to_container "$container_id" ~/.ssh "$CONTAINER_HOME/.ssh"
    file_exists ~/.api_keys && copy_file_to_container "$container_id" ~/.api_keys "$CONTAINER_HOME/.api_keys"

    dir_exists ~/.sandboxes/repos && copy_dir_to_container "$container_id" ~/.sandboxes/repos "$CONTAINER_HOME/.sandboxes/repos"

    log_info "Fixing ownership..."
    run_cmd docker exec "$container_id" sh -c "
        chown -R $CONTAINER_USER:$CONTAINER_USER \
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

    # Sync credentials for various AI tools (Claude uses CLAUDE_CODE_OAUTH_TOKEN from ~/.api_keys)
    dir_exists ~/.codex && copy_dir_to_container_quiet "$container_id" ~/.codex "$CONTAINER_HOME/.codex"
    dir_exists ~/.config/gh && copy_dir_to_container_quiet "$container_id" ~/.config/gh "$CONTAINER_HOME/.config/gh"
    dir_exists ~/.gemini && copy_dir_to_container_quiet "$container_id" ~/.gemini "$CONTAINER_HOME/.gemini"
    dir_exists ~/.config/opencode && copy_dir_to_container_quiet "$container_id" ~/.config/opencode "$CONTAINER_HOME/.config/opencode"
    file_exists ~/.local/share/opencode/auth.json && copy_file_to_container_quiet "$container_id" ~/.local/share/opencode/auth.json "$CONTAINER_HOME/.local/share/opencode/auth.json"
    dir_exists ~/.cursor && copy_dir_to_container_quiet "$container_id" ~/.cursor "$CONTAINER_HOME/.cursor"
    file_exists ~/.api_keys && copy_file_to_container_quiet "$container_id" ~/.api_keys "$CONTAINER_HOME/.api_keys"
}

copy_dir_to_container() {
    local container_id="$1"
    local src="$2"
    local dst="$3"
    local attempts=0

    while true; do
        run_cmd docker exec "$container_id" mkdir -p "$dst"
        if [ "$SANDBOX_VERBOSE" = "1" ]; then
            echo "+ COPYFILE_DISABLE=1 tar -C \"$src\" -cf - . | docker exec -i \"$container_id\" tar -C \"$dst\" -xf -"
        fi
        # COPYFILE_DISABLE=1 prevents macOS tar from including extended attributes
        if COPYFILE_DISABLE=1 tar -C "$src" -cf - . | docker exec -i "$container_id" tar -C "$dst" -xf -; then
            return 0
        fi
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 5 ]; then
            return 1
        fi
        sleep 0.2
    done
}

copy_file_to_container() {
    local container_id="$1"
    local src="$2"
    local dst="$3"
    local attempts=0
    local parent_dir
    parent_dir="$(dirname "$dst")"
    local src_dir
    src_dir="$(dirname "$src")"
    local src_base
    src_base="$(basename "$src")"

    while true; do
        run_cmd docker exec "$container_id" mkdir -p "$parent_dir"
        if [ "$SANDBOX_VERBOSE" = "1" ]; then
            echo "+ COPYFILE_DISABLE=1 tar -C \"$src_dir\" -cf - \"$src_base\" | docker exec -i \"$container_id\" tar -C \"$parent_dir\" -xf -"
        fi
        # COPYFILE_DISABLE=1 prevents macOS tar from including extended attributes
        if COPYFILE_DISABLE=1 tar -C "$src_dir" -cf - "$src_base" | docker exec -i "$container_id" tar -C "$parent_dir" -xf -; then
            return 0
        fi
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 5 ]; then
            return 1
        fi
        sleep 0.2
    done
}

copy_dir_to_container_quiet() {
    copy_dir_to_container "$@" 2>/dev/null
}

copy_file_to_container_quiet() {
    copy_file_to_container "$@" 2>/dev/null
}
