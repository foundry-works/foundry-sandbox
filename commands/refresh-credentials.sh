#!/bin/bash

# Source dependent commands
source "${SCRIPT_DIR}/commands/list.sh"
source "${SCRIPT_DIR}/commands/start.sh"

cmd_refresh_credentials() {
    parse_refresh_credentials_args "$@"

    local name="$REFRESH_CREDS_NAME"

    # Handle --last flag (reuse last attached sandbox)
    if [ "$REFRESH_CREDS_USE_LAST" = true ]; then
        if ! load_last_attach; then
            exit 1
        fi
        name="$LAST_ATTACH_NAME"
        echo "Refreshing credentials for: $name"
    fi

    # Auto-detect from current directory if no name
    if [ -z "$name" ]; then
        local cwd
        cwd=$(pwd -P 2>/dev/null || pwd)
        if [[ "$cwd" == "$WORKTREES_DIR/"* ]]; then
            local relative_path="${cwd#$WORKTREES_DIR/}"
            name="${relative_path%%/*}"
            if [ -n "$name" ] && [ -d "$WORKTREES_DIR/$name" ]; then
                echo "Auto-detected sandbox: $name"
            else
                name=""
            fi
        fi
    fi

    # fzf selection if still no name
    if [ -z "$name" ]; then
        if command -v fzf &>/dev/null && [ -d "$WORKTREES_DIR" ]; then
            name=$(ls -1 "$WORKTREES_DIR" 2>/dev/null | fzf --prompt="Select sandbox: " --height=10 --reverse)
            if [ -z "$name" ]; then
                echo "No sandbox selected."
                exit 1
            fi
        else
            echo "Usage: cast refresh-credentials <sandbox-name>"
            echo ""
            cmd_list
            exit 1
        fi
    fi

    derive_sandbox_paths "$name"
    load_sandbox_metadata "$name" || die "Failed to load sandbox metadata"

    local container="$DERIVED_CONTAINER_NAME"
    local container_id="${container}-dev-1"

    if ! container_is_running "$container"; then
        die "Sandbox '$name' is not running"
    fi

    # Check if credential isolation is enabled (unified-proxy container exists)
    local uses_credential_isolation="0"
    if docker ps -a --format '{{.Names}}' | grep -q "^${container}-unified-proxy-"; then
        uses_credential_isolation="1"
    fi

    if [ "$uses_credential_isolation" = "1" ]; then
        refresh_credentials_isolation_mode "$name" "$container"
    else
        refresh_credentials_direct_mode "$container_id"
    fi
}

refresh_credentials_direct_mode() {
    local container_id="$1"
    echo "Syncing credentials to sandbox..."
    sync_runtime_credentials "$container_id"
    echo "Credentials refreshed successfully."
}

refresh_credentials_isolation_mode() {
    local name="$1"
    local container="$2"
    echo "Restarting unified-proxy to reload credentials..."

    local override_file="$DERIVED_OVERRIDE_FILE"
    local compose_cmd
    compose_cmd=$(get_compose_command "$override_file" "true")

    $compose_cmd -p "$container" restart unified-proxy

    echo "Credentials refreshed (unified-proxy restarted)."
}
