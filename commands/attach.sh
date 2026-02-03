#!/bin/bash

# Source dependent commands
source "${SCRIPT_DIR}/commands/list.sh"
source "${SCRIPT_DIR}/commands/start.sh"

cmd_attach() {
    parse_attach_args "$@"

    local name="$ATTACH_NAME"

    # Handle --last flag
    if [ "$ATTACH_USE_LAST" = true ]; then
        if ! load_last_attach; then
            exit 1
        fi
        name="$LAST_ATTACH_NAME"
        echo "Reattaching to: $name"
    fi

    if [ -z "$name" ]; then
        # Try to auto-detect sandbox from current directory
        local cwd
        cwd=$(pwd -P 2>/dev/null || pwd)
        if [[ "$cwd" == "$WORKTREES_DIR/"* ]]; then
            # Extract sandbox name from path (first component after WORKTREES_DIR)
            local relative_path="${cwd#$WORKTREES_DIR/}"
            name="${relative_path%%/*}"
            if [ -n "$name" ] && [ -d "$WORKTREES_DIR/$name" ]; then
                echo "Auto-detected sandbox: $name"
            else
                name=""
            fi
        fi
    fi

    if [ -z "$name" ]; then
        if command -v fzf &>/dev/null && [ -d "$WORKTREES_DIR" ]; then
            name=$(ls -1 "$WORKTREES_DIR" 2>/dev/null | fzf --prompt="Select sandbox: " --height=10 --reverse)
            if [ -z "$name" ]; then
                echo "No sandbox selected."
                exit 1
            fi
        else
            echo "Usage: $0 attach <sandbox-name>"
            echo ""
            cmd_list
            exit 1
        fi
    fi

    derive_sandbox_paths "$name"
    local worktree_path="$DERIVED_WORKTREE_PATH"
    local container="$DERIVED_CONTAINER_NAME"
    local claude_config_path="$DERIVED_CLAUDE_CONFIG_PATH"

    if [ ! -d "$worktree_path" ]; then
        echo "Error: Sandbox '$name' not found"
        cmd_list
        exit 1
    fi

    local container_id="${container}-dev-1"
    if ! container_is_running "$container"; then
        echo "Container not running. Starting..."
        cmd_start "$name"
    else
        # Load metadata to get network mode and other settings
        load_sandbox_metadata "$name" || true

        if [ "${SANDBOX_SYNC_ON_ATTACH:-0}" = "1" ]; then
            sync_runtime_credentials "$container_id"
        else
            log_debug "Skipping credential sync on attach (SANDBOX_SYNC_ON_ATTACH=0)"
        fi

        # Note: Firewall IP refresh removed - wildcard mode handles rotating IPs via DNS filtering
    fi

    # Ensure metadata is loaded for working_dir (may not be loaded if container was started above)
    load_sandbox_metadata "$name" || true

    sync_opencode_local_plugins_on_first_attach "$name" "$container_id"

    # Save this sandbox as the last attached for --last flag
    save_last_attach "$name"

    # IDE launch logic
    local with_ide="$ATTACH_WITH_IDE"
    local ide_only="$ATTACH_IDE_ONLY"
    local skip_terminal=false

    if [ -t 0 ]; then
        if [ "$with_ide" = "none" ]; then
            # --no-ide: skip IDE prompt entirely
            :
        elif [ -n "$with_ide" ] && [ "$with_ide" != "auto" ]; then
            # Specific IDE requested via --with-ide=<name> or --ide-only=<name>
            if auto_launch_ide "$with_ide" "$worktree_path"; then
                if [ "$ide_only" = "true" ]; then
                    skip_terminal=true
                    echo "IDE launched. Run 'cast attach $name' for terminal."
                fi
            fi
        elif [ -n "$with_ide" ]; then
            # --with-ide or --ide-only without specific name: prompt for selection
            prompt_ide_selection "$worktree_path" "$name"
            if [ "$ide_only" = "true" ] || [ "$IDE_WAS_LAUNCHED" = "true" ]; then
                skip_terminal=true
                echo ""
                echo "  Run this in your IDE's terminal to connect:"
                echo ""
                echo "    cast attach $name"
                echo ""
            fi
        fi
        # Default for attach: go directly to terminal (no IDE prompt)
    fi

    if [ "$skip_terminal" = "false" ]; then
        tmux_attach "$name" "$SANDBOX_WORKING_DIR"
    fi
}
