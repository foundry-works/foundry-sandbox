#!/bin/bash

# IDE detection and launch utilities

# IDE commands (in preference order)
IDE_COMMANDS=("cursor" "zed" "code")

# Check if an IDE command exists
ide_exists() {
    local ide="$1"
    command -v "$ide" &>/dev/null
}

# Detect available IDEs
# Returns space-separated list of available IDE commands
detect_available_ides() {
    local available=()
    for ide in "${IDE_COMMANDS[@]}"; do
        if ide_exists "$ide"; then
            available+=("$ide")
        fi
    done
    echo "${available[*]}"
}

# Get display name for an IDE (bash 3.2 compatible)
ide_display_name() {
    local ide="$1"
    case "$ide" in
        cursor) echo "Cursor" ;;
        zed) echo "Zed" ;;
        code) echo "VS Code" ;;
        *) echo "$ide" ;;
    esac
}

# Launch IDE with the given path in background
# Args: $1 = IDE command, $2 = path to open
launch_ide() {
    local ide="$1"
    local path="$2"
    local display_name
    display_name=$(ide_display_name "$ide")

    echo "Launching $display_name..."

    # Launch in background, redirecting output to /dev/null
    nohup "$ide" "$path" >/dev/null 2>&1 &
    disown 2>/dev/null || true
}

# Launch a specific IDE by name
# Args: $1 = IDE name (cursor, zed, code), $2 = path to open
# Returns: 0 on success, 1 if IDE not found
auto_launch_ide() {
    local ide_request="$1"
    local path="$2"

    if [ -z "$ide_request" ] || [ "$ide_request" = "auto" ]; then
        # No specific IDE - caller should use prompt_ide_selection instead
        return 1
    fi

    if ide_exists "$ide_request"; then
        launch_ide "$ide_request" "$path"
        return 0
    else
        local display_name
        display_name=$(ide_display_name "$ide_request")
        echo "Warning: $display_name ($ide_request) not found"
        return 1
    fi
}

# Interactive IDE selection prompt
# Args: $1 = path to open, $2 = sandbox name (for terminal-only message)
# Returns: 0 always (callers should check IDE_WAS_LAUNCHED)
# Sets: IDE_WAS_LAUNCHED=true if an IDE was successfully launched
prompt_ide_selection() {
    local path="$1"
    local sandbox_name="$2"

    # Reset global
    IDE_WAS_LAUNCHED=false

    # Only prompt in interactive mode
    [ ! -t 0 ] && return 0

    local available
    available=$(detect_available_ides)

    # No IDEs available - fall through silently
    if [ -z "$available" ]; then
        return 0
    fi

    # Build options array
    local options=()
    for ide in $available; do
        options+=("$(ide_display_name "$ide")")
    done
    options+=("Terminal only")

    echo ""
    echo "  Launch an editor?"
    echo ""

    local selection
    if has_gum; then
        selection=$(printf '%s\n' "${options[@]}" | gum choose --cursor "  > " --cursor-prefix "" --selected-prefix "  > " --unselected-prefix "    ")
    else
        # Numbered fallback
        local i=1
        for opt in "${options[@]}"; do
            if [ $i -eq ${#options[@]} ]; then
                # Last option (Terminal only) is default
                echo "  $i) $opt (default)"
            else
                echo "  $i) $opt"
            fi
            ((i++))
        done
        echo ""
        local choice
        read -p "  Select [${#options[@]}]: " choice
        choice="${choice:-${#options[@]}}"

        # Validate input
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#options[@]} ]; then
            choice=${#options[@]}
        fi

        selection="${options[$((choice-1))]}"
    fi

    # Handle selection
    if [ "$selection" = "Terminal only" ] || [ -z "$selection" ]; then
        return 0
    fi

    # Find IDE command from display name
    local selected_ide=""
    for ide in $available; do
        if [ "$(ide_display_name "$ide")" = "$selection" ]; then
            selected_ide="$ide"
            break
        fi
    done

    if [ -n "$selected_ide" ]; then
        launch_ide "$selected_ide" "$path"
        IDE_WAS_LAUNCHED=true
    fi

    return 0
}
