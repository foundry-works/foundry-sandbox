#!/bin/bash

prompt_confirm() {
    local prompt="$1"
    local default_yes="$2"
    local default_hint=""

    if [ "$SANDBOX_ASSUME_YES" = "1" ]; then
        return 0
    fi

    if [ "$default_yes" = "true" ]; then
        default_hint="[Y/n]"
    else
        default_hint="[y/N]"
    fi

    read -p "$prompt $default_hint " confirm

    if [ -z "$confirm" ] && [ "$default_yes" = "true" ]; then
        return 0
    fi

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        return 0
    fi

    return 1
}
