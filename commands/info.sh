#!/bin/bash

cmd_info() {
    local json_output=false
    if [ "$1" = "--json" ]; then
        json_output=true
    fi

    source "$SCRIPT_DIR/commands/config.sh"
    source "$SCRIPT_DIR/commands/status.sh"

    if [ "$json_output" = true ]; then
        local config_json
        config_json=$(cmd_config --json)
        local status_json
        status_json=$(cmd_status --json)
        printf '{"config":%s,"status":%s}' "$config_json" "$status_json"
        return
    fi

    cmd_config
    format_section_break
    cmd_status
}
