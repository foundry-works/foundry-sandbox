#!/bin/bash

cmd_list() {
    local json_output=false
    if [ "$1" = "--json" ]; then
        json_output=true
    fi

    if [ "$json_output" = true ]; then
        for worktree in "$WORKTREES_DIR"/*/; do
            [ -d "$worktree" ] || continue
            local name
            name=$(basename "$worktree")
            sandbox_info_json "$name"
        done | json_array_from_lines
        return
    fi

    format_header "Sandboxes:"
    format_section_break

    for worktree in "$WORKTREES_DIR"/*/; do
        [ -d "$worktree" ] || continue
        local name
        name=$(basename "$worktree")
        sandbox_info_text_summary "$name"
    done
}
