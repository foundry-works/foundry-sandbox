#!/bin/bash

format_header() {
    echo "$1"
}

format_kv() {
    local key="$1"
    local value="$2"
    printf "  %s: %s\n" "$key" "$value"
}

format_section_break() {
    echo ""
}

format_table_row() {
    local name="$1"
    local status="$2"
    local extra="$3"
    printf "  %-30s %s%s\n" "$name" "$status" "$extra"
}

format_kv_list_item() {
    local value="$1"
    printf "    - %s\n" "$value"
}
