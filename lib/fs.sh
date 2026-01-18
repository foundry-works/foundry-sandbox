#!/bin/bash

ensure_dir() {
    local path="$1"
    [ -d "$path" ] || mkdir -p "$path"
}

path_exists() {
    local path="$1"
    [ -e "$path" ]
}

dir_exists() {
    local path="$1"
    [ -d "$path" ]
}

file_exists() {
    local path="$1"
    [ -f "$path" ]
}

remove_path() {
    local path="$1"
    if [ -e "$path" ]; then
        rm -rf "$path"
    fi
}
