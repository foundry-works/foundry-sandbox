#!/bin/bash

write_sandbox_metadata() {
    local name="$1"
    local repo_url="$2"
    local branch="$3"
    local from_branch="$4"
    shift 4

    local mounts=()
    local copies=()
    local mode="mounts"
    for arg in "$@"; do
        if [ "$arg" = "--" ]; then
            mode="copies"
            continue
        fi
        if [ "$mode" = "mounts" ]; then
            mounts+=("$arg")
        else
            copies+=("$arg")
        fi
    done

    local path
    path=$(path_metadata_file "$name")
    mkdir -p "$(dirname "$path")"

    {
        printf 'SANDBOX_REPO_URL=%q\n' "$repo_url"
        printf 'SANDBOX_BRANCH=%q\n' "$branch"
        printf 'SANDBOX_FROM_BRANCH=%q\n' "$from_branch"
        printf 'SANDBOX_MOUNTS=('
        for mount in "${mounts[@]}"; do
            printf '%q ' "$mount"
        done
        printf ')\n'
        printf 'SANDBOX_COPIES=('
        for copy in "${copies[@]}"; do
            printf '%q ' "$copy"
        done
        printf ')\n'
    } > "$path"
}

load_sandbox_metadata() {
    local name="$1"
    local path
    path=$(path_metadata_file "$name")

    if [ -f "$path" ]; then
        # shellcheck source=/dev/null
        source "$path"
        return 0
    fi
    return 1
}

ensure_override_from_metadata() {
    local name="$1"
    local override_file="$2"

    if file_exists "$override_file"; then
        return 0
    fi

    if ! load_sandbox_metadata "$name"; then
        return 0
    fi

    if [ ${#SANDBOX_MOUNTS[@]} -eq 0 ]; then
        return 0
    fi

    ensure_dir "$(dirname "$override_file")"
    cat > "$override_file" <<OVERRIDES
services:
  dev:
    volumes:
OVERRIDES
    for mount in "${SANDBOX_MOUNTS[@]}"; do
        echo "      - $mount" >> "$override_file"
    done
}
