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

    local repo_escaped branch_escaped from_branch_escaped network_escaped ssh_mode_escaped
    repo_escaped=$(json_escape "$repo_url")
    branch_escaped=$(json_escape "$branch")
    from_branch_escaped=$(json_escape "$from_branch")
    network_escaped=$(json_escape "${SANDBOX_NETWORK_MODE:-}")
    ssh_mode_escaped=$(json_escape "${SANDBOX_SSH_MODE:-}")

    local mounts_json="[]"
    if [ ${#mounts[@]} -gt 0 ]; then
        mounts_json="["
        local first_mount=true
        for mount in "${mounts[@]}"; do
            local mount_escaped
            mount_escaped=$(json_escape "$mount")
            if [ "$first_mount" = true ]; then
                first_mount=false
                mounts_json+="\"$mount_escaped\""
            else
                mounts_json+=",\"$mount_escaped\""
            fi
        done
        mounts_json+="]"
    fi

    local copies_json="[]"
    if [ ${#copies[@]} -gt 0 ]; then
        copies_json="["
        local first_copy=true
        for copy in "${copies[@]}"; do
            local copy_escaped
            copy_escaped=$(json_escape "$copy")
            if [ "$first_copy" = true ]; then
                first_copy=false
                copies_json+="\"$copy_escaped\""
            else
                copies_json+=",\"$copy_escaped\""
            fi
        done
        copies_json+="]"
    fi

    {
        printf '{'
        printf '"repo_url":"%s",' "$repo_escaped"
        printf '"branch":"%s",' "$branch_escaped"
        printf '"from_branch":"%s",' "$from_branch_escaped"
        printf '"network_mode":"%s",' "$network_escaped"
        printf '"sync_ssh":%s,' "${SANDBOX_SYNC_SSH:-0}"
        printf '"ssh_mode":"%s",' "$ssh_mode_escaped"
        printf '"sync_api_keys":%s,' "${SANDBOX_SYNC_API_KEYS:-0}"
        printf '"mounts":%s,' "$mounts_json"
        printf '"copies":%s' "$copies_json"
        printf '}\n'
    } > "$path"
    chmod 600 "$path"
}

_metadata_is_secure() {
    local path="$1"
    if [ ! -O "$path" ]; then
        warn "Metadata file is not owned by the current user: $path"
        return 1
    fi
    local mode=""
    mode=$(stat -c %a "$path" 2>/dev/null) || mode=$(stat -f %Lp "$path" 2>/dev/null) || true
    if [ -n "$mode" ]; then
        if (( 8#$mode & 022 )); then
            warn "Metadata file is group/world-writable: $path"
            return 1
        fi
    fi
    return 0
}

_metadata_parse_with_python() {
    local path="$1"
    local format="$2"
    local python_bin="${3:-python3}"
    "$python_bin" - "$path" "$format" <<'PY'
import json
import shlex
import sys

path = sys.argv[1]
fmt = sys.argv[2]

def emit(key, value):
    if value is None:
        return
    print(f"{key}\t{value}")

if fmt == "json":
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
elif fmt == "legacy":
    data = {"mounts": [], "copies": []}
    key_map = {
        "SANDBOX_REPO_URL": "repo_url",
        "SANDBOX_BRANCH": "branch",
        "SANDBOX_FROM_BRANCH": "from_branch",
        "SANDBOX_NETWORK_MODE": "network_mode",
        "SANDBOX_SYNC_SSH": "sync_ssh",
        "SANDBOX_SYNC_API_KEYS": "sync_api_keys",
    }
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("SANDBOX_MOUNTS="):
                inner = line.split("=", 1)[1].strip()
                if inner.startswith("(") and inner.endswith(")"):
                    inner = inner[1:-1]
                data["mounts"] = shlex.split(inner)
                continue
            if line.startswith("SANDBOX_COPIES="):
                inner = line.split("=", 1)[1].strip()
                if inner.startswith("(") and inner.endswith(")"):
                    inner = inner[1:-1]
                data["copies"] = shlex.split(inner)
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key not in key_map:
                continue
            parts = shlex.split(value)
            data[key_map[key]] = parts[0] if parts else ""
else:
    raise SystemExit(f"Unknown metadata format: {fmt}")

emit("repo_url", data.get("repo_url", ""))
emit("branch", data.get("branch", ""))
emit("from_branch", data.get("from_branch", ""))
emit("network_mode", data.get("network_mode", ""))
emit("sync_ssh", data.get("sync_ssh", "0"))
emit("ssh_mode", data.get("ssh_mode", ""))
emit("sync_api_keys", data.get("sync_api_keys", "0"))

for mount in data.get("mounts", []) or []:
    emit("mount", mount)
for copy in data.get("copies", []) or []:
    emit("copy", copy)
PY
}

_metadata_parse_with_node() {
    local path="$1"
    node - "$path" <<'NODE'
const fs = require("fs");

const path = process.argv[2];
const data = JSON.parse(fs.readFileSync(path, "utf8"));

const emit = (key, value) => {
  if (value === undefined || value === null) return;
  process.stdout.write(`${key}\t${value}\n`);
};

emit("repo_url", data.repo_url || "");
emit("branch", data.branch || "");
emit("from_branch", data.from_branch || "");
emit("network_mode", data.network_mode || "");
emit("sync_ssh", data.sync_ssh ?? "0");
emit("ssh_mode", data.ssh_mode || "");
emit("sync_api_keys", data.sync_api_keys ?? "0");

(data.mounts || []).forEach((mount) => emit("mount", mount));
(data.copies || []).forEach((copy) => emit("copy", copy));
NODE
}

_metadata_load_from_file() {
    local path="$1"
    local format="$2"

    SANDBOX_REPO_URL=""
    SANDBOX_BRANCH=""
    SANDBOX_FROM_BRANCH=""
    SANDBOX_NETWORK_MODE=""
    SANDBOX_SYNC_SSH="0"
    SANDBOX_SSH_MODE=""
    SANDBOX_SYNC_API_KEYS="0"
    SANDBOX_MOUNTS=()
    SANDBOX_COPIES=()

    local parser_output=""
    if command -v python3 >/dev/null 2>&1; then
        parser_output=$(_metadata_parse_with_python "$path" "$format" "python3") || return 1
    elif command -v python >/dev/null 2>&1; then
        parser_output=$(_metadata_parse_with_python "$path" "$format" "python") || return 1
    elif [ "$format" = "json" ] && command -v node >/dev/null 2>&1; then
        parser_output=$(_metadata_parse_with_node "$path") || return 1
    else
        warn "Metadata parser unavailable (install python3 to read $path)"
        return 1
    fi

    while IFS=$'\t' read -r key value; do
        case "$key" in
            repo_url) SANDBOX_REPO_URL="$value" ;;
            branch) SANDBOX_BRANCH="$value" ;;
            from_branch) SANDBOX_FROM_BRANCH="$value" ;;
            network_mode) SANDBOX_NETWORK_MODE="$value" ;;
            sync_ssh) SANDBOX_SYNC_SSH="$value" ;;
            ssh_mode) SANDBOX_SSH_MODE="$value" ;;
            sync_api_keys) SANDBOX_SYNC_API_KEYS="$value" ;;
            mount) SANDBOX_MOUNTS+=("$value") ;;
            copy) SANDBOX_COPIES+=("$value") ;;
        esac
    done <<< "$parser_output"

    if [ -z "$SANDBOX_SSH_MODE" ]; then
        if [ "${SANDBOX_SYNC_SSH:-0}" = "1" ]; then
            SANDBOX_SSH_MODE="always"
        else
            SANDBOX_SSH_MODE="disabled"
        fi
    fi
}

load_sandbox_metadata() {
    local name="$1"
    local path
    path=$(path_metadata_file "$name")
    local legacy_path
    legacy_path=$(path_metadata_legacy_file "$name")

    if [ -f "$path" ]; then
        _metadata_is_secure "$path" || return 1
        _metadata_load_from_file "$path" "json" || return 1
        return 0
    fi
    if [ -f "$legacy_path" ]; then
        _metadata_is_secure "$legacy_path" || return 1
        _metadata_load_from_file "$legacy_path" "legacy" || return 1
        write_sandbox_metadata "$name" "$SANDBOX_REPO_URL" "$SANDBOX_BRANCH" "$SANDBOX_FROM_BRANCH" "${SANDBOX_MOUNTS[@]}" -- "${SANDBOX_COPIES[@]}"
        rm -f "$legacy_path"
        return 0
    fi
    return 1
}

ensure_override_from_metadata() {
    local name="$1"
    local override_file="$2"

    if ! load_sandbox_metadata "$name"; then
        return 0
    fi

    if file_exists "$override_file"; then
        local claude_home
        claude_home=$(path_claude_home "$name")
        ensure_dir "$claude_home"
        add_claude_home_to_override "$override_file" "$claude_home"
        return 0
    fi

    ensure_dir "$(dirname "$override_file")"
    if [ ${#SANDBOX_MOUNTS[@]} -gt 0 ]; then
        cat > "$override_file" <<OVERRIDES
services:
  dev:
    volumes:
OVERRIDES
        for mount in "${SANDBOX_MOUNTS[@]}"; do
            echo "      - $mount" >> "$override_file"
        done
    fi

    if [ -n "${SANDBOX_NETWORK_MODE:-}" ]; then
        add_network_to_override "$SANDBOX_NETWORK_MODE" "$override_file"
    fi

    local claude_home
    claude_home=$(path_claude_home "$name")
    ensure_dir "$claude_home"
    add_claude_home_to_override "$override_file" "$claude_home"
}
