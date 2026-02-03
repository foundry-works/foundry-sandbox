#!/bin/bash

write_sandbox_metadata() {
    local name="$1"
    local repo_url="$2"
    local branch="$3"
    local from_branch="$4"
    local working_dir="$5"
    local sparse_checkout="$6"
    local pip_requirements="$7"
    shift 7

    # allow_pr is optional; default to false for backward compatibility
    local allow_pr="false"
    if [ "${1:-}" = "true" ] || [ "${1:-}" = "false" ]; then
        allow_pr="$1"
        shift 1
    fi

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

    local repo_escaped branch_escaped from_branch_escaped network_escaped ssh_mode_escaped working_dir_escaped pip_requirements_escaped allow_pr_val
    local enable_opencode_val enable_zai_val
    repo_escaped=$(json_escape "$repo_url")
    branch_escaped=$(json_escape "$branch")
    from_branch_escaped=$(json_escape "$from_branch")
    network_escaped=$(json_escape "${SANDBOX_NETWORK_MODE:-}")
    ssh_mode_escaped=$(json_escape "${SANDBOX_SSH_MODE:-}")
    working_dir_escaped=$(json_escape "$working_dir")
    pip_requirements_escaped=$(json_escape "$pip_requirements")
    # Convert allow_pr to boolean (true/false) for JSON
    if [ "$allow_pr" = "true" ]; then
        allow_pr_val="true"
    else
        allow_pr_val="false"
    fi
    # Convert enable flags to boolean (true/false) for JSON
    if [ "${SANDBOX_ENABLE_OPENCODE:-0}" = "1" ] || [ "${SANDBOX_ENABLE_OPENCODE:-}" = "true" ]; then
        enable_opencode_val="true"
    else
        enable_opencode_val="false"
    fi
    if [ "${SANDBOX_ENABLE_ZAI:-0}" = "1" ] || [ "${SANDBOX_ENABLE_ZAI:-}" = "true" ]; then
        enable_zai_val="true"
    else
        enable_zai_val="false"
    fi

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
        printf '"working_dir":"%s",' "$working_dir_escaped"
        printf '"sparse_checkout":%s,' "$sparse_checkout"
        printf '"pip_requirements":"%s",' "$pip_requirements_escaped"
        printf '"allow_pr":%s,' "$allow_pr_val"
        printf '"enable_opencode":%s,' "$enable_opencode_val"
        printf '"enable_zai":%s,' "$enable_zai_val"
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
emit("working_dir", data.get("working_dir", ""))
emit("sparse_checkout", "1" if data.get("sparse_checkout") else "0")
emit("pip_requirements", data.get("pip_requirements", ""))
emit("allow_pr", "1" if data.get("allow_pr") else "0")
emit("enable_opencode", "1" if data.get("enable_opencode") else "0")
emit("enable_zai", "1" if data.get("enable_zai") else "0")

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
emit("working_dir", data.working_dir || "");
emit("sparse_checkout", data.sparse_checkout ? "1" : "0");
emit("pip_requirements", data.pip_requirements || "");
emit("allow_pr", data.allow_pr ? "1" : "0");
emit("enable_opencode", data.enable_opencode ? "1" : "0");
emit("enable_zai", data.enable_zai ? "1" : "0");

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
    SANDBOX_WORKING_DIR=""
    SANDBOX_SPARSE_CHECKOUT="0"
    SANDBOX_PIP_REQUIREMENTS=""
    SANDBOX_ALLOW_PR="0"
    SANDBOX_ENABLE_OPENCODE="0"
    SANDBOX_ENABLE_ZAI="0"
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
            working_dir) SANDBOX_WORKING_DIR="$value" ;;
            sparse_checkout) SANDBOX_SPARSE_CHECKOUT="$value" ;;
            pip_requirements) SANDBOX_PIP_REQUIREMENTS="$value" ;;
            allow_pr) SANDBOX_ALLOW_PR="$value" ;;
            enable_opencode) SANDBOX_ENABLE_OPENCODE="$value" ;;
            enable_zai) SANDBOX_ENABLE_ZAI="$value" ;;
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
        write_sandbox_metadata "$name" "$SANDBOX_REPO_URL" "$SANDBOX_BRANCH" "$SANDBOX_FROM_BRANCH" "$SANDBOX_WORKING_DIR" "$SANDBOX_SPARSE_CHECKOUT" "$SANDBOX_PIP_REQUIREMENTS" "$SANDBOX_ALLOW_PR" "${SANDBOX_MOUNTS[@]}" -- "${SANDBOX_COPIES[@]}"
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
        add_timezone_to_override "$override_file"
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
    add_timezone_to_override "$override_file"
}

# ============================================================================
# Cast New Presets & History
# ============================================================================

# Save the last cast new arguments to a JSON file
save_last_cast_new() {
    local repo="$1"
    local branch="$2"
    local from_branch="$3"
    local working_dir="$4"
    local sparse="$5"
    local pip_requirements="$6"
    local allow_pr="$7"
    local network_mode="$8"
    local sync_ssh="$9"
    local enable_opencode="${10}"
    local enable_zai="${11}"
    shift 11

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
    path=$(path_last_cast_new)
    mkdir -p "$(dirname "$path")"

    _write_cast_new_json "$path" "$repo" "$branch" "$from_branch" "$working_dir" \
        "$sparse" "$pip_requirements" "$allow_pr" "$network_mode" "$sync_ssh" \
        "$enable_opencode" "$enable_zai" "${mounts[@]}" -- "${copies[@]}"
}

# Save a named preset
save_cast_preset() {
    local preset_name="$1"
    local repo="$2"
    local branch="$3"
    local from_branch="$4"
    local working_dir="$5"
    local sparse="$6"
    local pip_requirements="$7"
    local allow_pr="$8"
    local network_mode="$9"
    local sync_ssh="${10}"
    local enable_opencode="${11}"
    local enable_zai="${12}"
    shift 12

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

    local presets_dir
    presets_dir=$(path_presets_dir)
    mkdir -p "$presets_dir"

    local path
    path=$(path_preset_file "$preset_name")

    _write_cast_new_json "$path" "$repo" "$branch" "$from_branch" "$working_dir" \
        "$sparse" "$pip_requirements" "$allow_pr" "$network_mode" "$sync_ssh" \
        "$enable_opencode" "$enable_zai" "${mounts[@]}" -- "${copies[@]}"

    echo "Preset '$preset_name' saved."
}

# Internal: write cast new args to JSON file
_write_cast_new_json() {
    local path="$1"
    local repo="$2"
    local branch="$3"
    local from_branch="$4"
    local working_dir="$5"
    local sparse="$6"
    local pip_requirements="$7"
    local allow_pr="$8"
    local network_mode="$9"
    local sync_ssh="${10}"
    local enable_opencode="${11}"
    local enable_zai="${12}"
    shift 12

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

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Build command line for display
    local cmd_line="cast new $repo"
    [ -n "$branch" ] && cmd_line+=" $branch"
    [ -n "$from_branch" ] && cmd_line+=" $from_branch"
    [ -n "$working_dir" ] && cmd_line+=" --wd $working_dir"
    [ "$sparse" = "true" ] && cmd_line+=" --sparse"
    [ -n "$pip_requirements" ] && cmd_line+=" --pip-requirements $pip_requirements"
    [ "$allow_pr" = "true" ] && cmd_line+=" --allow-pr"
    [ "$network_mode" != "limited" ] && [ -n "$network_mode" ] && cmd_line+=" --network $network_mode"
    [ "$sync_ssh" = "1" ] && cmd_line+=" --with-ssh"
    [ "$enable_opencode" = "true" ] && cmd_line+=" --with-opencode"
    [ "$enable_zai" = "true" ] && cmd_line+=" --with-zai"
    for mount in "${mounts[@]}"; do
        cmd_line+=" --mount $mount"
    done
    for copy in "${copies[@]}"; do
        cmd_line+=" --copy $copy"
    done

    # Escape values for JSON
    local repo_escaped branch_escaped from_branch_escaped working_dir_escaped
    local pip_requirements_escaped network_escaped cmd_line_escaped timestamp_escaped
    repo_escaped=$(json_escape "$repo")
    branch_escaped=$(json_escape "$branch")
    from_branch_escaped=$(json_escape "$from_branch")
    working_dir_escaped=$(json_escape "$working_dir")
    pip_requirements_escaped=$(json_escape "$pip_requirements")
    network_escaped=$(json_escape "$network_mode")
    cmd_line_escaped=$(json_escape "$cmd_line")
    timestamp_escaped=$(json_escape "$timestamp")

    # Convert booleans
    local sparse_val allow_pr_val sync_ssh_val enable_opencode_val enable_zai_val
    [ "$sparse" = "true" ] && sparse_val="true" || sparse_val="false"
    [ "$allow_pr" = "true" ] && allow_pr_val="true" || allow_pr_val="false"
    [ "$sync_ssh" = "1" ] && sync_ssh_val="true" || sync_ssh_val="false"
    [ "$enable_opencode" = "true" ] && enable_opencode_val="true" || enable_opencode_val="false"
    [ "$enable_zai" = "true" ] && enable_zai_val="true" || enable_zai_val="false"

    # Build mounts array
    local mounts_json="[]"
    if [ ${#mounts[@]} -gt 0 ]; then
        mounts_json="["
        local first=true
        for mount in "${mounts[@]}"; do
            local mount_escaped
            mount_escaped=$(json_escape "$mount")
            if [ "$first" = true ]; then
                first=false
                mounts_json+="\"$mount_escaped\""
            else
                mounts_json+=",\"$mount_escaped\""
            fi
        done
        mounts_json+="]"
    fi

    # Build copies array
    local copies_json="[]"
    if [ ${#copies[@]} -gt 0 ]; then
        copies_json="["
        local first=true
        for copy in "${copies[@]}"; do
            local copy_escaped
            copy_escaped=$(json_escape "$copy")
            if [ "$first" = true ]; then
                first=false
                copies_json+="\"$copy_escaped\""
            else
                copies_json+=",\"$copy_escaped\""
            fi
        done
        copies_json+="]"
    fi

    {
        printf '{\n'
        printf '  "timestamp": "%s",\n' "$timestamp_escaped"
        printf '  "command_line": "%s",\n' "$cmd_line_escaped"
        printf '  "args": {\n'
        printf '    "repo": "%s",\n' "$repo_escaped"
        printf '    "branch": "%s",\n' "$branch_escaped"
        printf '    "from_branch": "%s",\n' "$from_branch_escaped"
        printf '    "working_dir": "%s",\n' "$working_dir_escaped"
        printf '    "sparse": %s,\n' "$sparse_val"
        printf '    "pip_requirements": "%s",\n' "$pip_requirements_escaped"
        printf '    "allow_pr": %s,\n' "$allow_pr_val"
        printf '    "mounts": %s,\n' "$mounts_json"
        printf '    "copies": %s,\n' "$copies_json"
        printf '    "network_mode": "%s",\n' "$network_escaped"
        printf '    "sync_ssh": %s,\n' "$sync_ssh_val"
        printf '    "enable_opencode": %s,\n' "$enable_opencode_val"
        printf '    "enable_zai": %s\n' "$enable_zai_val"
        printf '  }\n'
        printf '}\n'
    } > "$path"
    chmod 600 "$path"

    # Export for immediate use (e.g., in sandbox ready message)
    LAST_COMMAND_LINE="$cmd_line"
}

# Load the last cast new arguments into NEW_* variables
load_last_cast_new() {
    local path
    path=$(path_last_cast_new)
    if [ ! -f "$path" ]; then
        echo "No previous 'cast new' command found." >&2
        return 1
    fi
    _load_cast_new_json "$path"
}

# Load a named preset into NEW_* variables
load_cast_preset() {
    local preset_name="$1"
    local path
    path=$(path_preset_file "$preset_name")
    if [ ! -f "$path" ]; then
        echo "Preset '$preset_name' not found." >&2
        return 1
    fi
    _load_cast_new_json "$path"
}

# Internal: parse cast new JSON and set NEW_* variables
_load_cast_new_json() {
    local path="$1"

    # Initialize defaults
    NEW_REPO_URL=""
    NEW_BRANCH=""
    NEW_FROM_BRANCH=""
    NEW_WORKING_DIR=""
    NEW_SPARSE_CHECKOUT=false
    NEW_PIP_REQUIREMENTS=""
    NEW_ALLOW_PR=false
    NEW_MOUNTS=()
    NEW_COPIES=()
    NEW_NETWORK_MODE="limited"
    NEW_SYNC_SSH="0"
    NEW_ENABLE_OPENCODE=false
    NEW_ENABLE_ZAI=false

    local parser_output=""
    if command -v python3 >/dev/null 2>&1; then
        parser_output=$(_parse_cast_new_json_python "$path" "python3") || return 1
    elif command -v python >/dev/null 2>&1; then
        parser_output=$(_parse_cast_new_json_python "$path" "python") || return 1
    elif command -v node >/dev/null 2>&1; then
        parser_output=$(_parse_cast_new_json_node "$path") || return 1
    else
        echo "JSON parser unavailable (install python3 or node)" >&2
        return 1
    fi

    while IFS=$'\t' read -r key value; do
        case "$key" in
            repo) NEW_REPO_URL="$value" ;;
            branch) NEW_BRANCH="$value" ;;
            from_branch) NEW_FROM_BRANCH="$value" ;;
            working_dir) NEW_WORKING_DIR="$value" ;;
            sparse) [ "$value" = "1" ] && NEW_SPARSE_CHECKOUT=true || NEW_SPARSE_CHECKOUT=false ;;
            pip_requirements) NEW_PIP_REQUIREMENTS="$value" ;;
            allow_pr) [ "$value" = "1" ] && NEW_ALLOW_PR=true || NEW_ALLOW_PR=false ;;
            network_mode) NEW_NETWORK_MODE="$value" ;;
            sync_ssh) NEW_SYNC_SSH="$value" ;;
            enable_opencode) [ "$value" = "1" ] && NEW_ENABLE_OPENCODE=true || NEW_ENABLE_OPENCODE=false ;;
            enable_zai) [ "$value" = "1" ] && NEW_ENABLE_ZAI=true || NEW_ENABLE_ZAI=false ;;
            mount) NEW_MOUNTS+=("$value") ;;
            copy) NEW_COPIES+=("$value") ;;
            command_line) LAST_COMMAND_LINE="$value" ;;
        esac
    done <<< "$parser_output"
}

_parse_cast_new_json_python() {
    local path="$1"
    local python_bin="${2:-python3}"
    "$python_bin" - "$path" <<'PY'
import json
import sys

path = sys.argv[1]

def emit(key, value):
    if value is None:
        return
    print(f"{key}\t{value}")

with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

emit("command_line", data.get("command_line", ""))

args = data.get("args", {})
emit("repo", args.get("repo", ""))
emit("branch", args.get("branch", ""))
emit("from_branch", args.get("from_branch", ""))
emit("working_dir", args.get("working_dir", ""))
emit("sparse", "1" if args.get("sparse") else "0")
emit("pip_requirements", args.get("pip_requirements", ""))
emit("allow_pr", "1" if args.get("allow_pr") else "0")
emit("network_mode", args.get("network_mode", "limited"))
emit("sync_ssh", "1" if args.get("sync_ssh") else "0")
emit("enable_opencode", "1" if args.get("enable_opencode") else "0")
emit("enable_zai", "1" if args.get("enable_zai") else "0")

for mount in args.get("mounts", []) or []:
    emit("mount", mount)
for copy in args.get("copies", []) or []:
    emit("copy", copy)
PY
}

_parse_cast_new_json_node() {
    local path="$1"
    node - "$path" <<'NODE'
const fs = require("fs");

const path = process.argv[2];
const data = JSON.parse(fs.readFileSync(path, "utf8"));

const emit = (key, value) => {
  if (value === undefined || value === null) return;
  process.stdout.write(`${key}\t${value}\n`);
};

emit("command_line", data.command_line || "");

const args = data.args || {};
emit("repo", args.repo || "");
emit("branch", args.branch || "");
emit("from_branch", args.from_branch || "");
emit("working_dir", args.working_dir || "");
emit("sparse", args.sparse ? "1" : "0");
emit("pip_requirements", args.pip_requirements || "");
emit("allow_pr", args.allow_pr ? "1" : "0");
emit("network_mode", args.network_mode || "limited");
emit("sync_ssh", args.sync_ssh ? "1" : "0");
emit("enable_opencode", args.enable_opencode ? "1" : "0");
emit("enable_zai", args.enable_zai ? "1" : "0");

(args.mounts || []).forEach((mount) => emit("mount", mount));
(args.copies || []).forEach((copy) => emit("copy", copy));
NODE
}

# List all available presets
list_cast_presets() {
    local presets_dir
    presets_dir=$(path_presets_dir)
    if [ ! -d "$presets_dir" ]; then
        echo "No presets saved yet."
        return 0
    fi
    local found=false
    for f in "$presets_dir"/*.json; do
        [ -e "$f" ] || continue
        found=true
        local name
        name=$(basename "$f" .json)
        echo "$name"
    done
    if [ "$found" = false ]; then
        echo "No presets saved yet."
    fi
}

# Show details of a preset
show_cast_preset() {
    local preset_name="$1"
    local path
    path=$(path_preset_file "$preset_name")
    if [ ! -f "$path" ]; then
        echo "Preset '$preset_name' not found." >&2
        return 1
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -m json.tool "$path"
    elif command -v python >/dev/null 2>&1; then
        python -m json.tool "$path"
    elif command -v jq >/dev/null 2>&1; then
        jq . "$path"
    else
        cat "$path"
    fi
}

# Delete a preset
delete_cast_preset() {
    local preset_name="$1"
    local path
    path=$(path_preset_file "$preset_name")
    if [ ! -f "$path" ]; then
        echo "Preset '$preset_name' not found." >&2
        return 1
    fi
    rm -f "$path"
    echo "Preset '$preset_name' deleted."
}

# ============================================================================
# Last Attach State
# ============================================================================

# Save the last attached sandbox name to a JSON file
save_last_attach() {
    local sandbox_name="$1"
    local path
    path=$(path_last_attach)
    mkdir -p "$(dirname "$path")"

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local name_escaped timestamp_escaped
    name_escaped=$(json_escape "$sandbox_name")
    timestamp_escaped=$(json_escape "$timestamp")

    {
        printf '{\n'
        printf '  "timestamp": "%s",\n' "$timestamp_escaped"
        printf '  "sandbox_name": "%s"\n' "$name_escaped"
        printf '}\n'
    } > "$path"
    chmod 600 "$path"
}

# Load the last attached sandbox name
# Sets LAST_ATTACH_NAME on success
load_last_attach() {
    local path
    path=$(path_last_attach)
    if [ ! -f "$path" ]; then
        echo "No previous 'cast attach' command found." >&2
        return 1
    fi

    LAST_ATTACH_NAME=""

    local parser_output=""
    if command -v python3 >/dev/null 2>&1; then
        parser_output=$(_parse_last_attach_python "$path" "python3") || return 1
    elif command -v python >/dev/null 2>&1; then
        parser_output=$(_parse_last_attach_python "$path" "python") || return 1
    elif command -v node >/dev/null 2>&1; then
        parser_output=$(_parse_last_attach_node "$path") || return 1
    else
        echo "JSON parser unavailable (install python3 or node)" >&2
        return 1
    fi

    while IFS=$'\t' read -r key value; do
        case "$key" in
            sandbox_name) LAST_ATTACH_NAME="$value" ;;
        esac
    done <<< "$parser_output"

    if [ -z "$LAST_ATTACH_NAME" ]; then
        echo "Last attach file is empty or corrupted." >&2
        return 1
    fi
}

_parse_last_attach_python() {
    local path="$1"
    local python_bin="${2:-python3}"
    "$python_bin" - "$path" <<'PY'
import json
import sys

path = sys.argv[1]

def emit(key, value):
    if value is None:
        return
    print(f"{key}\t{value}")

with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

emit("sandbox_name", data.get("sandbox_name", ""))
PY
}

_parse_last_attach_node() {
    local path="$1"
    node - "$path" <<'NODE'
const fs = require("fs");

const path = process.argv[2];
const data = JSON.parse(fs.readFileSync(path, "utf8"));

const emit = (key, value) => {
  if (value === undefined || value === null) return;
  process.stdout.write(`${key}\t${value}\n`);
};

emit("sandbox_name", data.sandbox_name || "");
NODE
}
