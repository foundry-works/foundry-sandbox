#!/bin/bash

TAR_NO_XATTRS_ARGS=()
TAR_TRANSFORM_SUPPORTED=0
if command -v tar >/dev/null 2>&1; then
    # Avoid libarchive xattr headers that GNU tar warns about.
    if tar --no-xattrs --version >/dev/null 2>&1; then
        TAR_NO_XATTRS_ARGS+=(--no-xattrs)
    fi
    if tar --help 2>/dev/null | grep -q -- '--transform'; then
        TAR_TRANSFORM_SUPPORTED=1
    fi
fi

CODEX_COPY_EXCLUDES=("logs")
if [ -n "${SANDBOX_CODEX_EXCLUDES:-}" ]; then
    IFS=',' read -ra codex_extra <<< "$SANDBOX_CODEX_EXCLUDES"
    for pattern in "${codex_extra[@]}"; do
        [ -n "$pattern" ] && CODEX_COPY_EXCLUDES+=("$pattern")
    done
fi

# Global cache for Claude plugins (shared across all sandboxes)
CLAUDE_PLUGINS_CACHE="${CLAUDE_PLUGINS_CACHE:-$HOME/.cache/claude-plugins}"

# Verify the container user exists (built into image via SANDBOX_USERNAME)
# If user doesn't match, warn to rebuild
ensure_container_user() {
    local container_id="$1"

    # Skip if using default ubuntu user
    if [ "$CONTAINER_USER" = "ubuntu" ]; then
        return 0
    fi

    # Verify user exists in the image
    if ! docker exec "$container_id" id "$CONTAINER_USER" >/dev/null 2>&1; then
        log_warn "User $CONTAINER_USER not found in image."
        log_warn "Rebuild with: SANDBOX_USERNAME=$CONTAINER_USER cast build"
    fi
}

# Pre-populate Claude foundry as a global install on the HOST before container starts.
# This installs skills and hooks directly without using Claude's plugin system.
# MCP server config is written during container setup (ensure_foundry_mcp_config).
#
# Arguments:
#   $1 - claude_home_path: Host path that will be mounted as ~/.claude in container
#   $2 - skip_if_populated: If "1", skip if already installed (default: 0)
#
# Returns 0 on success, 1 on failure (but continues - install is best-effort)
prepopulate_foundry_global() {
    local claude_home_path="$1"
    local skip_if_populated="${2:-0}"

    local skills_dir="$claude_home_path/skills"
    local hooks_dir="$claude_home_path/hooks"

    # Check if already populated
    if [ "$skip_if_populated" = "1" ] && [ -d "$skills_dir/foundry-spec" ]; then
        log_debug "Foundry skills already installed, skipping"
        return 0
    fi

    log_info "Pre-populating foundry global install..."

    # Ensure directories exist
    mkdir -p "$skills_dir"
    mkdir -p "$hooks_dir"
    mkdir -p "$CLAUDE_PLUGINS_CACHE"

    # Clone or update the foundry plugin repo to global cache
    local foundry_cache="$CLAUDE_PLUGINS_CACHE/claude-foundry"
    if [ -d "$foundry_cache/.git" ]; then
        log_debug "Updating cached foundry repo..."
        if ! git -C "$foundry_cache" pull --ff-only -q 2>/dev/null; then
            log_warn "Failed to update foundry cache, using existing version"
        fi
    else
        log_info "Cloning foundry repo to cache..."
        if ! git clone --depth 1 -q \
            "https://github.com/foundry-works/claude-foundry.git" \
            "$foundry_cache" 2>&1; then
            log_warn "Failed to clone foundry repo - network may be unavailable"
            return 1
        fi
    fi

    # Get plugin version from plugin.json (for logging)
    local plugin_json="$foundry_cache/.claude-plugin/plugin.json"
    local version="unknown"
    if [ -f "$plugin_json" ]; then
        version=$(python3 -c "import json; print(json.load(open('$plugin_json'))['version'])" 2>/dev/null || echo "unknown")
    fi

    log_info "Installing foundry v$version as global install..."

    # Copy skills to ~/.claude/skills/
    if [ -d "$foundry_cache/skills" ]; then
        rsync -a --delete "$foundry_cache/skills/" "$skills_dir/" 2>/dev/null || \
            cp -r "$foundry_cache/skills/"* "$skills_dir/" 2>/dev/null
        log_debug "Copied skills to $skills_dir"
    else
        log_warn "No skills directory found in foundry repo"
    fi

    # Copy hooks executables to ~/.claude/hooks/
    # Note: We skip hooks.json - that's a plugin-specific config format.
    # Global hooks are configured in settings.json, not via hooks.json.
    if [ -d "$foundry_cache/hooks" ]; then
        for hook_file in "$foundry_cache/hooks"/*; do
            if [ -f "$hook_file" ] && [ "$(basename "$hook_file")" != "hooks.json" ]; then
                cp "$hook_file" "$hooks_dir/"
                chmod +x "$hooks_dir/$(basename "$hook_file")"
            fi
        done
        log_debug "Copied hooks to $hooks_dir"
    else
        log_warn "No hooks directory found in foundry repo"
    fi

    # Update settings.json with hooks configuration and sandbox defaults
    local settings_file="$claude_home_path/settings.json"
    python3 - "$settings_file" <<'PY'
import json
import sys
import os

path = sys.argv[1]
try:
    with open(path) as f:
        data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    data = {}

# Ensure sandbox defaults are set
if "model" not in data:
    data["model"] = "opus"
if "subagentModel" not in data:
    data["subagentModel"] = "haiku"
data["alwaysThinkingEnabled"] = True

# Configure hooks with absolute paths (container paths)
data["hooks"] = {
    "PreToolUse": [
        {
            "matcher": "Read",
            "hooks": [{"type": "command", "command": "/home/ubuntu/.claude/hooks/block-json-specs"}]
        },
        {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/home/ubuntu/.claude/hooks/block-spec-bash-access"}]
        }
    ],
    "PostToolUse": [
        {
            "hooks": [{"type": "command", "command": "/home/ubuntu/.claude/hooks/context-monitor"}]
        }
    ]
}

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY

    log_info "Foundry global install completed successfully"
    return 0
}

# Install Python packages from requirements.txt into the container.
# Supports auto-detection, host paths (copied in), and workspace-relative paths.
#
# Arguments:
#   $1 - container_id: The container to install packages in
#   $2 - requirements_path: Path specification (auto, host path, or workspace-relative)
#   $3 - quiet: If "1", suppress non-warning output (default: 0)
#
# Returns 0 on success or graceful skip, continues on pip failures
install_pip_requirements() {
    local container_id="$1"
    local requirements_path="$2"
    local quiet="${3:-0}"

    [ -z "$requirements_path" ] && return 0

    local container_req_path=""

    if [ "$requirements_path" = "auto" ]; then
        if docker exec "$container_id" test -f /workspace/requirements.txt 2>/dev/null; then
            container_req_path="/workspace/requirements.txt"
            [ "$quiet" != "1" ] && log_info "Auto-detected requirements.txt"
        else
            [ "$quiet" != "1" ] && log_debug "No requirements.txt found (auto-detect)"
            return 0
        fi
    elif [[ "$requirements_path" = /* ]] || [[ "$requirements_path" = ~/* ]]; then
        # Host path - copy into container
        local expanded_path="$requirements_path"
        [[ "$expanded_path" == "~/"* ]] && expanded_path="${expanded_path/#\~/$HOME}"

        if [ ! -f "$expanded_path" ]; then
            [ "$quiet" != "1" ] && log_warn "Requirements file not found: $expanded_path"
            return 0
        fi

        container_req_path="/tmp/sandbox-requirements.txt"
        copy_file_to_container "$container_id" "$expanded_path" "$container_req_path" || return 0
    else
        # Workspace-relative path
        container_req_path="/workspace/$requirements_path"
        if ! docker exec "$container_id" test -f "$container_req_path" 2>/dev/null; then
            [ "$quiet" != "1" ] && log_warn "Requirements file not found: $container_req_path"
            return 0
        fi
    fi

    [ "$quiet" != "1" ] && log_info "Installing Python packages from $container_req_path..."

    if docker exec -u "$CONTAINER_USER" "$container_id" \
        pip install --no-warn-script-location -r "$container_req_path" 2>&1; then
        [ "$quiet" != "1" ] && log_info "Python packages installed successfully"
    else
        [ "$quiet" != "1" ] && log_warn "Some pip packages failed to install (continuing)"
    fi

    # Clean up temp file
    [ "$container_req_path" = "/tmp/sandbox-requirements.txt" ] && \
        docker exec "$container_id" rm -f "$container_req_path" 2>/dev/null || true

    return 0
}

# Install CLAUDE.md and AGENTS.md from stubs into workspace.
# Appends content if stub files exist, creates destination if needed.
# Uses <foundry-instructions> tags (already in source files) to detect duplicates.
#
# Arguments:
#   $1 - container_id: The container to modify
install_foundry_workspace_docs() {
    local container_id="$1"
    local claude_md_src="$SANDBOX_HOME/stubs/CLAUDE.md"
    local agents_md_src="$SANDBOX_HOME/stubs/AGENTS.md"
    local marker="<foundry-instructions>"

    # Install CLAUDE.md from stubs
    if file_exists "$claude_md_src"; then
        # Check if already installed (marker present)
        if ! docker exec "$container_id" grep -qF "$marker" /workspace/CLAUDE.md 2>/dev/null; then
            log_info "Installing CLAUDE.md from stubs..."
            docker exec "$container_id" sh -c "[ ! -f /workspace/CLAUDE.md ] && touch /workspace/CLAUDE.md"
            docker exec -i "$container_id" sh -c "echo '' >> /workspace/CLAUDE.md && cat >> /workspace/CLAUDE.md" < "$claude_md_src"
        fi
    fi

    # Install AGENTS.md from stubs
    if file_exists "$agents_md_src"; then
        # Check if already installed (marker present)
        if ! docker exec "$container_id" grep -qF "$marker" /workspace/AGENTS.md 2>/dev/null; then
            log_info "Installing AGENTS.md from stubs..."
            docker exec "$container_id" sh -c "[ ! -f /workspace/AGENTS.md ] && touch /workspace/AGENTS.md"
            docker exec -i "$container_id" sh -c "echo '' >> /workspace/AGENTS.md && cat >> /workspace/AGENTS.md" < "$agents_md_src"
        fi
    fi
}

# Merge host's Claude settings into container's settings without overwriting critical sandbox settings.
# This preserves the hooks configuration and model defaults set up by prepopulate_foundry_global
# while bringing in other user preferences from the host.
#
# Arguments:
#   $1 - container_id: The container to modify
#   $2 - host_settings: Path to host's settings.json
#   $3 - container_settings: Path inside container to settings.json
merge_claude_settings() {
    local container_id="$1"
    local host_settings="$2"
    local container_settings="$3"

    # Copy host settings to temp location in container
    local temp_host="/tmp/host-settings.json"
    copy_file_to_container "$container_id" "$host_settings" "$temp_host" || {
        log_warn "Failed to copy host settings for merge"
        return 1
    }

    # Merge settings in container
    docker exec -u "$CONTAINER_USER" "$container_id" python3 - "$container_settings" "$temp_host" <<'PY'
import json
import sys
import os

container_path = sys.argv[1]
host_path = sys.argv[2]

# Load host settings
try:
    with open(host_path) as f:
        host_data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    host_data = {}

# Load existing container settings (may have hooks from prepopulate_foundry_global)
try:
    with open(container_path) as f:
        container_data = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    container_data = {}

# Settings to preserve from container (sandbox defaults)
preserve_keys = {"model", "subagentModel", "hooks"}
preserved = {k: container_data[k] for k in preserve_keys if k in container_data}

# Merge: host settings take precedence, except for preserved keys
merged = {**container_data, **host_data}

# Restore preserved settings (opus model, haiku subagent, hooks config)
merged.update(preserved)

# Remove foundry plugin from enabledPlugins - we use direct global install for it
# This prevents "Plugin not found" errors from stale host config
# But keep other plugins like pyright-lsp that use the normal plugin system
if "enabledPlugins" in merged:
    merged["enabledPlugins"].pop("foundry@claude-foundry", None)
    # Clean up empty dict
    if not merged["enabledPlugins"]:
        del merged["enabledPlugins"]

os.makedirs(os.path.dirname(container_path), exist_ok=True)
with open(container_path, "w") as f:
    json.dump(merged, f, indent=2)
    f.write("\n")
PY

    # Clean up temp file
    docker exec "$container_id" rm -f "$temp_host" 2>/dev/null || true
}

ssh_agent_preflight() {
    local container_id="$1"
    local enable_ssh="${2:-${SANDBOX_SYNC_SSH:-0}}"
    local quiet="${3:-0}"

    if [ "$enable_ssh" != "1" ] || [ "$quiet" = "1" ]; then
        return 0
    fi

    local ssh_agent_sock=""
    ssh_agent_sock=$(resolve_ssh_agent_sock) || ssh_agent_sock=""
    if [ -z "$ssh_agent_sock" ]; then
        log_warn "SSH agent not detected; plugin installs may use HTTPS or prompt for passphrase."
        return 0
    fi

    if ! docker exec "$container_id" test -S "$SSH_AGENT_CONTAINER_SOCK" 2>/dev/null; then
        log_warn "SSH agent socket not available at $SSH_AGENT_CONTAINER_SOCK inside container."
        return 0
    fi

    local ssh_add_output=""
    ssh_add_output=$(docker exec -u "$CONTAINER_USER" "$container_id" sh -c "SSH_AUTH_SOCK=$SSH_AGENT_CONTAINER_SOCK ssh-add -l" 2>&1)
    local ssh_add_status=$?
    if [ "$ssh_add_status" -eq 0 ]; then
        log_info "SSH agent forwarding looks active."
        return 0
    fi

    if echo "$ssh_add_output" | grep -qi "The agent has no identities"; then
        log_warn "SSH agent is available but has no identities; run ssh-add on the host."
    elif echo "$ssh_add_output" | grep -qi "Error connecting to agent"; then
        log_warn "SSH agent is mounted but not accessible by $CONTAINER_USER."
    elif echo "$ssh_add_output" | grep -qi "Permission denied"; then
        log_warn "SSH agent socket is not readable by $CONTAINER_USER."
    elif echo "$ssh_add_output" | grep -qi "command not found"; then
        log_warn "ssh-add is not available inside the container."
    else
        log_warn "SSH agent check failed; plugin installs may prompt for passphrase."
    fi
}

sync_opencode_foundry() {
    local container_id="$1"
    local quiet="${2:-0}"
    local repo_path="${SANDBOX_OPENCODE_FOUNDRY_PATH:-$SANDBOX_HOME/vendor/opencode-foundry}"
    local repo_url="${SANDBOX_OPENCODE_FOUNDRY_REPO:-https://github.com/foundry-works/opencode-foundry.git}"
    local repo_branch="${SANDBOX_OPENCODE_FOUNDRY_BRANCH:-main}"

    if [ -z "${SANDBOX_OPENCODE_FOUNDRY_PATH:-}" ]; then
        if ! ensure_repo_checkout "$repo_url" "$repo_path" "$repo_branch"; then
            if [ "$quiet" != "1" ]; then
                log_warn "Failed to fetch opencode-foundry from $repo_url"
            fi
            return 0
        fi
    fi

    if [[ "$repo_path" == "~/"* ]]; then
        repo_path="${repo_path/#\~/$HOME}"
    fi

    if ! dir_exists "$repo_path"; then
        if [ "$quiet" != "1" ]; then
            log_warn "SANDBOX_OPENCODE_FOUNDRY_PATH not found: $repo_path"
        fi
        return 0
    fi

    local skills_path="$repo_path/skills"
    local template_path="$repo_path/install/assets/opencode-global.json"

    if ! dir_exists "$skills_path"; then
        if [ "$quiet" != "1" ]; then
            log_warn "opencode-foundry skills not found: $skills_path"
        fi
        return 0
    fi

    if [ "$quiet" != "1" ]; then
        log_info "Syncing opencode-foundry from $repo_path..."
    fi

    local copy_dir_fn="copy_dir_to_container"
    local copy_file_fn="copy_file_to_container"
    local run_fn="run_cmd"
    if [ "$quiet" = "1" ]; then
        copy_dir_fn="copy_dir_to_container_quiet"
        copy_file_fn="copy_file_to_container_quiet"
        run_fn="run_cmd_quiet"
    fi

    if ! $copy_dir_fn "$container_id" "$skills_path" "$CONTAINER_HOME/.config/opencode/skills"; then
        if [ "$quiet" != "1" ]; then
            log_warn "Failed to sync opencode-foundry skills"
        fi
        return 0
    fi

    local disable_npm_plugins="${SANDBOX_OPENCODE_DISABLE_NPM_PLUGINS:-0}"
    if [ "${SANDBOX_OPENCODE_PREFETCH_NPM_PLUGINS:-0}" = "1" ]; then
        disable_npm_plugins="0"
    fi
    local local_plugin_dir_env=""
    if [ -n "${SANDBOX_OPENCODE_PLUGIN_DIR:-}" ]; then
        local host_plugin_dir="$SANDBOX_OPENCODE_PLUGIN_DIR"
        if [[ "$host_plugin_dir" == "~/"* ]]; then
            host_plugin_dir="${host_plugin_dir/#\~/$HOME}"
        fi
        if dir_exists "$host_plugin_dir"; then
            local_plugin_dir_env="$CONTAINER_OPENCODE_PLUGIN_DIR"
        fi
    fi

    if file_exists "$template_path"; then
        local template_dst="$CONTAINER_HOME/.config/opencode/opencode-foundry.json"
        if ! $copy_file_fn "$container_id" "$template_path" "$template_dst"; then
            if [ "$quiet" != "1" ]; then
                log_warn "Failed to copy opencode-foundry config template"
            fi
            return 0
        fi
        if ! $run_fn docker exec -i -u "$CONTAINER_USER" \
            -e SANDBOX_OPENCODE_DISABLE_NPM_PLUGINS="$disable_npm_plugins" \
            -e SANDBOX_OPENCODE_LOCAL_PLUGIN_DIR="$local_plugin_dir_env" \
            "$container_id" python3 - "$template_dst" "$CONTAINER_HOME/.config/opencode/opencode.json" <<'PY'
import json
import os
import shutil
import sys

template_path = sys.argv[1]
config_path = sys.argv[2]

def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def deep_merge(base, overlay):
    result = base.copy()
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        elif key not in result:
            result[key] = value
    return result

template = load_json(template_path)
existing = load_json(config_path)
merged = deep_merge(existing, template)

def is_local_plugin(plugin):
    if isinstance(plugin, str):
        return plugin.startswith(("/", "./", "../", "~/"))
    if isinstance(plugin, dict):
        path = plugin.get("path") or plugin.get("file") or plugin.get("src")
        if isinstance(path, str):
            return path.startswith(("/", "./", "../", "~/"))
    return False

local_plugin_dir = os.environ.get("SANDBOX_OPENCODE_LOCAL_PLUGIN_DIR") or ""

def plugin_spec(plugin):
    if isinstance(plugin, str):
        return plugin
    if isinstance(plugin, dict):
        for key in ("name", "package", "npm", "module"):
            value = plugin.get(key)
            if isinstance(value, str):
                version = plugin.get("version")
                if isinstance(version, str) and version:
                    return f"{value}@{version}"
                return value
    return None

def plugin_name(spec):
    if not isinstance(spec, str) or not spec:
        return ""
    if spec.startswith("@"):
        if "@" in spec[1:]:
            return spec.rsplit("@", 1)[0]
        return spec
    if "@" in spec:
        return spec.split("@", 1)[0]
    return spec

def map_plugin_to_local(plugin):
    if is_local_plugin(plugin):
        return plugin
    spec = plugin_spec(plugin)
    name = plugin_name(spec)
    if not name:
        return plugin
    local_path = os.path.join(local_plugin_dir, name)
    if isinstance(plugin, dict):
        mapped = plugin.copy()
        mapped["path"] = local_path
        return mapped
    return local_path

if local_plugin_dir:
    plugins = merged.get("plugin")
    if isinstance(plugins, list):
        merged["plugin"] = [map_plugin_to_local(plugin) for plugin in plugins]

disable_npm_plugins = os.environ.get("SANDBOX_OPENCODE_DISABLE_NPM_PLUGINS", "0") == "1"
if disable_npm_plugins:
    plugins = merged.get("plugin")
    if isinstance(plugins, list):
        local_plugins = [plugin for plugin in plugins if is_local_plugin(plugin)]
        if local_plugins:
            merged["plugin"] = local_plugins
        else:
            merged.pop("plugin", None)
    else:
        merged.pop("plugin", None)

def find_executable(name, extra_paths=()):
    path = shutil.which(name)
    if path:
        return path
    for candidate in extra_paths:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

foundry_cmd = find_executable("foundry-mcp", (
    "/home/ubuntu/.local/bin/foundry-mcp",
    "/usr/local/bin/foundry-mcp",
    "/usr/bin/foundry-mcp",
))
uvx_cmd = find_executable("uvx", (
    "/home/ubuntu/.local/bin/uvx",
    "/usr/local/bin/uvx",
    "/usr/bin/uvx",
))

command = merged.get("mcp", {}).get("foundry-mcp", {}).get("command", [])
command_list = command if isinstance(command, list) else []

def command_looks_like_foundry(cmd):
    if not cmd:
        return True
    head = cmd[0]
    if head in ("uvx", "foundry-mcp"):
        return True
    if head in ("python", "python3") and len(cmd) >= 3 and cmd[1] == "-m":
        module = cmd[2]
        return module in ("foundry-mcp", "foundry_mcp", "foundry_mcp.server")
    return False

def pick_foundry_command(cmd):
    if foundry_cmd:
        return [foundry_cmd]
    if uvx_cmd:
        if cmd and cmd[0] == "uvx":
            return [uvx_cmd] + cmd[1:]
        return [uvx_cmd, "foundry-mcp"]
    python_cmd = sys.executable or find_executable("python3") or find_executable("python")
    if python_cmd:
        return [python_cmd, "-m", "foundry_mcp.server"]
    return None

if command_looks_like_foundry(command_list):
    new_command = pick_foundry_command(command_list)
    if new_command:
        merged.setdefault("mcp", {}).setdefault("foundry-mcp", {})["command"] = new_command

os.makedirs(os.path.dirname(config_path), exist_ok=True)
with open(config_path, "w") as f:
    json.dump(merged, f, indent=2)
    f.write("\n")
PY
        then
            if [ "$quiet" != "1" ]; then
                log_warn "Failed to merge opencode-foundry config"
            fi
        fi
    else
        if [ "$quiet" != "1" ]; then
            log_warn "opencode-foundry config template not found: $template_path"
        fi
    fi
}

# Add tavily-mcp to OpenCode's MCP configuration (only if TAVILY_API_KEY is set)
ensure_opencode_tavily_mcp() {
    local container_id="$1"
    local quiet="${2:-0}"
    local run_fn="run_cmd"
    if [ "$quiet" = "1" ]; then
        run_fn="run_cmd_quiet"
    fi

    # Skip if TAVILY_API_KEY is not set or is the credential proxy placeholder
    if [ -z "${TAVILY_API_KEY:-}" ] || [ "${TAVILY_API_KEY}" = "CREDENTIAL_PROXY_PLACEHOLDER" ]; then
        return 0
    fi

    $run_fn docker exec -u "$CONTAINER_USER" -i "$container_id" python3 - <<'PY'
import json
import os

config_path = "/home/ubuntu/.config/opencode/opencode.json"

def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

data = load_json(config_path)
if not isinstance(data, dict):
    data = {}

# Ensure mcp section exists and is a dict
mcp = data.get("mcp")
if not isinstance(mcp, dict):
    mcp = {}
    data["mcp"] = mcp

# Add tavily-mcp if not already configured
if "tavily-mcp" not in mcp:
    mcp["tavily-mcp"] = {
        "command": ["tavily-mcp"]
    }

    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
PY
}

ensure_opencode_default_model() {
    local container_id="$1"
    local quiet="${2:-0}"
    local default_model="${SANDBOX_OPENCODE_DEFAULT_MODEL}"
    local run_fn="run_cmd"
    if [ "$quiet" = "1" ]; then
        run_fn="run_cmd_quiet"
    fi

    if [ -z "$default_model" ]; then
        return 0
    fi

    $run_fn docker exec -u "$CONTAINER_USER" -i "$container_id" python3 - <<'PY'
import json
import os

config_path = "/home/ubuntu/.config/opencode/opencode.json"
default_model = os.environ.get("SANDBOX_OPENCODE_DEFAULT_MODEL", "").strip()
if not default_model:
    raise SystemExit(0)

def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

data = load_json(config_path)
if not isinstance(data, dict):
    data = {}

model = data.get("model")
if not model:
    data["model"] = default_model
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
PY
}

prefetch_opencode_npm_plugins() {
    local container_id="$1"
    local quiet="${2:-0}"

    if [ "${SANDBOX_OPENCODE_PREFETCH_NPM_PLUGINS:-0}" != "1" ]; then
        return 0
    fi

    local run_fn="run_cmd"
    if [ "$quiet" = "1" ]; then
        run_fn="run_cmd_quiet"
    fi

    if [ "$quiet" != "1" ]; then
        log_info "Prefetching OpenCode npm plugins..."
    fi

    if $run_fn docker exec -u "$CONTAINER_USER" -i "$container_id" python3 - <<'PY'
import json
import os
import shutil
import subprocess
import sys

config_path = "/home/ubuntu/.config/opencode/opencode.json"
cache_dir = "/home/ubuntu/.cache/opencode"

def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def is_local_plugin(plugin):
    if isinstance(plugin, str):
        return plugin.startswith(("/", "./", "../", "~/"))
    if isinstance(plugin, dict):
        path = plugin.get("path") or plugin.get("file") or plugin.get("src")
        if isinstance(path, str):
            return path.startswith(("/", "./", "../", "~/"))
    return False

def plugin_spec(plugin):
    if isinstance(plugin, str):
        return plugin
    if isinstance(plugin, dict):
        for key in ("name", "package", "npm", "module"):
            value = plugin.get(key)
            if isinstance(value, str):
                version = plugin.get("version")
                if isinstance(version, str) and version:
                    return f"{value}@{version}"
                return value
    return None

def split_spec(spec):
    if spec.startswith("@"):
        if "@" in spec[1:]:
            name, _, version = spec.rpartition("@")
            return name, version
        return spec, ""
    if "@" in spec:
        name, version = spec.split("@", 1)
        return name, version
    return spec, ""

config = load_json(config_path)
plugins = config.get("plugin")
if not isinstance(plugins, list):
    raise SystemExit(0)

deps = {}
for plugin in plugins:
    if is_local_plugin(plugin):
        continue
    spec = plugin_spec(plugin)
    if not spec:
        continue
    name, version = split_spec(spec)
    if not name:
        continue
    deps[name] = version or "latest"

if not deps:
    raise SystemExit(0)

os.makedirs(cache_dir, exist_ok=True)
pkg_path = os.path.join(cache_dir, "package.json")
existing = load_json(pkg_path)
existing_deps = existing.get("dependencies") if isinstance(existing, dict) else {}
if not isinstance(existing_deps, dict):
    existing_deps = {}

changed = False
for name, version in deps.items():
    if existing_deps.get(name) != version:
        existing_deps[name] = version
        changed = True

if changed or not os.path.exists(pkg_path):
    with open(pkg_path, "w") as f:
        json.dump({"dependencies": existing_deps}, f, indent=2)
        f.write("\n")

node_modules = os.path.join(cache_dir, "node_modules")
all_installed = True
for name in deps:
    parts = name.split("/")
    path = os.path.join(node_modules, *parts)
    if not os.path.isdir(path):
        all_installed = False
        break

if all_installed:
    raise SystemExit(0)

installer = None
if shutil.which("bun"):
    installer = ["bun", "install"]
elif shutil.which("npm"):
    installer = ["npm", "install", "--no-fund", "--no-audit"]

if not installer:
    print("OpenCode plugin prefetch skipped: bun/npm not available", file=sys.stderr)
    raise SystemExit(0)

try:
    subprocess.check_call(installer, cwd=cache_dir)
except Exception as exc:
    print(f"OpenCode plugin prefetch failed: {exc}", file=sys.stderr)
    sys.exit(1)
PY
    then
        return 0
    fi

    if [ "$quiet" != "1" ]; then
        log_warn "Failed to prefetch OpenCode npm plugins"
    fi
}

sync_opencode_local_plugins_on_first_attach() {
    local name="$1"
    local container_id="$2"
    local quiet="${3:-0}"

    local host_dir="${SANDBOX_OPENCODE_PLUGIN_DIR:-}"
    if [ -z "$host_dir" ]; then
        return 0
    fi
    if [[ "$host_dir" == "~/"* ]]; then
        host_dir="${host_dir/#\~/$HOME}"
    fi
    if ! dir_exists "$host_dir"; then
        if [ "$quiet" != "1" ]; then
            log_warn "OpenCode local plugin dir not found: $host_dir"
        fi
        return 0
    fi

    local marker
    marker=$(path_opencode_plugins_marker "$name")

    local has_container_plugins="0"
    if docker exec "$container_id" sh -c "test -d '$CONTAINER_OPENCODE_PLUGIN_DIR' && [ \"\$(ls -A '$CONTAINER_OPENCODE_PLUGIN_DIR' 2>/dev/null)\" ]" >/dev/null 2>&1; then
        has_container_plugins="1"
    fi

    if [ -f "$marker" ] && [ "$has_container_plugins" = "1" ]; then
        if [ "$quiet" != "1" ]; then
            log_debug "OpenCode local plugins already synced."
        fi
        return 0
    fi

    if [ "$quiet" != "1" ]; then
        log_info "Syncing OpenCode local plugins from $host_dir..."
    fi

    if ! copy_dir_to_container "$container_id" "$host_dir" "$CONTAINER_OPENCODE_PLUGIN_DIR"; then
        if [ "$quiet" != "1" ]; then
            log_warn "Failed to sync OpenCode local plugins from $host_dir"
        fi
        return 0
    fi

    ensure_dir "$(dirname "$marker")"
    printf "%s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" > "$marker"
    chmod 600 "$marker" 2>/dev/null || true

    sync_opencode_foundry "$container_id" "$quiet"
    ensure_opencode_tavily_mcp "$container_id" "$quiet"
}

# Ensure Claude model defaults and hooks are set in settings.json.
# This runs AFTER host settings are copied, so it restores the hooks configuration.
# Also installs pyright-lsp plugin (optional, uses normal plugin system).
ensure_claude_foundry_mcp() {
    local container_id="$1"
    local quiet="${2:-0}"
    local run_fn="run_cmd"
    if [ "$quiet" = "1" ]; then
        run_fn="run_cmd_quiet"
    fi

    # Set model defaults and hooks in settings.json
    # Note: Host settings are copied first, so we must restore hooks here
    $run_fn docker exec -u "$CONTAINER_USER" -i "$container_id" python3 - <<'PY'
import json
import os

path = "/home/ubuntu/.claude/settings.json"

def load_json(p):
    try:
        with open(p) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

data = load_json(path)

# Force model settings (opus for main, haiku for subagents)
data["model"] = "opus"
data["subagentModel"] = "haiku"
data["alwaysThinkingEnabled"] = True

# Configure hooks with absolute paths (these get overwritten when host settings are copied)
data["hooks"] = {
    "PreToolUse": [
        {
            "matcher": "Read",
            "hooks": [{"type": "command", "command": "/home/ubuntu/.claude/hooks/block-json-specs"}]
        },
        {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/home/ubuntu/.claude/hooks/block-spec-bash-access"}]
        }
    ],
    "PostToolUse": [
        {
            "hooks": [{"type": "command", "command": "/home/ubuntu/.claude/hooks/context-monitor"}]
        }
    ]
}

# Foundry permissions based on claude-foundry v2.1.0
FOUNDRY_ALLOW = [
    "Skill(foundry:*)",
    "mcp__plugin_foundry_foundry-mcp__*",
    "mcp__tavily-mcp__*",
    "Bash(git add:*)",
    "Bash(git branch:*)",
    "Bash(git checkout:*)",
    "Bash(git clone:*)",
    "Bash(git commit:*)",
    "Bash(git config:*)",
    "Bash(git diff:*)",
    "Bash(git fetch:*)",
    "Bash(git init:*)",
    "Bash(git log:*)",
    "Bash(git ls-files:*)",
    "Bash(git merge:*)",
    "Bash(git mv:*)",
    "Bash(git pull:*)",
    "Bash(git push:*)",
    "Bash(git remote:*)",
    "Bash(git restore:*)",
    "Bash(git rev-parse:*)",
    "Bash(git revert:*)",
    "Bash(git show:*)",
    "Bash(git stash:*)",
    "Bash(git status:*)",
    "Bash(git switch:*)",
    "Bash(git tag:*)",
    "Bash(gh issue create:*)",
    "Bash(gh issue list:*)",
    "Bash(gh issue view:*)",
    "Bash(gh pr checkout:*)",
    "Bash(gh pr create:*)",
    "Bash(gh pr list:*)",
    "Bash(gh pr status:*)",
    "Bash(gh pr view:*)",
    "Bash(gh repo clone:*)",
    "Bash(gh repo view:*)",
    "Bash(pytest:*)",
    "Bash(agent:*)",
    "Bash(claude:*)",
    "Bash(claude-agent:*)",
    "Bash(codex:*)",
    "Bash(gemini:*)",
    "Bash(opencode:*)",
    "Read(/workspace/**)",
    "Write(/workspace/**)",
    "Edit(/workspace/**)",
]

FOUNDRY_DENY = [
    "Read(/workspace/**/specs/**/*.json)",
    "Bash(gh api:*)",
    "Bash(gh repo delete:*)",
    "Bash(gh release delete:*)",
    "Bash(gh secret:*)",
    "Bash(gh variable:*)",
]

# Merge permissions (preserving existing, adding foundry)
if "permissions" not in data:
    data["permissions"] = {}
existing_allow = set(data["permissions"].get("allow", []))
existing_deny = set(data["permissions"].get("deny", []))
data["permissions"]["allow"] = sorted(existing_allow | set(FOUNDRY_ALLOW))
data["permissions"]["deny"] = sorted(existing_deny | set(FOUNDRY_DENY))

# Remove foundry plugin from enabledPlugins - we use direct global install for it
# This prevents "Plugin not found" errors from stale host config
# But keep other plugins like pyright-lsp that use the normal plugin system
if "enabledPlugins" in data:
    data["enabledPlugins"].pop("foundry@claude-foundry", None)
    # Clean up empty dict
    if not data["enabledPlugins"]:
        del data["enabledPlugins"]

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY

    # pyright-lsp is optional - install via normal plugin system
    if [ "$quiet" != "1" ]; then
        if docker exec "$container_id" sh -c \
            "ls $CONTAINER_HOME/.claude/plugins/cache/claude-plugins-official/pyright-lsp/*/\.claude-plugin/plugin.json" \
            >/dev/null 2>&1; then
            log_debug "pyright-lsp already cached"
            docker exec -u "$CONTAINER_USER" "$container_id" \
                claude plugin enable pyright-lsp@claude-plugins-official 2>/dev/null || true
        else
            log_debug "Attempting pyright-lsp install (optional)..."
            docker exec -u "$CONTAINER_USER" "$container_id" sh -c "
                claude plugin marketplace add anthropics/claude-plugins-official 2>/dev/null && \
                claude plugin install pyright-lsp@claude-plugins-official 2>/dev/null && \
                claude plugin enable pyright-lsp@claude-plugins-official 2>/dev/null
            " || log_debug "pyright-lsp not installed (optional)"
        fi
    fi
}

ensure_github_https_git() {
    local container_id="$1"
    local quiet="${2:-0}"
    local enable_ssh="${3:-0}"
    local run_fn="run_cmd"
    if [ "$quiet" = "1" ]; then
        run_fn="run_cmd_quiet"
    fi

    if [ "$enable_ssh" = "1" ]; then
        return 0
    fi

    if [ "$quiet" != "1" ]; then
        log_info "Forcing HTTPS for GitHub Git remotes (SSH disabled)..."
    fi

    $run_fn docker exec -u "$CONTAINER_USER" "$container_id" sh -c "
        export HOME='$CONTAINER_HOME'
        cd '$CONTAINER_HOME' || exit 0
        git config --global --unset-all url.\"git@github.com:\".insteadOf 2>/dev/null || true
        git config --global --unset-all url.\"ssh://git@github.com/\".insteadOf 2>/dev/null || true
        git config --global --unset-all url.\"git@github.com:\".pushInsteadOf 2>/dev/null || true
        git config --global --unset-all url.\"ssh://git@github.com/\".pushInsteadOf 2>/dev/null || true
        git config --global --unset-all url.\"https://github.com/\".insteadOf 2>/dev/null || true
        git config --global --add url.\"https://github.com/\".insteadOf git@github.com: 2>/dev/null || true
        git config --global --add url.\"https://github.com/\".insteadOf ssh://git@github.com/ 2>/dev/null || true
    "

    # Configure gh as credential helper after URL rewriting
    configure_gh_credential_helper "$container_id" "$quiet"
}

# Configure gh as the git credential helper for HTTPS authentication
# This leverages existing gh auth credentials from ~/.config/gh
# When SANDBOX_GATEWAY_ENABLED=true, skip this - credentials are injected by the gateway
configure_gh_credential_helper() {
    local container_id="$1"
    local quiet="${2:-0}"

    # Skip when credential isolation gateway is enabled
    # The gateway injects credentials; no token material should be in the container
    if [ "${SANDBOX_GATEWAY_ENABLED:-}" = "true" ]; then
        if [ "$quiet" != "1" ]; then
            log_debug "Skipping gh credential helper (gateway enabled)"
        fi
        return 0
    fi

    # Only configure if gh config exists in container
    docker exec -u "$CONTAINER_USER" "$container_id" sh -c "
        export HOME='$CONTAINER_HOME'
        if [ -d '$CONTAINER_HOME/.config/gh' ] && command -v gh >/dev/null 2>&1; then
            git config --global credential.helper '!gh auth git-credential'
        fi
    " 2>/dev/null || true
}

ensure_claude_statusline() {
    local container_id="$1"
    local quiet="${2:-0}"
    local run_fn="run_cmd"
    if [ "$quiet" = "1" ]; then
        run_fn="run_cmd_quiet"
    fi

    local binary_exists=0
    if $run_fn docker exec "$container_id" sh -c "command -v claude-statusline >/dev/null 2>&1 || [ -x $CONTAINER_HOME/.local/bin/claude-statusline ]"; then
        binary_exists=1
    fi

    local statusline_configured=0
    if $run_fn docker exec "$container_id" sh -c "test -f $CONTAINER_HOME/.claude/settings.json && grep -q '\"statusLine\"' $CONTAINER_HOME/.claude/settings.json"; then
        statusline_configured=1
    fi

    if [ "$binary_exists" = "1" ]; then
        # Binary exists - ensure config uses the bundled binary
        if [ "$statusline_configured" = "1" ]; then
            # Check if the current command uses the bundled binary
            local uses_bundled=0
            if $run_fn docker exec "$container_id" sh -c "grep -q '\"command\": \"claude-statusline\"' $CONTAINER_HOME/.claude/settings.json 2>/dev/null"; then
                uses_bundled=1
            fi
            if [ "$uses_bundled" = "1" ]; then
                return 0  # Already using bundled binary
            fi
            # Otherwise, replace with bundled binary (network commands like npx won't work in sandbox)
        fi
        # Set the statusLine configuration to use the bundled binary
        $run_fn docker exec -u "$CONTAINER_USER" -i "$container_id" python3 - <<'PY'
import json
import os

path = "/home/ubuntu/.claude/settings.json"
os.makedirs(os.path.dirname(path), exist_ok=True)

if os.path.exists(path):
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        data = {}
else:
    data = {}

# Always set to bundled binary (replaces any network-dependent commands like npx)
data["statusLine"] = {
    "type": "command",
    "command": "claude-statusline",
    "padding": 0
}
with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
    else
        # Binary missing - remove config if present
        if [ "$statusline_configured" = "0" ]; then
            return 0  # Not configured, nothing to do
        fi
        $run_fn docker exec -u "$CONTAINER_USER" -i "$container_id" python3 - <<'PY'
import json
import os

path = "/home/ubuntu/.claude/settings.json"
if not os.path.exists(path):
    raise SystemExit(0)

try:
    with open(path, "r") as f:
        data = json.load(f)
except json.JSONDecodeError:
    data = {}

if "statusLine" in data:
    data.pop("statusLine", None)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
PY
        if [ "$quiet" != "1" ]; then
            log_warn "claude-statusline not found; removing statusLine from Claude settings inside sandbox. Install cc-context-stats in the container to enable it."
        fi
    fi
}

ensure_claude_onboarding() {
    local container_id="$1"
    local quiet="${2:-0}"
    local run_fn="run_cmd"
    if [ "$quiet" = "1" ]; then
        run_fn="run_cmd_quiet"
    fi

    $run_fn docker exec -u "$CONTAINER_USER" -i "$container_id" python3 - <<'PY'
import json
import os

paths = [
    "/home/ubuntu/.claude.json",
    "/home/ubuntu/.claude/.claude.json",
]

for path in paths:
    data = {}
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}

    if not isinstance(data, dict):
        data = {}

    changed = False
    if data.get("hasCompletedOnboarding") is not True:
        data["hasCompletedOnboarding"] = True
        changed = True
    if data.get("githubRepoPaths") != {}:
        data["githubRepoPaths"] = {}
        changed = True
    if data.get("projects") != {}:
        data["projects"] = {}
        changed = True
    if data.get("skillUsage") != {}:
        data["skillUsage"] = {}
        changed = True
    if data.get("autoUpdates") is not False:
        data["autoUpdates"] = False
        changed = True
    if data.get("autoCompactEnabled") is not False:
        data["autoCompactEnabled"] = False
        changed = True
    if changed or not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
PY
}

# Register foundry-mcp server in ~/.claude.json inside the container.
# This is called after host's ~/.claude.json is copied (if it exists).
ensure_foundry_mcp_config() {
    local container_id="$1"
    local quiet="${2:-0}"
    local run_fn="run_cmd"
    if [ "$quiet" = "1" ]; then
        run_fn="run_cmd_quiet"
    fi

    $run_fn docker exec -u "$CONTAINER_USER" -i "$container_id" python3 - <<'PY'
import json
import os

paths = [
    "/home/ubuntu/.claude.json",
    "/home/ubuntu/.claude/.claude.json",
]

for path in paths:
    data = {}
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}

    if not isinstance(data, dict):
        data = {}

    # Add MCP server configuration
    if "mcpServers" not in data:
        data["mcpServers"] = {}

    # Only add if not already configured
    changed = False
    if "foundry-mcp" not in data["mcpServers"]:
        data["mcpServers"]["foundry-mcp"] = {
            "command": "python",
            "args": ["-m", "foundry_mcp.server"]
        }
        changed = True

    # Only add tavily-mcp if TAVILY_API_KEY is available (and not the placeholder)
    tavily_key = os.environ.get("TAVILY_API_KEY", "")
    if tavily_key and tavily_key != "CREDENTIAL_PROXY_PLACEHOLDER":
        if "tavily-mcp" not in data["mcpServers"]:
            data["mcpServers"]["tavily-mcp"] = {
                "command": "tavily-mcp",
                "args": []
            }
            changed = True

    if changed:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
PY
}

ensure_codex_config() {
    local container_id="$1"
    local quiet="${2:-0}"
    local run_fn="run_cmd"
    if [ "$quiet" = "1" ]; then
        run_fn="run_cmd_quiet"
    fi

    if [ "$quiet" != "1" ]; then
        log_info "Ensuring Codex config defaults (no updates/analytics)..."
    fi

    $run_fn docker exec -u "$CONTAINER_USER" -i "$container_id" python3 - <<'PY'
import os
import re

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None

path = "/home/ubuntu/.codex/config.toml"
os.makedirs(os.path.dirname(path), exist_ok=True)

default_approval_policy_line = 'approval_policy = "on-failure"'
default_sandbox_mode_line = 'sandbox_mode = "danger-full-access"'
default_update_line = "check_for_update_on_startup = false"
default_analytics_lines = ["[analytics]", "enabled = false"]
default_tavily_mcp_lines = ["[mcp_servers.tavily-mcp]", 'command = "tavily-mcp"', "args = []"]

# Only include tavily-mcp if API key is available (and not the placeholder)
tavily_key = os.environ.get("TAVILY_API_KEY", "")
include_tavily = tavily_key and tavily_key != "CREDENTIAL_PROXY_PLACEHOLDER"

if not os.path.exists(path):
    with open(path, "w") as f:
        root_lines = [
            default_approval_policy_line,
            default_sandbox_mode_line,
            default_update_line,
        ]
        content = "\n".join(root_lines) + "\n\n" + "\n".join(default_analytics_lines)
        if include_tavily:
            content += "\n\n" + "\n".join(default_tavily_mcp_lines)
        f.write(content + "\n")
    raise SystemExit(0)

with open(path, "r") as f:
    text = f.read()

data = {}
if tomllib is not None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        data = {}

missing_update = "check_for_update_on_startup" not in data
if missing_update:
    if re.search(r"(?m)^\\s*check_for_update_on_startup\\s*=", text):
        missing_update = False
missing_approval_policy = "approval_policy" not in data
if missing_approval_policy:
    if re.search(r"(?m)^\\s*approval_policy\\s*=", text):
        missing_approval_policy = False
missing_sandbox_mode = "sandbox_mode" not in data
if missing_sandbox_mode:
    if re.search(r"(?m)^\\s*sandbox_mode\\s*=", text):
        missing_sandbox_mode = False
analytics = data.get("analytics") if isinstance(data, dict) else None
missing_analytics_enabled = not (isinstance(analytics, dict) and "enabled" in analytics)

# Check if tavily-mcp MCP server is configured (only if API key is available)
mcp_servers = data.get("mcp_servers") if isinstance(data, dict) else None
missing_tavily_mcp = False
if include_tavily:
    missing_tavily_mcp = not (isinstance(mcp_servers, dict) and "tavily-mcp" in mcp_servers)
    if missing_tavily_mcp:
        # Also check raw text for section header
        if re.search(r"(?m)^\s*\[mcp_servers\.tavily-mcp\]", text):
            missing_tavily_mcp = False

inline_changed = False
if missing_analytics_enabled:
    inline_re = re.compile(r"(?m)^(\\s*analytics\\s*=\\s*\\{)([^}]*)\\}(\\s*(#.*)?)$")
    match = inline_re.search(text)
    if match:
        inner = match.group(2)
        if not re.search(r"\\benabled\\s*=", inner):
            inner_clean = inner.strip()
            if inner_clean:
                new_inner = inner_clean + ", enabled = false"
            else:
                new_inner = "enabled = false"
            new_line = match.group(1) + new_inner + "}" + match.group(3)
            text = text[:match.start()] + new_line + text[match.end():]
            inline_changed = True

prepend_lines = []
append_lines = []

# Root-level settings must be prepended to avoid ending up under a section header
if missing_approval_policy:
    prepend_lines.append(default_approval_policy_line)
if missing_sandbox_mode:
    prepend_lines.append(default_sandbox_mode_line)
if missing_update:
    prepend_lines.append(default_update_line)

if missing_analytics_enabled and not inline_changed:
    append_lines.append("")
    append_lines.extend(default_analytics_lines)

if missing_tavily_mcp:
    append_lines.append("")
    append_lines.extend(default_tavily_mcp_lines)

changed = inline_changed or bool(prepend_lines) or bool(append_lines)
if changed:
    if prepend_lines:
        prepend_text = "\n".join(prepend_lines) + "\n\n"
        text = prepend_text + text
    if append_lines:
        if text and not text.endswith("\n"):
            text += "\n"
        text += "\n".join(append_lines).rstrip() + "\n"
    with open(path, "w") as f:
        f.write(text)
PY
}

ensure_gemini_settings() {
    local container_id="$1"
    local quiet="${2:-0}"
    local run_fn="run_cmd"
    if [ "$quiet" = "1" ]; then
        run_fn="run_cmd_quiet"
    fi

    if [ "$quiet" != "1" ]; then
        log_info "Ensuring Gemini settings defaults (no updates/telemetry)..."
    fi

    $run_fn docker exec -u "$CONTAINER_USER" -i "$container_id" python3 - <<'PY'
import json
import os

path = "/home/ubuntu/.gemini/settings.json"
os.makedirs(os.path.dirname(path), exist_ok=True)

data = {}
if os.path.exists(path):
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        data = {}

if not isinstance(data, dict):
    data = {}

changed = False

general = data.get("general")
if not isinstance(general, dict):
    general = {}
if "disableAutoUpdate" not in general:
    general["disableAutoUpdate"] = True
    changed = True
if "disableUpdateNag" not in general:
    general["disableUpdateNag"] = True
    changed = True
if "previewFeatures" not in general:
    general["previewFeatures"] = True
    changed = True
if general:
    data["general"] = general

telemetry = data.get("telemetry")
if not isinstance(telemetry, dict):
    telemetry = {}
if "enabled" not in telemetry:
    telemetry["enabled"] = False
    changed = True
if telemetry:
    data["telemetry"] = telemetry

privacy = data.get("privacy")
if not isinstance(privacy, dict):
    privacy = {}
if "usageStatisticsEnabled" not in privacy:
    privacy["usageStatisticsEnabled"] = False
    changed = True
if privacy:
    data["privacy"] = privacy

# Add tavily-mcp to mcpServers (only if TAVILY_API_KEY is available and not placeholder)
tavily_key = os.environ.get("TAVILY_API_KEY", "")
if tavily_key and tavily_key != "CREDENTIAL_PROXY_PLACEHOLDER":
    mcp_servers = data.get("mcpServers")
    if not isinstance(mcp_servers, dict):
        mcp_servers = {}
    if "tavily-mcp" not in mcp_servers:
        mcp_servers["tavily-mcp"] = {
            "command": "tavily-mcp",
            "args": []
        }
        changed = True
    if mcp_servers:
        data["mcpServers"] = mcp_servers

if changed or not os.path.exists(path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
PY
}

ensure_foundry_mcp_workspace_dirs() {
    local container_id="$1"
    local working_dir="${2:-}"
    local quiet="${3:-0}"

    if [ "$quiet" != "1" ]; then
        log_info "Creating foundry-mcp workspace directories..."
    fi

    # Calculate specs base path (includes working_dir if set)
    local specs_base="/workspace${working_dir:+/$working_dir}"

    # Create workspace specs directories
    docker exec "$container_id" mkdir -p \
        "$specs_base/specs/active" \
        "$specs_base/specs/pending" \
        "$specs_base/specs/completed" \
        "$specs_base/specs/archived" \
        "$specs_base/specs/.notes" \
        "$specs_base/specs/.plans" \
        "$specs_base/specs/.plan-reviews" \
        "$specs_base/specs/.fidelity-reviews" \
        "$specs_base/specs/.research/conversations" \
        "$specs_base/specs/.research/investigations" \
        "$specs_base/specs/.research/ideations" \
        "$specs_base/specs/.research/deep-research"

    # Create home foundry-mcp directories
    docker exec "$container_id" mkdir -p \
        "$CONTAINER_HOME/.foundry-mcp/cache" \
        "$CONTAINER_HOME/.foundry-mcp/errors" \
        "$CONTAINER_HOME/.foundry-mcp/metrics"

    # Fix ownership
    docker exec "$container_id" sh -c "
        chown -R $CONTAINER_USER:$CONTAINER_USER $specs_base/specs 2>/dev/null || true
        chown -R $CONTAINER_USER:$CONTAINER_USER $CONTAINER_HOME/.foundry-mcp 2>/dev/null || true
    "
}

copy_configs_to_container() {
    local container_id="$1"
    local skip_plugins="${2:-0}"
    local enable_ssh="${3:-${SANDBOX_SYNC_SSH:-0}}"
    local working_dir="${4:-}"
    local isolate_credentials="${5:-false}"

    # Create container user if using host user matching
    ensure_container_user "$container_id"

    log_info "Copying config files into container..."

    # Home is tmpfs; wait briefly for it to be ready before copying.
    local attempts=0
    while ! docker exec "$container_id" test -d "$CONTAINER_HOME/.config" 2>/dev/null; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 5 ]; then
            break
        fi
        sleep 0.2
    done

    run_cmd docker exec -u "$CONTAINER_USER" "$container_id" mkdir -p \
        "$CONTAINER_HOME/.claude" \
        "$CONTAINER_HOME/.config/gh" \
        "$CONTAINER_HOME/.gemini" \
        "$CONTAINER_HOME/.config/opencode" \
        "$CONTAINER_HOME/.local/share/opencode" \
        "$CONTAINER_HOME/.codex" \
        "$CONTAINER_HOME/.ssh" \
        "$CONTAINER_HOME/.ssh/sockets"

    # Claude config from host (no credentials file sync)
    if file_exists ~/.claude.json; then
        copy_file_to_container "$container_id" ~/.claude.json "$CONTAINER_HOME/.claude.json"
        copy_file_to_container "$container_id" ~/.claude.json "$CONTAINER_HOME/.claude/.claude.json"
    fi
    # Fix ownership immediately (docker exec may run as root in credential isolation mode)
    docker exec "$container_id" chown -R "$CONTAINER_USER:$CONTAINER_USER" "$CONTAINER_HOME/.claude" "$CONTAINER_HOME/.claude.json" 2>/dev/null || true
    ensure_claude_onboarding "$container_id"
    ensure_foundry_mcp_config "$container_id"
    if file_exists ~/.claude/settings.json; then
        copy_file_to_container "$container_id" ~/.claude/settings.json "$CONTAINER_HOME/.claude/settings.json"
    fi
    if file_exists ~/.claude/statusline.conf; then
        copy_file_to_container "$container_id" ~/.claude/statusline.conf "$CONTAINER_HOME/.claude/statusline.conf"
    elif file_exists "$SCRIPT_DIR/statusline.conf"; then
        copy_file_to_container "$container_id" "$SCRIPT_DIR/statusline.conf" "$CONTAINER_HOME/.claude/statusline.conf"
    fi
    ensure_claude_statusline "$container_id"
    dir_exists ~/.config/gh && copy_dir_to_container "$container_id" ~/.config/gh "$CONTAINER_HOME/.config/gh"
    # Skip auth file copies when credential isolation is enabled (they're mounted as stubs)
    if [ "$isolate_credentials" != "true" ]; then
        # Gemini CLI OAuth credentials (created via `gemini auth` on host)
        if file_exists ~/.gemini/oauth_creds.json; then
            docker exec -u "$CONTAINER_USER" "$container_id" mkdir -p "$CONTAINER_HOME/.gemini" 2>/dev/null || true
            copy_file_to_container "$container_id" ~/.gemini/oauth_creds.json "$CONTAINER_HOME/.gemini/oauth_creds.json"
        fi
        file_exists ~/.local/share/opencode/auth.json && copy_file_to_container "$container_id" ~/.local/share/opencode/auth.json "$CONTAINER_HOME/.local/share/opencode/auth.json"
        dir_exists ~/.codex && copy_dir_to_container "$container_id" ~/.codex "$CONTAINER_HOME/.codex" "${CODEX_COPY_EXCLUDES[@]}"
    fi
    # OpenCode config (not credentials)
    if file_exists ~/.config/opencode/opencode.json; then
        copy_file_to_container "$container_id" ~/.config/opencode/opencode.json "$CONTAINER_HOME/.config/opencode/opencode.json"
    elif file_exists "$SCRIPT_DIR/opencode.json"; then
        copy_file_to_container "$container_id" "$SCRIPT_DIR/opencode.json" "$CONTAINER_HOME/.config/opencode/opencode.json"
    fi
    # Skip settings writes when credential isolation is enabled (dirs may be read-only)
    if [ "$isolate_credentials" != "true" ]; then
        ensure_gemini_settings "$container_id"
        ensure_codex_config "$container_id"
    fi
    sync_opencode_foundry "$container_id"
    ensure_opencode_tavily_mcp "$container_id"
    ensure_opencode_default_model "$container_id" "$skip_plugins"
    if [ "$skip_plugins" != "1" ]; then
        prefetch_opencode_npm_plugins "$container_id"
    fi
    file_exists ~/.gitconfig && copy_file_to_container "$container_id" ~/.gitconfig "$CONTAINER_HOME/.gitconfig"
    if [ "$enable_ssh" = "1" ]; then
        local ssh_agent_sock=""
        ssh_agent_sock=$(resolve_ssh_agent_sock) || ssh_agent_sock=""
        if [ -n "$ssh_agent_sock" ]; then
            log_info "SSH agent forwarding enabled; skipping private key copy."
            file_exists ~/.ssh/known_hosts && copy_file_to_container "$container_id" ~/.ssh/known_hosts "$CONTAINER_HOME/.ssh/known_hosts"
            file_exists ~/.ssh/config && copy_file_to_container "$container_id" ~/.ssh/config "$CONTAINER_HOME/.ssh/config"
            docker exec "$container_id" sh -c "if [ -f /etc/skel/.ssh/known_hosts ]; then touch '$CONTAINER_HOME/.ssh/known_hosts'; cat /etc/skel/.ssh/known_hosts >> '$CONTAINER_HOME/.ssh/known_hosts'; fi" 2>/dev/null || true
            docker exec "$container_id" sh -c "touch '$CONTAINER_HOME/.ssh/config'; if ! grep -q '^Host github.com' '$CONTAINER_HOME/.ssh/config'; then printf '\nHost github.com\n  IdentityAgent %s\n  IdentitiesOnly no\n' '$SSH_AGENT_CONTAINER_SOCK' >> '$CONTAINER_HOME/.ssh/config'; fi" 2>/dev/null || true
        else
            log_warn "SSH agent not detected; skipping SSH key copy (agent-only mode)."
        fi
        # Remove macOS-specific SSH config options that don't work on Linux
        docker exec "$container_id" sed -i '/UseKeychain/d; /AddKeysToAgent.*apple/Id' "$CONTAINER_HOME/.ssh/config" 2>/dev/null || true
    fi
    dir_exists ~/.sandboxes/repos && copy_dir_to_container "$container_id" ~/.sandboxes/repos "$CONTAINER_HOME/.sandboxes/repos"
    # Copy foundry-mcp config: user config takes priority, fall back to sandbox bundled config
    local foundry_config_source=""
    if file_exists ~/.foundry-mcp.toml; then
        foundry_config_source="$HOME/.foundry-mcp.toml"
    elif file_exists "${FOUNDRY_SANDBOX_HOME:-$HOME/.foundry-sandbox}/.foundry-mcp.toml"; then
        foundry_config_source="${FOUNDRY_SANDBOX_HOME:-$HOME/.foundry-sandbox}/.foundry-mcp.toml"
    fi
    if [[ -n "$foundry_config_source" ]]; then
        docker exec -u "$CONTAINER_USER" "$container_id" mkdir -p "$CONTAINER_HOME/.config/foundry-mcp" 2>/dev/null || true
        copy_file_to_container "$container_id" "$foundry_config_source" "$CONTAINER_HOME/.config/foundry-mcp/config.toml"
        configure_foundry_research_providers "$container_id"
    fi
    fix_worktree_paths "$container_id" "$(whoami)"
    detect_nested_git_repos "$container_id"

    log_info "Fixing ownership..."
    run_cmd docker exec "$container_id" sh -c "
        chown -R $CONTAINER_USER:$CONTAINER_USER \
            $CONTAINER_HOME/.claude \
            $CONTAINER_HOME/.config \
            $CONTAINER_HOME/.gemini \
            $CONTAINER_HOME/.codex \
            $CONTAINER_HOME/.ssh \
            $CONTAINER_HOME/.sandboxes \
            $CONTAINER_HOME/.local/share/opencode \
            2>/dev/null
        chown $CONTAINER_USER:$CONTAINER_USER $CONTAINER_HOME/.gitconfig 2>/dev/null
        chmod 700 $CONTAINER_HOME/.ssh 2>/dev/null
        find $CONTAINER_HOME/.ssh -type d -exec chmod 700 {} + 2>/dev/null || true
        find $CONTAINER_HOME/.ssh -type f -exec chmod 600 {} + 2>/dev/null || true
    " || true

    ensure_github_https_git "$container_id" "0" "$enable_ssh"
    ssh_agent_preflight "$container_id" "$enable_ssh" "$skip_plugins"

    # Ensure model defaults (hooks and MCP are configured by prepopulate_foundry_global)
    ensure_claude_foundry_mcp "$container_id" "$skip_plugins"

    # Create foundry-mcp workspace directories
    ensure_foundry_mcp_workspace_dirs "$container_id" "$working_dir"

    # Install foundry workspace documentation
    install_foundry_workspace_docs "$container_id"

    # Debug: show what ended up in the container
    log_info "=== Claude Config Debug ==="
    docker exec "$container_id" sh -c "
        echo 'Settings (key fields):'
        python3 -c \"import json; d=json.load(open('$CONTAINER_HOME/.claude/settings.json')); print('  model:', d.get('model', 'NOT SET')); print('  hooks:', 'configured' if d.get('hooks') else 'NOT SET')\" 2>/dev/null || echo '  settings.json missing or invalid'
        echo 'Skills:'
        ls -1 $CONTAINER_HOME/.claude/skills/ 2>/dev/null | head -5 || echo '  no skills found'
        echo 'Hooks:'
        ls -1 $CONTAINER_HOME/.claude/hooks/ 2>/dev/null || echo '  no hooks found'
        echo 'MCP servers:'
        python3 -c \"import json; d=json.load(open('$CONTAINER_HOME/.claude.json')); print('  ', list(d.get('mcpServers', {}).keys()))\" 2>/dev/null || echo '  .claude.json missing or invalid'
    " || true
}

sync_runtime_credentials() {
    local container_id="$1"

    # Sync credentials for various AI tools
    # API keys are passed via environment variables (docker-compose), not copied from files
    dir_exists ~/.codex && copy_dir_to_container_quiet "$container_id" ~/.codex "$CONTAINER_HOME/.codex" "${CODEX_COPY_EXCLUDES[@]}"
    if file_exists ~/.claude.json; then
        copy_file_to_container_quiet "$container_id" ~/.claude.json "$CONTAINER_HOME/.claude.json"
        copy_file_to_container_quiet "$container_id" ~/.claude.json "$CONTAINER_HOME/.claude/.claude.json"
    fi
    ensure_claude_onboarding "$container_id" "1"
    ensure_foundry_mcp_config "$container_id" "1"
    if file_exists ~/.claude/settings.json; then
        copy_file_to_container_quiet "$container_id" ~/.claude/settings.json "$CONTAINER_HOME/.claude/settings.json"
    fi
    if file_exists ~/.claude/statusline.conf; then
        copy_file_to_container_quiet "$container_id" ~/.claude/statusline.conf "$CONTAINER_HOME/.claude/statusline.conf"
    elif file_exists "$SCRIPT_DIR/statusline.conf"; then
        copy_file_to_container_quiet "$container_id" "$SCRIPT_DIR/statusline.conf" "$CONTAINER_HOME/.claude/statusline.conf"
    fi
    ensure_claude_foundry_mcp "$container_id" "1"
    ensure_claude_statusline "$container_id" "1"
    dir_exists ~/.config/gh && copy_dir_to_container_quiet "$container_id" ~/.config/gh "$CONTAINER_HOME/.config/gh"
    dir_exists ~/.gemini && copy_dir_to_container_quiet "$container_id" ~/.gemini "$CONTAINER_HOME/.gemini" "antigravity"
    if file_exists ~/.config/opencode/opencode.json; then
        copy_file_to_container_quiet "$container_id" ~/.config/opencode/opencode.json "$CONTAINER_HOME/.config/opencode/opencode.json"
    elif file_exists "$SCRIPT_DIR/opencode.json"; then
        copy_file_to_container_quiet "$container_id" "$SCRIPT_DIR/opencode.json" "$CONTAINER_HOME/.config/opencode/opencode.json"
    fi
    file_exists ~/.local/share/opencode/auth.json && copy_file_to_container_quiet "$container_id" ~/.local/share/opencode/auth.json "$CONTAINER_HOME/.local/share/opencode/auth.json"
    sync_opencode_foundry "$container_id" "1"
    ensure_opencode_tavily_mcp "$container_id" "1"
    ensure_opencode_default_model "$container_id" "1"
    ensure_gemini_settings "$container_id" "1"
    ensure_codex_config "$container_id" "1"
    if file_exists ~/.foundry-mcp.toml; then
        docker exec -u "$CONTAINER_USER" "$container_id" mkdir -p "$CONTAINER_HOME/.config/foundry-mcp" 2>/dev/null || true
        copy_file_to_container_quiet "$container_id" ~/.foundry-mcp.toml "$CONTAINER_HOME/.config/foundry-mcp/config.toml"
        docker exec "$container_id" chown -R $CONTAINER_USER:$CONTAINER_USER "$CONTAINER_HOME/.config/foundry-mcp" 2>/dev/null || true
        configure_foundry_research_providers "$container_id"
    fi
    detect_nested_git_repos "$container_id"
}

# Configure foundry-mcp research providers based on available API keys.
# Dynamically adds tavily/perplexity to deep_research_providers if keys are set.
# If FOUNDRY_SEARCH_PROVIDERS is set, it overrides auto-detection entirely.
configure_foundry_research_providers() {
    local container_id="$1"
    local config_path="$CONTAINER_HOME/.config/foundry-mcp/config.toml"

    # Build provider list based on explicit override or available API keys
    docker exec "$container_id" bash -c '
        CONFIG_PATH="'"$config_path"'"
        [ ! -f "$CONFIG_PATH" ] && exit 0

        # Check for explicit provider override
        if [ -n "${FOUNDRY_SEARCH_PROVIDERS:-}" ]; then
            # Parse comma-separated list into TOML array format
            # e.g., "tavily,perplexity" -> "\"tavily\", \"perplexity\""
            PROVIDERS=$(echo "$FOUNDRY_SEARCH_PROVIDERS" | sed "s/,/\", \"/g" | sed "s/^/\"/;s/$/\"/")
        else
            # Auto-detect based on API keys
            # Priority: tavily first (if available), then perplexity, then semantic_scholar
            PROVIDERS=""
            [ -n "${TAVILY_API_KEY:-}" ] && PROVIDERS="\"tavily\""
            [ -n "${PERPLEXITY_API_KEY:-}" ] && {
                [ -n "$PROVIDERS" ] && PROVIDERS="$PROVIDERS, "
                PROVIDERS="${PROVIDERS}\"perplexity\""
            }
            # semantic_scholar always included (no key required)
            [ -n "$PROVIDERS" ] && PROVIDERS="$PROVIDERS, "
            PROVIDERS="${PROVIDERS}\"semantic_scholar\""
        fi

        # Update the TOML using python (reliable TOML handling)
        python3 << EOF
import re
with open("$CONFIG_PATH", "r") as f:
    content = f.read()
# Replace deep_research_providers line
pattern = r"deep_research_providers\s*=\s*\[[^\]]*\]"
replacement = f"deep_research_providers = [{PROVIDERS}]"
content = re.sub(pattern, replacement, content)
with open("$CONFIG_PATH", "w") as f:
    f.write(content)
EOF
    ' 2>/dev/null || true
}

copy_dir_to_container() {
    local container_id="$1"
    local src="$2"
    local dst="$3"
    shift 3
    local excludes=("$@")
    local attempts=0
    local tar_flags=""
    local tar_args=("${TAR_NO_XATTRS_ARGS[@]}")
    local exclude_args=()

    for pattern in "${excludes[@]}"; do
        exclude_args+=(--exclude="$pattern")
    done
    if [ ${#exclude_args[@]} -gt 0 ]; then
        tar_args+=("${exclude_args[@]}")
    fi

    if [ ${#tar_args[@]} -gt 0 ]; then
        tar_flags=" ${tar_args[*]}"
    fi

    while true; do
        run_cmd docker exec "$container_id" mkdir -p "$dst"
        if [ "$SANDBOX_VERBOSE" = "1" ]; then
            echo "+ COPYFILE_DISABLE=1 tar${tar_flags} -C \"$src\" -cf - . | docker exec -i \"$container_id\" tar --warning=no-unknown-keyword -C \"$dst\" -xf -"
        fi
        # COPYFILE_DISABLE=1 and --no-xattrs avoid macOS metadata and xattrs.
        if COPYFILE_DISABLE=1 tar "${tar_args[@]}" -C "$src" -cf - . | docker exec -i "$container_id" tar --warning=no-unknown-keyword -C "$dst" -xf -; then
            return 0
        fi
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 5 ]; then
            return 1
        fi
        sleep 0.2
    done
}

copy_file_to_container() {
    local container_id="$1"
    local src="$2"
    local dst="$3"
    local attempts=0
    local tar_flags=""
    local parent_dir
    parent_dir="$(dirname "$dst")"
    local src_dir
    src_dir="$(dirname "$src")"
    local src_base
    src_base="$(basename "$src")"
    local dst_base
    dst_base="$(basename "$dst")"

    if [ ${#TAR_NO_XATTRS_ARGS[@]} -gt 0 ]; then
        tar_flags=" ${TAR_NO_XATTRS_ARGS[*]}"
    fi

    while true; do
        run_cmd docker exec "$container_id" mkdir -p "$parent_dir"
        if [ "$src_base" = "$dst_base" ]; then
            if [ "$SANDBOX_VERBOSE" = "1" ]; then
                echo "+ COPYFILE_DISABLE=1 tar${tar_flags} -C \"$src_dir\" -cf - \"$src_base\" | docker exec -i \"$container_id\" tar --warning=no-unknown-keyword -C \"$parent_dir\" -xf -"
            fi
            # COPYFILE_DISABLE=1 and --no-xattrs avoid macOS metadata and xattrs.
            if COPYFILE_DISABLE=1 tar "${TAR_NO_XATTRS_ARGS[@]}" -C "$src_dir" -cf - "$src_base" | docker exec -i "$container_id" tar --warning=no-unknown-keyword -C "$parent_dir" -xf -; then
                return 0
            fi
        else
            if [ "$SANDBOX_VERBOSE" = "1" ]; then
                echo "+ COPYFILE_DISABLE=1 tar${tar_flags} -C \"$src_dir\" --transform=\"s|^$src_base\\$|$dst_base|\" -cf - \"$src_base\" | docker exec -i \"$container_id\" tar --warning=no-unknown-keyword -C \"$parent_dir\" -xf -"
            fi
            # COPYFILE_DISABLE=1 and --no-xattrs avoid macOS metadata and xattrs.
            if [ "$TAR_TRANSFORM_SUPPORTED" = "1" ]; then
                if COPYFILE_DISABLE=1 tar "${TAR_NO_XATTRS_ARGS[@]}" -C "$src_dir" --transform="s|^$src_base\$|$dst_base|" -cf - "$src_base" | docker exec -i "$container_id" tar --warning=no-unknown-keyword -C "$parent_dir" -xf -; then
                    return 0
                fi
            else
                if [ "$SANDBOX_VERBOSE" = "1" ]; then
                    echo "+ COPYFILE_DISABLE=1 tar${tar_flags} -C \"$src_dir\" -cf - \"$src_base\" | docker exec -i \"$container_id\" tar --warning=no-unknown-keyword -C \"$parent_dir\" -xf -"
                    echo "+ docker exec \"$container_id\" sh -c \"mv -f '$parent_dir/$src_base' '$dst'\""
                fi
                if COPYFILE_DISABLE=1 tar "${TAR_NO_XATTRS_ARGS[@]}" -C "$src_dir" -cf - "$src_base" | docker exec -i "$container_id" tar --warning=no-unknown-keyword -C "$parent_dir" -xf -; then
                    run_cmd docker exec "$container_id" sh -c "mv -f '$parent_dir/$src_base' '$dst'"
                    return 0
                fi
            fi
        fi
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 5 ]; then
            return 1
        fi
        sleep 0.2
    done
}

copy_dir_to_container_quiet() {
    copy_dir_to_container "$@" 2>/dev/null
}

copy_file_to_container_quiet() {
    copy_file_to_container "$@" 2>/dev/null
}

fix_worktree_paths() {
    local container_id="$1"
    local host_user="$2"

    if [ -z "$host_user" ]; then
        return 0
    fi

    docker exec "$container_id" sh -c "
        if [ -f /workspace/.git ]; then
            # Fix the worktree's .git reference
            if grep -q '/home/$host_user' /workspace/.git 2>/dev/null || \
               grep -q '/Users/$host_user' /workspace/.git 2>/dev/null; then
                sed -i \
                    -e 's|/home/$host_user|/home/ubuntu|g' \
                    -e 's|/Users/$host_user|/home/ubuntu|g' \
                    /workspace/.git

                # Fix the bare repo's gitdir reference and set core.worktree
                GITDIR_PATH=\$(grep 'gitdir:' /workspace/.git | sed 's/gitdir: //')
                if [ -d \"\$GITDIR_PATH\" ]; then
                    echo '/workspace/.git' > \"\$GITDIR_PATH/gitdir\"

                    # Set core.worktree to fix worktree detection
                    # Essential for --no-checkout sparse worktrees
                    touch \"\$GITDIR_PATH/config.worktree\" 2>/dev/null || true
                    git config --file \"\$GITDIR_PATH/config.worktree\" core.worktree /workspace
                fi
            fi
        fi
    "
}

detect_nested_git_repos() {
    local container_id="$1"

    docker exec "$container_id" sh -c '
        nested_gits=$(find /workspace -mindepth 2 -name ".git" -type d 2>/dev/null)
        if [ -n "$nested_gits" ]; then
            echo ""
            echo "⚠️  WARNING: Nested .git directories detected:"
            echo "$nested_gits" | while read -r git_dir; do
                parent_dir=$(dirname "$git_dir")
                branch=$(git -C "$parent_dir" branch --show-current 2>/dev/null || echo "unknown")
                echo "  - $git_dir (branch: $branch)"
            done
            echo ""
            echo "These shadow the sparse worktree and will cause git commands to use"
            echo "the wrong repository. Consider removing them with:"
            echo "  rm -rf <path>"
            echo ""
        fi
    '
}
