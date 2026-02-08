"""Sync OpenCode configuration with Foundry MCP settings.

Extracted from lib/container_config.sh sync_opencode_foundry() function.
Handles deep merging of opencode-foundry config template into existing
OpenCode configuration, with plugin path mapping and npm plugin filtering.

Usage:
    python3 sync_opencode_foundry.py <template_path> <config_path>

Environment Variables:
    SANDBOX_OPENCODE_DISABLE_NPM_PLUGINS: Set to "1" to filter out npm plugins
    SANDBOX_OPENCODE_LOCAL_PLUGIN_DIR: Local directory for plugin path mapping
"""

import os
import shutil
import sys
from typing import Any, Dict, List, Optional, Union

# Import shared utilities
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from json_config import load_json, write_json, deep_merge_no_overwrite


PluginSpec = Union[str, Dict[str, Any]]


def is_local_plugin(plugin: PluginSpec) -> bool:
    """Check if a plugin spec refers to a local path."""
    if isinstance(plugin, str):
        return plugin.startswith(("/", "./", "../", "~/"))
    if isinstance(plugin, dict):
        path = plugin.get("path") or plugin.get("file") or plugin.get("src")
        if isinstance(path, str):
            return path.startswith(("/", "./", "../", "~/"))
    return False


def plugin_spec(plugin: PluginSpec) -> Optional[str]:
    """Extract the spec string from a plugin entry."""
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


def plugin_name(spec: Optional[str]) -> str:
    """Extract the package name from a spec string (strip version)."""
    if not isinstance(spec, str) or not spec:
        return ""
    if spec.startswith("@"):
        # Scoped package: @scope/name@version
        if "@" in spec[1:]:
            return spec.rsplit("@", 1)[0]
        return spec
    if "@" in spec:
        return spec.split("@", 1)[0]
    return spec


def map_plugin_to_local(plugin: PluginSpec, local_plugin_dir: str) -> PluginSpec:
    """Map a plugin to its local path if available."""
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


def find_executable(name: str, extra_paths: tuple = ()) -> Optional[str]:
    """Find an executable by name, checking PATH and extra locations."""
    path = shutil.which(name)
    if path:
        return path
    for candidate in extra_paths:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def command_looks_like_foundry(cmd: List[str]) -> bool:
    """Check if a command list looks like a foundry-mcp invocation."""
    if not cmd:
        return True
    head = cmd[0]
    if head in ("uvx", "foundry-mcp"):
        return True
    if head in ("python", "python3") and len(cmd) >= 3 and cmd[1] == "-m":
        module = cmd[2]
        return module in ("foundry-mcp", "foundry_mcp", "foundry_mcp.server")
    return False


def pick_foundry_command(cmd: List[str]) -> Optional[List[str]]:
    """Select the best available command to run foundry-mcp."""
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


def sync_opencode_foundry(template_path: str, config_path: str) -> None:
    """Sync OpenCode config with Foundry template.

    Args:
        template_path: Path to opencode-foundry.json template.
        config_path: Path to opencode.json config file.
    """
    template = load_json(template_path)
    existing = load_json(config_path)
    merged = deep_merge_no_overwrite(existing, template)

    # Map plugins to local paths if configured
    local_plugin_dir = os.environ.get("SANDBOX_OPENCODE_LOCAL_PLUGIN_DIR") or ""
    if local_plugin_dir:
        plugins = merged.get("plugin")
        if isinstance(plugins, list):
            merged["plugin"] = [map_plugin_to_local(p, local_plugin_dir) for p in plugins]

    # Filter npm plugins if disabled
    disable_npm_plugins = os.environ.get("SANDBOX_OPENCODE_DISABLE_NPM_PLUGINS", "0") == "1"
    if disable_npm_plugins:
        plugins = merged.get("plugin")
        if isinstance(plugins, list):
            local_plugins = [p for p in plugins if is_local_plugin(p)]
            if local_plugins:
                merged["plugin"] = local_plugins
            else:
                merged.pop("plugin", None)
        else:
            merged.pop("plugin", None)

    # Update foundry-mcp command if needed
    command = merged.get("mcp", {}).get("foundry-mcp", {}).get("command", [])
    command_list = command if isinstance(command, list) else []

    if command_looks_like_foundry(command_list):
        new_command = pick_foundry_command(command_list)
        if new_command:
            merged.setdefault("mcp", {}).setdefault("foundry-mcp", {})["command"] = new_command

    write_json(config_path, merged)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: sync_opencode_foundry.py <template_path> <config_path>",
              file=sys.stderr)
        sys.exit(1)

    sync_opencode_foundry(sys.argv[1], sys.argv[2])
