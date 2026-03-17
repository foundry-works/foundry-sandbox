"""Marketplace and plugin management for sandbox containers.

Retained functions:
  - sync_marketplace_manifests: registers official marketplace and synthesizes manifests
  - ensure_pyright_lsp: pre-bakes pyright-lsp plugin cache
  - ensure_claude_settings_defaults: sets model defaults in container settings
"""
from __future__ import annotations

import json
import subprocess

from foundry_sandbox.constants import CONTAINER_HOME, CONTAINER_USER, TIMEOUT_DOCKER_EXEC
from foundry_sandbox.utils import log_debug, log_step, log_warn


def ensure_claude_settings_defaults(container_id: str, *, quiet: bool = False) -> None:
    """Set model defaults and clean up stale plugin references in container settings.

    Args:
        container_id: Container ID or name
        quiet: If True, suppress output
    """
    python_script = '''
import json
import os

path = "/home/ubuntu/.claude/settings.json"

def load_json(p) -> dict:
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

# Remove stale plugin references
if "enabledPlugins" in data:
    data["enabledPlugins"].pop("foundry@claude-foundry", None)
    if not data["enabledPlugins"]:
        del data["enabledPlugins"]

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\\n")
'''

    result = subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, "-i", container_id, "python3", "-c", python_script],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    if result.returncode != 0 and not quiet:
        log_warn(f"Failed to configure settings defaults: {result.stderr}")


def ensure_pyright_lsp(container_id: str, *, quiet: bool = False) -> None:
    """Pre-bake pyright-lsp plugin cache (git clone is blocked by sandbox policy).

    Args:
        container_id: Container ID or name
        quiet: If True, suppress output
    """
    if quiet:
        return

    pyright_version = "1.0.0"
    pyright_script = f'''
import json, os

home = os.environ.get("CONTAINER_HOME", os.path.expanduser("~"))
plugin_version = "{pyright_version}"
cache_dir = f"{{home}}/.claude/plugins/cache/claude-plugins-official/pyright-lsp/{{plugin_version}}/.claude-plugin"
plugins_file = f"{{home}}/.claude/plugins/installed_plugins.json"

# Create plugin.json in cache
os.makedirs(cache_dir, exist_ok=True)
plugin_json = {{
    "name": "pyright-lsp",
    "description": "Python language server (Pyright) for type checking and code intelligence",
    "version": plugin_version,
    "author": {{"name": "Anthropic", "email": "support@anthropic.com"}},
    "lspServers": {{
        "pyright": {{
            "command": "pyright-langserver",
            "args": ["--stdio"],
            "extensionToLanguage": {{".py": "python", ".pyi": "python"}}
        }}
    }}
}}
with open(os.path.join(cache_dir, "plugin.json"), "w") as f:
    json.dump(plugin_json, f, indent=2)
    f.write("\\n")

# Update installed_plugins.json
try:
    with open(plugins_file) as f:
        installed = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    installed = {{"version": 2, "plugins": {{}}}}

installed.setdefault("version", 2)
installed.setdefault("plugins", {{}})
installed["plugins"]["pyright-lsp@claude-plugins-official"] = [{{
    "scope": "user",
    "installPath": f"{{home}}/.claude/plugins/cache/claude-plugins-official/pyright-lsp/{{plugin_version}}",
    "version": plugin_version,
    "isLocal": True
}}]

os.makedirs(os.path.dirname(plugins_file), exist_ok=True)
with open(plugins_file, "w") as f:
    json.dump(installed, f, indent=2)
    f.write("\\n")

# Ensure enabledPlugins in settings.json
settings_file = f"{{home}}/.claude/settings.json"
try:
    with open(settings_file) as f:
        settings = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    settings = {{}}

settings.setdefault("enabledPlugins", {{}})
settings["enabledPlugins"]["pyright-lsp@claude-plugins-official"] = True

with open(settings_file, "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\\n")
'''

    result = subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, "-i",
         "-e", f"PYRIGHT_PLUGIN_VERSION={pyright_version}",
         "-e", f"CONTAINER_HOME={CONTAINER_HOME}",
         container_id, "python3", "-c", pyright_script],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    if result.returncode == 0:
        log_step(f"Pyright LSP: cached (v{pyright_version})")
    else:
        log_debug("pyright-lsp pre-bake failed (optional)")


def ensure_marketplace_config(container_id: str, *, quiet: bool = False) -> None:
    """Set marketplace state flags in Claude config files.

    Marks the official marketplace as already installed so Claude doesn't
    try to auto-install it (which would fail in sandboxes).

    Args:
        container_id: Container ID or name
        quiet: If True, suppress error output
    """
    python_script = '''
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

    if "mcpServers" not in data:
        data["mcpServers"] = {}

    # Mark official marketplace as already installed
    changed = False
    marketplace_state = {
        "officialMarketplaceAutoInstalled": True,
        "officialMarketplaceAutoInstallAttempted": True,
    }
    # Remove stale failure/retry keys
    for key in ("officialMarketplaceAutoInstallFailReason",
                "officialMarketplaceAutoInstallRetryCount",
                "officialMarketplaceAutoInstallLastAttemptTime",
                "officialMarketplaceAutoInstallNextRetryTime"):
        if key in data:
            del data[key]
            changed = True
    for key, val in marketplace_state.items():
        if data.get(key) != val:
            data[key] = val
            changed = True

    if changed:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\\n")
        except PermissionError:
            import sys
            print(f"Warning: cannot write {path} (PermissionError), skipping", file=sys.stderr)
            continue
'''

    result = subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, "-i",
         container_id, "python3", "-c", python_script],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    if result.returncode != 0 and not quiet:
        log_warn(f"Failed to configure marketplace: {result.stderr}")


def sync_marketplace_manifests(container_id: str, plugins_dir: str, *, quiet: bool = False) -> None:
    """Register marketplace and synthesize missing plugin manifests inside container.

    Registers the official marketplace in known_marketplaces.json, then synthesizes
    missing per-plugin manifests from marketplace.json. Commits synthesized manifests
    so they're visible via git tree reads.

    Args:
        container_id: Container ID or name
        plugins_dir: Path to plugins directory in container
        quiet: If True, suppress stderr from docker exec
    """
    plugins_dir_escaped = json.dumps(plugins_dir)
    python_script = f'''
import json, os, sys

plugins_dir = {plugins_dir_escaped}
mkt_name = "claude-plugins-official"
mkt_install = os.path.join(plugins_dir, "marketplaces", mkt_name)

# 1. Register in known_marketplaces.json
known_path = os.path.join(plugins_dir, "known_marketplaces.json")
try:
    with open(known_path) as f:
        known = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    known = {{}}
known[mkt_name] = {{
    "source": {{"source": "github", "repo": "anthropics/claude-plugins-official"}},
    "installLocation": mkt_install,
    "lastUpdated": "2026-01-01T00:00:00.000Z",
}}
os.makedirs(os.path.dirname(known_path), exist_ok=True)
with open(known_path, "w") as f:
    json.dump(known, f, indent=2)
    f.write("\\n")

# 2. Synthesise missing per-plugin manifests from marketplace.json
mkt_json = os.path.join(mkt_install, ".claude-plugin", "marketplace.json")
if os.path.isfile(mkt_json):
    with open(mkt_json) as f:
        mkt = json.load(f)
    # Keys that are marketplace-level metadata, not valid in plugin.json
    strip_keys = {{"source", "category", "strict", "homepage", "tags"}}
    for plugin in mkt.get("plugins", []):
        source = plugin.get("source")
        if not isinstance(source, str) or not source.startswith("./"):
            continue
        manifest_dir = os.path.join(mkt_install, source.removeprefix("./"), ".claude-plugin")
        manifest_path = os.path.join(manifest_dir, "plugin.json")
        if os.path.isfile(manifest_path):
            continue
        cleaned = {{k: v for k, v in plugin.items() if k not in strip_keys}}
        os.makedirs(manifest_dir, exist_ok=True)
        with open(manifest_path, "w") as f:
            json.dump(cleaned, f, indent=2)
            f.write("\\n")
'''

    stderr_mode = subprocess.DEVNULL if quiet else None

    # Execute Python script
    subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, "-i", container_id, "python3", "-c", python_script],
        stderr=stderr_mode,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    # Commit synthesised manifests
    subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, container_id, "sh", "-c",
         f"cd '{CONTAINER_HOME}/.claude/plugins/marketplaces/claude-plugins-official' && "
         f"git add -A && "
         f"git -c user.email='sandbox@local' -c user.name='sandbox' "
         f"commit -m 'Add missing plugin manifests' --allow-empty"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )


def ensure_claude_foundry_mcp(container_id: str, *, quiet: bool = False) -> None:
    """Configure Claude settings defaults and pyright LSP.

    Backward-compatible wrapper that replaces the old foundry-specific setup
    with generic settings defaults + pyright.
    """
    ensure_claude_settings_defaults(container_id, quiet=quiet)
    ensure_pyright_lsp(container_id, quiet=quiet)


def ensure_foundry_mcp_config(container_id: str, *, quiet: bool = False) -> None:
    """Set marketplace state flags in Claude config (no MCP server registration).

    Backward-compatible wrapper.
    """
    ensure_marketplace_config(container_id, quiet=quiet)


