"""Foundry MCP plugin lifecycle management.

Migrated from lib/container_config.sh: prepopulate_foundry_global, ensure_claude_foundry_mcp,
ensure_foundry_mcp_config, ensure_foundry_mcp_workspace_dirs, sync_marketplace_manifests,
configure_foundry_research_providers.

Absorbs lib/python/ensure_claude_foundry_mcp.py.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from foundry_sandbox.config import load_json, write_json
from foundry_sandbox.constants import CONTAINER_HOME, CONTAINER_USER, TIMEOUT_DOCKER_EXEC, TIMEOUT_GIT_TRANSFER, TIMEOUT_LOCAL_CMD, get_sandbox_verbose
from foundry_sandbox.permissions import FOUNDRY_ALLOW, FOUNDRY_DENY
from foundry_sandbox.utils import log_debug, log_info, log_step, log_warn

DEFAULT_HOOKS = {
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


# ============================================================================
# Host-Side Functions
# ============================================================================

def prepopulate_foundry_global(claude_home_path: str, *, skip_if_populated: bool = False) -> bool:
    """Prepopulate Foundry plugin files into the host Claude home directory.

    Runs on HOST, not in container. Clones/updates the foundry plugin repo from GitHub
    to a global cache, then copies skills and hooks to the Claude home directory.
    Updates settings.json with model defaults and hooks configuration.

    Args:
        claude_home_path: Path to Claude home directory (e.g., ~/.claude)
        skip_if_populated: If True, skip if skills already exist

    Returns:
        True on success, False on failure (best-effort)
    """
    skills_dir = Path(claude_home_path) / "skills"
    hooks_dir = Path(claude_home_path) / "hooks"

    # Check if already populated
    if skip_if_populated and (skills_dir / "foundry-spec").exists():
        log_debug("Foundry skills already installed, skipping")
        return True

    # Ensure directories exist
    skills_dir.mkdir(parents=True, exist_ok=True)
    hooks_dir.mkdir(parents=True, exist_ok=True)

    # Get cache directory from environment
    cache_home = os.environ.get("CLAUDE_PLUGINS_CACHE", str(Path.home() / ".cache" / "claude-plugins"))
    cache_path = Path(cache_home)
    cache_path.mkdir(parents=True, exist_ok=True)

    # Clone or update the foundry plugin repo to global cache
    foundry_cache = cache_path / "claude-foundry"
    if (foundry_cache / ".git").exists():
        log_debug("Updating cached foundry repo...")
        result = subprocess.run(
            ["git", "-C", str(foundry_cache), "pull", "--ff-only", "-q"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_GIT_TRANSFER,
        )
        if result.returncode != 0:
            log_warn("Failed to update foundry cache, using existing version")
    else:
        log_debug("Cloning foundry repo to cache...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "-q",
             "https://github.com/foundry-works/claude-foundry.git",
             str(foundry_cache)],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_GIT_TRANSFER,
        )
        if result.returncode != 0:
            log_warn("Failed to clone foundry repo - network may be unavailable")
            return False

    # Get plugin version from plugin.json (for logging)
    plugin_json = foundry_cache / ".claude-plugin" / "plugin.json"
    version = "unknown"
    if plugin_json.exists():
        try:
            with open(plugin_json) as f:
                version = json.load(f).get("version", "unknown")
        except (json.JSONDecodeError, OSError):
            pass

    # Copy skills to ~/.claude/skills/
    foundry_skills = foundry_cache / "skills"
    if foundry_skills.exists():
        # Try rsync first, fall back to cp
        result = subprocess.run(
            ["rsync", "-a", "--delete", f"{foundry_skills}/", f"{skills_dir}/"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_LOCAL_CMD,
        )
        if result.returncode != 0:
            # Fall back to cp
            subprocess.run(
                ["cp", "-r"] + [str(f) for f in foundry_skills.glob("*")] + [str(skills_dir)],
                capture_output=True,
                text=True,
                check=False,
                timeout=TIMEOUT_LOCAL_CMD,
            )
        log_debug(f"Copied skills to {skills_dir}")
    else:
        log_warn("No skills directory found in foundry repo")

    # Copy hooks executables to ~/.claude/hooks/
    # Skip hooks.json - that's a plugin-specific config format
    foundry_hooks = foundry_cache / "hooks"
    if foundry_hooks.exists():
        for hook_file in foundry_hooks.iterdir():
            if hook_file.is_file() and hook_file.name != "hooks.json":
                dest = hooks_dir / hook_file.name
                subprocess.run(["cp", str(hook_file), str(dest)], check=False, timeout=TIMEOUT_LOCAL_CMD)
                dest.chmod(0o755)
        log_debug(f"Copied hooks to {hooks_dir}")
    else:
        log_warn("No hooks directory found in foundry repo")

    # Update settings.json with hooks configuration and sandbox defaults
    settings_file = Path(claude_home_path) / "settings.json"
    data = load_json(str(settings_file))

    # Ensure sandbox defaults are set
    if "model" not in data:
        data["model"] = "opus"
    if "subagentModel" not in data:
        data["subagentModel"] = "haiku"
    data["alwaysThinkingEnabled"] = True

    # Configure hooks with absolute paths (container paths)
    data["hooks"] = DEFAULT_HOOKS

    write_json(str(settings_file), data)

    log_step(f"Foundry v{version} installed")
    return True


# ============================================================================
# Container-Side Functions (run via docker exec)
# ============================================================================

def ensure_claude_foundry_mcp(container_id: str, *, quiet: bool = False) -> None:
    """Configure Claude settings with Foundry MCP permissions and hooks inside container.

    Runs inside container via docker exec with inline Python. Sets model defaults,
    hooks configuration, and Foundry permission allowlists. Also pre-bakes pyright-lsp
    plugin cache when not quiet.

    Args:
        container_id: Container ID or name
        quiet: If True, suppress output and skip pyright-lsp pre-bake
    """
    # Python script that runs inside the container.
    # Inject module-level constants via json.dumps() to avoid duplication.
    allow_json = json.dumps(FOUNDRY_ALLOW)
    deny_json = json.dumps(FOUNDRY_DENY)
    hooks_json = json.dumps(DEFAULT_HOOKS)

    python_script = f'''
import json
import os

path = "/home/ubuntu/.claude/settings.json"

def load_json(p) -> dict:
    try:
        with open(p) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {{}}

data = load_json(path)

# Force model settings (opus for main, haiku for subagents)
data["model"] = "opus"
data["subagentModel"] = "haiku"
data["alwaysThinkingEnabled"] = True

# Configure hooks with absolute paths (injected from module constants)
data["hooks"] = {hooks_json}

# Foundry permissions (injected from module constants)
FOUNDRY_ALLOW = {allow_json}
FOUNDRY_DENY = {deny_json}

# Merge permissions (preserving existing, adding foundry)
if "permissions" not in data:
    data["permissions"] = {{}}
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
    f.write("\\n")
'''

    # Execute in container
    result = subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, "-i", container_id, "python3", "-c", python_script],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    if result.returncode != 0 and not quiet:
        log_warn(f"Failed to configure foundry settings: {result.stderr}")

    # Pre-bake pyright-lsp plugin cache (git clone is blocked by sandbox policy)
    if not quiet:
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


def ensure_foundry_mcp_config(container_id: str, *, quiet: bool = False) -> None:
    """Register foundry-mcp server in Claude config files inside container.

    Updates both ~/.claude.json and ~/.claude/.claude.json with foundry-mcp
    server configuration. Also adds tavily-mcp if enabled and sets marketplace
    state flags.

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

    # Add MCP server configuration
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

    # Ensure foundry-mcp uses -s (skip user site-packages)
    if "foundry-mcp" not in data["mcpServers"]:
        data["mcpServers"]["foundry-mcp"] = {
            "command": "python",
            "args": ["-s", "-m", "foundry_mcp.server"]
        }
        changed = True
    else:
        fmcp = data["mcpServers"]["foundry-mcp"]
        args = fmcp.get("args", [])
        cmd = fmcp.get("command", "")
        is_python = cmd in ("python", "python3") or (
            isinstance(args, list) and args and args[0] == "-m"
        )
        if is_python and isinstance(args, list) and "-s" not in args:
            args.insert(0, "-s")
            fmcp["args"] = args
            changed = True

    # Only add tavily-mcp if Tavily is enabled
    enable_tavily = os.environ.get("SANDBOX_ENABLE_TAVILY", "0") == "1"
    if enable_tavily:
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
            f.write("\\n")
'''

    # Get SANDBOX_ENABLE_TAVILY from environment
    env_vars = []
    if os.environ.get("SANDBOX_ENABLE_TAVILY"):
        env_vars.extend(["-e", f"SANDBOX_ENABLE_TAVILY={os.environ['SANDBOX_ENABLE_TAVILY']}"])

    result = subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, "-i"] + env_vars +
        [container_id, "python3", "-c", python_script],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    if result.returncode != 0 and not quiet:
        log_warn(f"Failed to configure foundry-mcp: {result.stderr}")


def ensure_foundry_mcp_workspace_dirs(container_id: str, working_dir: str = "", *, quiet: bool = False) -> None:
    """Create foundry-mcp workspace directory structure inside container.

    Creates specs directories (active, pending, completed, archived, .notes, etc.)
    and home foundry-mcp directories. Fixes ownership to container user.

    Args:
        container_id: Container ID or name
        working_dir: Optional subdirectory under /workspace for specs
        quiet: If True, suppress debug output
    """
    if not quiet:
        log_debug("Creating foundry-mcp workspace directories...")

    # Calculate specs base path
    specs_base = f"/workspace/{working_dir}" if working_dir else "/workspace"

    # Create workspace specs directories
    specs_dirs = [
        f"{specs_base}/specs/active",
        f"{specs_base}/specs/pending",
        f"{specs_base}/specs/completed",
        f"{specs_base}/specs/archived",
        f"{specs_base}/specs/.notes",
        f"{specs_base}/specs/.plans",
        f"{specs_base}/specs/.plan-reviews",
        f"{specs_base}/specs/.fidelity-reviews",
        f"{specs_base}/specs/.research/conversations",
        f"{specs_base}/specs/.research/investigations",
        f"{specs_base}/specs/.research/ideations",
        f"{specs_base}/specs/.research/deep-research",
    ]

    subprocess.run(
        ["docker", "exec", container_id, "mkdir", "-p"] + specs_dirs,
        capture_output=quiet,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    # Create home foundry-mcp directories
    home_dirs = [
        f"{CONTAINER_HOME}/.foundry-mcp/cache",
        f"{CONTAINER_HOME}/.foundry-mcp/errors",
        f"{CONTAINER_HOME}/.foundry-mcp/metrics",
    ]

    subprocess.run(
        ["docker", "exec", container_id, "mkdir", "-p"] + home_dirs,
        capture_output=quiet,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    # Fix ownership — use shlex.quote to prevent injection via specs_base
    subprocess.run(
        ["docker", "exec", container_id, "sh", "-c",
         f"chown -R {shlex.quote(CONTAINER_USER)}:{shlex.quote(CONTAINER_USER)} {shlex.quote(specs_base + '/specs')} 2>/dev/null || true"],
        capture_output=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )
    subprocess.run(
        ["docker", "exec", container_id, "sh", "-c",
         f"chown -R {shlex.quote(CONTAINER_USER)}:{shlex.quote(CONTAINER_USER)} {shlex.quote(CONTAINER_HOME + '/.foundry-mcp')} 2>/dev/null || true"],
        capture_output=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )


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


def configure_foundry_research_providers(container_id: str, *, quiet: bool = False) -> None:
    """Configure foundry-mcp research providers based on available API keys.

    Updates deep_research_providers in foundry-mcp config.toml based on
    available API keys (TAVILY_API_KEY, PERPLEXITY_API_KEY) or explicit
    FOUNDRY_SEARCH_PROVIDERS override.

    Args:
        container_id: Container ID or name
    """
    # Use a Python script inside the container to update the TOML config.
    # This avoids heredoc variable expansion issues and shell injection risks.
    container_home_escaped = json.dumps(CONTAINER_HOME)
    python_script = f'''
import re, os, sys

config_path = os.path.join({container_home_escaped}, ".config/foundry-mcp/config.toml")
if not os.path.isfile(config_path):
    sys.exit(0)

# Determine providers
explicit = os.environ.get("FOUNDRY_SEARCH_PROVIDERS", "")
if explicit:
    providers = [p.strip() for p in explicit.split(",") if p.strip()]
else:
    providers = []
    if os.environ.get("TAVILY_API_KEY"):
        providers.append("tavily")
    if os.environ.get("PERPLEXITY_API_KEY"):
        providers.append("perplexity")
    # semantic_scholar always included (no key required)
    providers.append("semantic_scholar")

# Format as TOML array
toml_array = ", ".join(f'"{{p}}"' for p in providers)

with open(config_path, "r") as f:
    content = f.read()

pattern = r"deep_research_providers\\s*=\\s*\\[[^\\]]*\\]"
replacement = f"deep_research_providers = [{{toml_array}}]"
content = re.sub(pattern, replacement, content)

with open(config_path, "w") as f:
    f.write(content)
'''

    subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, container_id,
         "python3", "-c", python_script],
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )
