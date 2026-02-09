"""Configuration defaults for foundry-sandbox.

This module replaces lib/constants.sh and provides Python equivalents
for all sandbox configuration constants.
"""

from __future__ import annotations

import os
from pathlib import Path


# ============================================================================
# Directory & Path Constants
# ============================================================================


def get_sandbox_home() -> Path:
    """Get the base directory for sandboxes.

    Respects SANDBOX_HOME environment variable override.
    Defaults to ~/.sandboxes if not set.

    Returns:
        Path to sandbox home directory
    """
    home_str = os.environ.get("SANDBOX_HOME")
    if home_str:
        return Path(home_str)
    return Path.home() / ".sandboxes"


def get_repos_dir() -> Path:
    """Get the repository bare clones directory.

    Returns:
        Path to repos directory ($SANDBOX_HOME/repos)
    """
    return get_sandbox_home() / "repos"


def get_worktrees_dir() -> Path:
    """Get the Git worktrees directory.

    Returns:
        Path to worktrees directory ($SANDBOX_HOME/worktrees)
    """
    return get_sandbox_home() / "worktrees"


def get_claude_configs_dir() -> Path:
    """Get the Claude configuration directory.

    Returns:
        Path to claude-config directory ($SANDBOX_HOME/claude-config)
    """
    return get_sandbox_home() / "claude-config"


# ============================================================================
# Container Constants
# ============================================================================

DOCKER_IMAGE: str = "foundry-sandbox:latest"
"""Docker image name and tag for sandbox containers."""

CONTAINER_USER: str = "ubuntu"
"""Default container user (can be overridden via SANDBOX_USERNAME at build time)."""

CONTAINER_HOME: str = "/home/ubuntu"
"""Container home directory (tmpfs mount with user's home symlinked there)."""

SSH_AGENT_CONTAINER_SOCK: str = "/ssh-agent"
"""Path to SSH agent socket inside container."""

CONTAINER_OPENCODE_PLUGIN_DIR: str = "/home/ubuntu/.config/opencode/plugins"
"""Default OpenCode plugins directory inside container."""


# ============================================================================
# Runtime Flag Defaults (read from environment)
# ============================================================================


def get_sandbox_debug() -> int:
    """Get SANDBOX_DEBUG flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return int(os.environ.get("SANDBOX_DEBUG", "0"))


def get_sandbox_verbose() -> int:
    """Get SANDBOX_VERBOSE flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return int(os.environ.get("SANDBOX_VERBOSE", "0"))


def get_sandbox_assume_yes() -> int:
    """Get SANDBOX_ASSUME_YES flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return int(os.environ.get("SANDBOX_ASSUME_YES", "0"))


def get_sandbox_network_mode() -> str:
    """Get network mode from environment.

    Valid values: limited, host-only, none

    Returns:
        Network mode (default: "limited")
    """
    return os.environ.get("SANDBOX_NETWORK_MODE", "limited")


def get_sandbox_sync_on_attach() -> int:
    """Get credential sync on attach flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return int(os.environ.get("SANDBOX_SYNC_ON_ATTACH", "0"))


def get_sandbox_sync_ssh() -> int:
    """Get SSH credential sync flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return int(os.environ.get("SANDBOX_SYNC_SSH", "0"))


def get_sandbox_ssh_mode() -> str:
    """Get SSH mode from environment.

    Returns:
        SSH mode (default: "always")
    """
    return os.environ.get("SANDBOX_SSH_MODE", "always")


def get_sandbox_opencode_disable_npm_plugins() -> int:
    """Get OpenCode npm plugins disable flag from environment.

    Returns:
        1 if disabled (default), 0 if enabled
    """
    return int(os.environ.get("SANDBOX_OPENCODE_DISABLE_NPM_PLUGINS", "1"))


def get_sandbox_opencode_plugin_dir() -> str:
    """Get OpenCode plugin directory from environment.

    Returns:
        Plugin directory path (default: empty string)
    """
    return os.environ.get("SANDBOX_OPENCODE_PLUGIN_DIR", "")


def get_sandbox_opencode_prefetch_npm_plugins() -> int:
    """Get OpenCode npm plugins prefetch flag from environment.

    Returns:
        1 if enabled (default), 0 if disabled
    """
    return int(os.environ.get("SANDBOX_OPENCODE_PREFETCH_NPM_PLUGINS", "1"))


def get_sandbox_opencode_default_model() -> str:
    """Get OpenCode default model from environment.

    Returns:
        Default model (default: "openai/gpt-5.2-codex")
    """
    return os.environ.get("SANDBOX_OPENCODE_DEFAULT_MODEL", "openai/gpt-5.2-codex")


def get_sandbox_tmux_scrollback() -> int:
    """Get tmux scrollback buffer size from environment.

    Returns:
        Number of lines (default: 200000)
    """
    return int(os.environ.get("SANDBOX_TMUX_SCROLLBACK", "200000"))


def get_sandbox_tmux_mouse() -> int:
    """Get tmux mouse support flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return int(os.environ.get("SANDBOX_TMUX_MOUSE", "0"))
