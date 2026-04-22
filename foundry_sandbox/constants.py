"""Configuration defaults for foundry-sandbox.

This module replaces lib/constants.sh and provides Python equivalents
for all sandbox configuration constants.
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path


def _env_int(key: str, default: int) -> int:
    """Read an integer from an environment variable, returning default on parse failure."""
    try:
        return int(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


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

    .. deprecated::
        Removed in next release. sbx now manages worktrees internally.

    Returns:
        Path to worktrees directory ($SANDBOX_HOME/worktrees)
    """
    warnings.warn(
        "get_worktrees_dir() is deprecated and will be removed in the next release; "
        "sbx now manages worktrees internally.",
        DeprecationWarning,
        stacklevel=2,
    )
    return get_sandbox_home() / "worktrees"


def get_claude_configs_dir() -> Path:
    """Get the Claude configuration directory.

    Returns:
        Path to claude-config directory ($SANDBOX_HOME/claude-config)
    """
    return get_sandbox_home() / "claude-config"


# ============================================================================
# Retry / Timeout Constants
# ============================================================================

CONTAINER_READY_ATTEMPTS: int = 5
"""Number of attempts when waiting for container readiness."""

CONTAINER_READY_DELAY: float = 0.2
"""Seconds between container readiness retries."""

SANDBOX_NAME_MAX_LENGTH: int = 120
"""Maximum length for auto-generated sandbox names before truncation+hash."""

# ============================================================================
# Subprocess Timeout Constants (seconds)
# ============================================================================

TIMEOUT_GIT_TRANSFER: int = 120
"""Timeout for git clone/fetch/worktree add (network-bound)."""

TIMEOUT_GIT_QUERY: int = 10
"""Timeout for git config/rev-parse/for-each-ref (local)."""

TIMEOUT_LOCAL_CMD: int = 5
"""Timeout for quick local commands (id, etc.)."""

TIMEOUT_PIP_INSTALL: int = 300
"""Timeout for pip install (can be very slow)."""


# ============================================================================
# Runtime Flag Defaults (read from environment)
# ============================================================================


def get_sandbox_debug() -> int:
    """Get SANDBOX_DEBUG flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return _env_int("SANDBOX_DEBUG", 0)


def get_sandbox_verbose() -> int:
    """Get SANDBOX_VERBOSE flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return _env_int("SANDBOX_VERBOSE", 0)


def get_sandbox_assume_yes() -> int:
    """Get SANDBOX_ASSUME_YES flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return _env_int("SANDBOX_ASSUME_YES", 0)


VALID_NETWORK_MODES = frozenset({"limited", "host-only", "none"})
"""Allowed values for SANDBOX_NETWORK_MODE."""


def get_sandbox_network_mode() -> str:
    """Get network mode from environment.

    Valid values: limited, host-only, none

    Returns:
        Network mode (default: "limited")

    Raises:
        ValueError: If the environment variable contains an invalid value.
    """
    mode = os.environ.get("SANDBOX_NETWORK_MODE", "limited")
    if mode not in VALID_NETWORK_MODES:
        raise ValueError(
            f"Invalid SANDBOX_NETWORK_MODE={mode!r}; "
            f"must be one of: {', '.join(sorted(VALID_NETWORK_MODES))}"
        )
    return mode


def get_sandbox_sync_on_attach() -> int:
    """Get credential sync on attach flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return _env_int("SANDBOX_SYNC_ON_ATTACH", 0)


def get_sandbox_sync_ssh() -> int:
    """Get SSH credential sync flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return _env_int("SANDBOX_SYNC_SSH", 0)


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
    return _env_int("SANDBOX_OPENCODE_DISABLE_NPM_PLUGINS", 1)


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
    return _env_int("SANDBOX_OPENCODE_PREFETCH_NPM_PLUGINS", 1)


def get_sandbox_opencode_default_model() -> str:
    """Get OpenCode default model from environment.

    Returns:
        Default model (default: "openai/gpt-5.3-codex")
    """
    return os.environ.get("SANDBOX_OPENCODE_DEFAULT_MODEL", "openai/gpt-5.3-codex")


def get_sandbox_tmux_scrollback() -> int:
    """Get tmux scrollback buffer size from environment.

    Returns:
        Number of lines (default: 200000)
    """
    return _env_int("SANDBOX_TMUX_SCROLLBACK", 200000)


def get_sandbox_tmux_mouse() -> int:
    """Get tmux mouse support flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return _env_int("SANDBOX_TMUX_MOUSE", 0)
