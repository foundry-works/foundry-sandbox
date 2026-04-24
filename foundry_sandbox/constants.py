"""Configuration defaults for foundry-sandbox."""

from __future__ import annotations

import os
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


def get_sandbox_configs_dir() -> Path:
    """Get the sandbox configuration directory.

    Returns:
        Path to sandboxes directory ($SANDBOX_HOME/sandboxes)
    """
    return get_sandbox_home() / "sandboxes"


# ============================================================================
# Name Length
# ============================================================================

SANDBOX_NAME_MAX_LENGTH: int = 64
"""Maximum sandbox name length supported by git-safety authentication."""

# ============================================================================
# Subprocess Timeout Constants (seconds)
# ============================================================================

TIMEOUT_GIT_TRANSFER: int = 120
"""Timeout for git clone/fetch/worktree add (network-bound)."""

TIMEOUT_GIT_QUERY: int = 10
"""Timeout for git config/rev-parse/for-each-ref (local)."""

TIMEOUT_LOCAL_CMD: int = 5
"""Timeout for quick local commands (id, etc.)."""


# ============================================================================
# Runtime Flag Defaults (read from environment)
# ============================================================================


def get_sandbox_verbose() -> int:
    """Get SANDBOX_VERBOSE flag from environment.

    Returns:
        1 if enabled, 0 if disabled (default)
    """
    return _env_int("SANDBOX_VERBOSE", 0)
