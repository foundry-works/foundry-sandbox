"""Path resolution utilities for foundry-sandbox.

This module replaces lib/paths.sh and absorbs lib/fs.sh helpers.
It provides functions for:
  - Resolving sandbox paths (worktrees, configs, metadata)
  - Deriving all related paths for a named sandbox
  - Directory and path management (ensure_dir, safe_remove)
"""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

from foundry_sandbox.constants import (
    get_claude_configs_dir,
    get_sandbox_home,
    get_worktrees_dir,
)


# ============================================================================
# SandboxPaths Data Structure
# ============================================================================


class SandboxPaths(NamedTuple):
    """Container for all derived paths related to a sandbox.

    Attributes:
        worktree_path: Path to the Git worktree
        container_name: Docker container name
        claude_config_path: Path to Claude configuration directory
        claude_home_path: Path to Claude home directory
        override_file: Path to docker-compose override file
    """

    worktree_path: Path
    container_name: str
    claude_config_path: Path
    claude_home_path: Path
    override_file: Path


# ============================================================================
# Path Resolution Functions
# ============================================================================


def path_worktree(name: str) -> Path:
    """Get the path to a sandbox worktree.

    Args:
        name: Sandbox name

    Returns:
        Path to the worktree directory
    """
    return get_worktrees_dir() / name


def path_claude_config(name: str) -> Path:
    """Get the path to a sandbox's Claude configuration directory.

    Args:
        name: Sandbox name

    Returns:
        Path to the Claude config directory
    """
    return get_claude_configs_dir() / name


def path_claude_home(name: str) -> Path:
    """Get the path to a sandbox's Claude home directory.

    Args:
        name: Sandbox name

    Returns:
        Path to the Claude home directory (within Claude config)
    """
    return path_claude_config(name) / "claude"


def path_override_file(name: str) -> Path:
    """Get the path to a sandbox's docker-compose override file.

    Args:
        name: Sandbox name

    Returns:
        Path to the override YAML file
    """
    return path_claude_config(name) / "docker-compose.override.yml"


def path_metadata_file(name: str) -> Path:
    """Get the path to a sandbox's metadata file (JSON).

    Args:
        name: Sandbox name

    Returns:
        Path to the metadata.json file
    """
    return path_claude_config(name) / "metadata.json"


def path_metadata_legacy_file(name: str) -> Path:
    """Get the path to a sandbox's legacy metadata file (ENV format).

    Args:
        name: Sandbox name

    Returns:
        Path to the metadata.env file (legacy format)
    """
    return path_claude_config(name) / "metadata.env"


def path_opencode_plugins_marker(name: str) -> Path:
    """Get the path to a sandbox's OpenCode plugins sync marker file.

    Args:
        name: Sandbox name

    Returns:
        Path to the opencode-plugins.synced marker file
    """
    return path_claude_config(name) / "opencode-plugins.synced"


def path_last_cast_new() -> Path:
    """Get the path to the last 'cast new' session info file.

    Returns:
        Path to .last-cast-new.json in sandbox home
    """
    return get_sandbox_home() / ".last-cast-new.json"


def path_last_attach() -> Path:
    """Get the path to the last 'attach' session info file.

    Returns:
        Path to .last-attach.json in sandbox home
    """
    return get_sandbox_home() / ".last-attach.json"


def path_presets_dir() -> Path:
    """Get the path to the presets directory.

    Returns:
        Path to the presets directory in sandbox home
    """
    return get_sandbox_home() / "presets"


def path_preset_file(name: str) -> Path:
    """Get the path to a specific preset file.

    Args:
        name: Preset name (without .json extension)

    Returns:
        Path to the preset JSON file
    """
    return path_presets_dir() / f"{name}.json"


# ============================================================================
# Path Derivation
# ============================================================================


def derive_sandbox_paths(name: str) -> SandboxPaths:
    """Derive all paths related to a named sandbox.

    This function combines several path helpers to create a complete
    set of paths for a given sandbox.

    Args:
        name: Sandbox name

    Returns:
        SandboxPaths with all derived paths and container name
    """
    return SandboxPaths(
        worktree_path=path_worktree(name),
        container_name=f"sandbox-{name}",
        claude_config_path=path_claude_config(name),
        claude_home_path=path_claude_home(name),
        override_file=path_override_file(name),
    )


# ============================================================================
# File System Helpers (from lib/fs.sh)
# ============================================================================


def ensure_dir(path: str | Path) -> Path:
    """Ensure a directory exists, creating it if necessary.

    Equivalent to `mkdir -p`. Creates all parent directories as needed.

    Args:
        path: Directory path (string or Path)

    Returns:
        Path object of the directory
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _rmtree_no_follow_symlinks(path: Path) -> None:
    """Remove a directory tree without following symlinks within.

    Walks the tree bottom-up. Symlinks (both files and dirs) are
    unlinked rather than followed, preventing traversal outside
    the intended directory.

    Args:
        path: Directory path to remove.
    """
    for child in path.iterdir():
        if child.is_symlink():
            child.unlink()
        elif child.is_dir():
            _rmtree_no_follow_symlinks(child)
        else:
            child.unlink()
    path.rmdir()


def safe_remove(path: str | Path) -> None:
    """Remove a file or directory tree safely.

    For directories, removes the entire tree without following symlinks
    inside the tree. Top-level symlinks are unlinked rather than followed.

    For files or symlinks, removes just the entry. Does nothing if path
    doesn't exist.

    Args:
        path: File or directory path (string or Path)
    """
    p = Path(path)
    if not p.exists() and not p.is_symlink():
        return

    # If the path itself is a symlink, just remove the link
    if p.is_symlink():
        p.unlink()
        return

    if p.is_dir():
        _rmtree_no_follow_symlinks(p)
    else:
        p.unlink()
