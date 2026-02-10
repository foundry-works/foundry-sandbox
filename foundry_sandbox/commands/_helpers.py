"""Shared helper functions for sandbox commands.

Consolidates duplicated utilities from destroy.py, prune.py, legacy_bridge.py,
start.py, attach.py, and new.py.
"""
from __future__ import annotations

import os
from pathlib import Path

from foundry_sandbox.constants import get_repos_dir


def repo_url_to_bare_path(repo_url: str) -> str:
    """Convert a repository URL to its bare-clone path under REPOS_DIR.

    Handles https://, http://, git@, and local filesystem paths.

    Args:
        repo_url: Repository URL or local path.

    Returns:
        Absolute path string to the bare repository.
    """
    repos_dir = str(get_repos_dir())

    if not repo_url:
        return f"{repos_dir}/unknown.git"

    # Local filesystem path
    if repo_url.startswith(("~/", "/", "./", "../")):
        expanded = repo_url
        if expanded.startswith("~/"):
            expanded = str(Path.home()) + expanded[1:]
        p = Path(expanded)
        if p.exists():
            try:
                expanded = str(p.resolve())
            except OSError:
                pass
        stripped = expanded.lstrip("/")
        return f"{repos_dir}/local/{stripped}.git"

    # HTTPS, HTTP, or git@ URL
    path = repo_url
    path = path.removeprefix("https://")
    path = path.removeprefix("http://")
    path = path.removeprefix("git@")
    path = path.replace(":", "/", 1) if ":" in path else path
    if path.endswith(".git"):
        path = path[:-4]
    return f"{repos_dir}/{path}.git"


def flag_enabled(value: object) -> bool:
    """Parse persisted 0/1/true/false style flag values.

    Args:
        value: Value to parse (bool, int, or str).

    Returns:
        True if the value represents an enabled flag.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def tmux_session_name(name: str) -> str:
    """Return the tmux session name for a sandbox.

    Currently just returns the sandbox name as-is.

    Args:
        name: Sandbox name.

    Returns:
        Tmux session name.
    """
    return name
