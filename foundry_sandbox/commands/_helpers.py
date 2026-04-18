"""Shared helper functions for sandbox commands.

UI helpers (auto-detect, fzf select, list) live here.
Domain functions have been moved to their canonical modules;
backward-compatible re-exports are provided below.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from foundry_sandbox.constants import get_worktrees_dir
from foundry_sandbox.utils import log_debug
from foundry_sandbox.validate import validate_existing_sandbox_name


# ---------------------------------------------------------------------------
# UI helpers (canonical home)
# ---------------------------------------------------------------------------


def auto_detect_sandbox() -> str | None:
    """Auto-detect sandbox name from current working directory.

    If the cwd is under the worktrees directory, extracts the first path
    component as the sandbox name.

    Returns:
        Sandbox name if detected, None otherwise.
    """
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        return None

    worktrees_dir = get_worktrees_dir()

    try:
        relative = cwd.relative_to(worktrees_dir)
        parts = relative.parts
        if parts:
            name = parts[0]
            valid, _ = validate_existing_sandbox_name(name)
            if valid and (worktrees_dir / name).is_dir():
                return name
    except ValueError:
        pass

    return None


def fzf_select_sandbox() -> str | None:
    """Interactively select a sandbox using fzf.

    Returns:
        Selected sandbox name, or None if canceled/unavailable.
    """
    worktrees_dir = get_worktrees_dir()

    if not worktrees_dir.is_dir():
        return None

    if shutil.which("fzf") is None:
        return None

    try:
        sandboxes = sorted(
            entry.name for entry in worktrees_dir.iterdir()
            if entry.is_dir()
        )

        if not sandboxes:
            return None

        # no timeout: fzf is interactive and waits for user input
        result = subprocess.run(
            ["fzf", "--prompt=Select sandbox: ", "--height=10", "--reverse"],
            input="\n".join(sandboxes),
            text=True,
            capture_output=True,
            check=False,
        )

        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except OSError:
        log_debug("fzf selection failed, falling back")

    return None


def list_sandbox_names() -> list[str]:
    """List all sandbox names by scanning WORKTREES_DIR.

    Returns:
        Sorted list of sandbox directory names.
    """
    worktrees_dir = get_worktrees_dir()
    if not worktrees_dir.is_dir():
        return []

    try:
        return sorted(entry.name for entry in worktrees_dir.iterdir() if entry.is_dir())
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Backward-compatible re-exports (canonical locations noted)
# ---------------------------------------------------------------------------

# From foundry_sandbox.paths
from foundry_sandbox.paths import (  # noqa: F401, E402
    find_next_sandbox_name,
    repo_url_to_bare_path,
    resolve_ssh_agent_sock,
    sandbox_name,
    strip_github_url,
)

# From foundry_sandbox.docker
from foundry_sandbox.docker import (  # noqa: F401, E402
    apply_network_restrictions,
    cleanup_orphaned_networks,
    proxy_cleanup,
    remove_sandbox_networks,
    uses_credential_isolation,
)

# From foundry_sandbox.utils
from foundry_sandbox.utils import (  # noqa: F401, E402
    flag_enabled,
    generate_sandbox_id,
)

# From foundry_sandbox.tmux
from foundry_sandbox.tmux import tmux_session_name  # noqa: F401, E402
