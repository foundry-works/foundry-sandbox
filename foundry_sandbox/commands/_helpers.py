"""Shared helper functions for sandbox commands.

UI helpers (auto-detect, fzf select, list) live here.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from foundry_sandbox.constants import get_claude_configs_dir, get_worktrees_dir
from foundry_sandbox.utils import log_debug
from foundry_sandbox.validate import validate_existing_sandbox_name


# ---------------------------------------------------------------------------
# UI helpers (canonical home)
# ---------------------------------------------------------------------------


def auto_detect_sandbox() -> str | None:
    """Auto-detect sandbox name from current working directory.

    For new-layout sandboxes, matches cwd against the ``workspace_path``
    stored in each sandbox's metadata. For legacy sandboxes, matches
    against the old ``~/.sandboxes/worktrees/<name>/`` directory.

    Returns:
        Sandbox name if detected, None otherwise.
    """
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        return None

    # Check new-layout sandboxes via metadata workspace_path
    from foundry_sandbox.state import list_sandboxes

    try:
        for sb in list_sandboxes():
            wp = sb.get("workspace_path", "")
            if wp:
                try:
                    cwd.relative_to(Path(wp).resolve())
                    name = sb.get("name", "")
                    valid, _ = validate_existing_sandbox_name(name)
                    if valid:
                        return name
                except ValueError:
                    continue
    except OSError:
        pass

    # Fallback: legacy worktrees/ directory
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
    if shutil.which("fzf") is None:
        return None

    sandboxes = list_sandbox_names()
    if not sandboxes:
        return None

    try:
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
    """List all sandbox names by scanning claude-config directories.

    The claude-config directory is the authoritative registry — it covers
    both old-layout and new-layout sandboxes.

    Returns:
        Sorted list of sandbox directory names.
    """
    configs_dir = get_claude_configs_dir()
    if not configs_dir.is_dir():
        return []

    try:
        return sorted(
            entry.name
            for entry in configs_dir.iterdir()
            if entry.is_dir() and (entry / "metadata.json").exists()
        )
    except OSError:
        return []
