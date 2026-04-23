"""Shared helper functions for sandbox commands.

UI helpers (auto-detect, fzf select, list, resolve) live here.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import click

from foundry_sandbox.constants import get_sandbox_configs_dir
from foundry_sandbox.utils import log_debug, log_error
from foundry_sandbox.validate import validate_existing_sandbox_name


# ---------------------------------------------------------------------------
# UI helpers (canonical home)
# ---------------------------------------------------------------------------


def auto_detect_sandbox() -> str | None:
    """Auto-detect sandbox name from current working directory.

    Matches cwd against the ``host_worktree_path`` stored in each
    sandbox's metadata.

    Returns:
        Sandbox name if detected, None otherwise.
    """
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        return None

    from foundry_sandbox.state import list_sandboxes

    try:
        for sb in list_sandboxes():
            wp = sb.get("host_worktree_path", "")
            if wp:
                try:
                    cwd.relative_to(Path(wp).resolve())
                    name = str(sb.get("name", ""))
                    valid, _ = validate_existing_sandbox_name(name)
                    if valid:
                        return name
                except ValueError:
                    continue
    except OSError:
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
    """List all sandbox names by scanning sandbox config directories.

    The sandboxes directory is the authoritative registry.

    Returns:
        Sorted list of sandbox directory names.
    """
    configs_dir = get_sandbox_configs_dir()
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


def resolve_sandbox_name(
    name: str | None,
    *,
    use_last: bool = False,
    allow_fzf: bool = True,
) -> str:
    """Resolve sandbox name via --last, auto-detect, fzf, then validate."""
    if use_last:
        from foundry_sandbox.state import load_last_attach

        name = load_last_attach()
        if not name:
            log_error("No previous sandbox found.")
            sys.exit(1)

    if not name:
        name = auto_detect_sandbox()
        if name:
            click.echo(f"Auto-detected sandbox: {name}")

    if not name and allow_fzf:
        name = fzf_select_sandbox()

    if not name:
        click.echo("Usage: cast <command> <sandbox-name>")
        names = list_sandbox_names()
        if names:
            click.echo("Available sandboxes:")
            for n in names:
                click.echo(f"  {n}")
        sys.exit(1)

    valid, err = validate_existing_sandbox_name(name)
    if not valid:
        log_error(err)
        sys.exit(1)

    return name
