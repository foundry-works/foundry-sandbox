"""Attach command — connect to a running sandbox via tmux.

Migrated from commands/attach.sh. Performs the following sequence:
  1. Parse arguments (name, --last, --with-ide, --ide-only, --no-ide)
  2. Handle --last flag to reattach to previous sandbox
  3. Auto-detect sandbox from current directory if under worktrees
  4. Interactive fzf selection if available and no name provided
  5. Derive sandbox paths
  6. Check if container is running, start it if needed
  7. Load metadata and optionally sync credentials
  8. Sync OpenCode plugins on first attach (stub)
  9. Save as last attached sandbox
  10. Handle IDE launch logic (stub for now)
  11. Attach to tmux session (or skip if --ide-only)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import click

from foundry_sandbox.constants import get_worktrees_dir
from foundry_sandbox.docker import container_is_running
from foundry_sandbox.legacy_bridge import run_legacy_command
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.state import load_last_attach, load_sandbox_metadata, save_last_attach
from foundry_sandbox.tool_configs import sync_opencode_local_plugins_on_first_attach
from foundry_sandbox.tmux import attach as tmux_attach_session, session_exists as tmux_session_exists, create_and_attach as tmux_create_and_attach, attach_existing as tmux_attach_to_existing
from foundry_sandbox.utils import log_debug, log_error, log_info, log_warn
from foundry_sandbox.validate import validate_existing_sandbox_name

# Path to sandbox.sh for shell fallback
SANDBOX_SH = Path(__file__).resolve().parent.parent.parent / "sandbox.sh"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _list_sandboxes() -> None:
    """Display available sandboxes (fallback to shell for now)."""
    run_legacy_command("list", capture_output=False)


def _auto_detect_sandbox() -> str | None:
    """Auto-detect sandbox from current working directory.

    Returns:
        Sandbox name if detected, None otherwise.
    """
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        return None

    worktrees_dir = get_worktrees_dir()

    # Check if we're under the worktrees directory
    try:
        relative = cwd.relative_to(worktrees_dir)
        # Extract first component (sandbox name)
        parts = relative.parts
        if parts:
            name = parts[0]
            # Validate the detected name before returning
            valid, _ = validate_existing_sandbox_name(name)
            if valid and (worktrees_dir / name).is_dir():
                return name
    except ValueError:
        # Not under worktrees_dir
        pass

    return None


def _fzf_select_sandbox() -> str | None:
    """Interactively select a sandbox using fzf.

    Returns:
        Selected sandbox name, or None if canceled/unavailable.
    """
    worktrees_dir = get_worktrees_dir()

    if not worktrees_dir.is_dir():
        return None

    # Check if fzf is available
    if shutil.which("fzf") is None:
        return None

    try:
        # List directories in worktrees
        sandboxes = sorted(
            entry.name for entry in worktrees_dir.iterdir()
            if entry.is_dir()
        )

        if not sandboxes:
            return None

        # Run fzf with sandbox list
        result = subprocess.run(
            ["fzf", "--prompt=Select sandbox: ", "--height=10", "--reverse"],
            input="\n".join(sandboxes),
            text=True,
            capture_output=True,
            check=False,
        )

        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass

    return None


from foundry_sandbox.commands._helpers import flag_enabled as _flag_enabled


def _start_container(name: str) -> None:
    """Start a sandbox container using shell fallback.

    Args:
        name: Sandbox name.
    """
    click.echo("Container not running. Starting...")
    result = run_legacy_command("start", name, capture_output=False)
    if result.returncode != 0:
        sys.exit(result.returncode)


def _sync_credentials(container_id: str) -> None:
    """Sync runtime credentials to container (stub/shell fallback).

    Args:
        container_id: Container ID.
    """
    # Shell fallback for now - this function is in lib/container_config.sh
    log_debug(f"Syncing credentials to {container_id}")
    run_legacy_command("_bridge_sync_creds", container_id, capture_output=False)


def _sync_opencode_plugins(name: str, container_id: str) -> None:
    """Sync OpenCode local plugins on first attach.

    Args:
        name: Sandbox name.
        container_id: Container ID.
    """
    try:
        sync_opencode_local_plugins_on_first_attach(name, container_id)
    except Exception as exc:
        # Keep attach resilient; plugin sync is best-effort.
        log_warn(f"OpenCode plugin sync skipped: {exc}")


def _tmux_attach(name: str, working_dir: str, paths) -> None:
    """Create or attach to tmux session for sandbox.

    Delegates to foundry_sandbox.tmux module.

    Args:
        name: Sandbox name.
        working_dir: Working directory inside container.
        paths: SandboxPaths object.
    """
    container_id = f"{paths.container_name}-dev-1"
    worktree_path = str(paths.worktree_path)
    tmux_attach_session(name, container_id, worktree_path, working_dir)


def _launch_ide(ide_name: str, worktree_path: str) -> bool:
    """Launch a specific IDE by name.

    Args:
        ide_name: IDE name (e.g., "cursor", "code").
        worktree_path: Path to worktree.

    Returns:
        True if IDE was launched successfully.
    """
    from foundry_sandbox.ide import auto_launch_ide

    return auto_launch_ide(ide_name, worktree_path)


def _prompt_ide_selection(worktree_path: str, name: str) -> bool:
    """Prompt for IDE selection.

    Args:
        worktree_path: Path to worktree.
        name: Sandbox name.

    Returns:
        True if IDE was launched.
    """
    from foundry_sandbox.ide import prompt_ide_selection

    return prompt_ide_selection(worktree_path, name)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


@click.command()
@click.argument("name", required=False, default=None)
@click.option("--last", "use_last", is_flag=True, help="Reattach to last sandbox")
@click.option(
    "--with-ide",
    "with_ide",
    is_flag=False,
    flag_value="auto",
    default=None,
    help="Launch IDE (optional: specify name like 'cursor')",
)
@click.option(
    "--ide-only",
    "ide_only",
    is_flag=False,
    flag_value="auto",
    default=None,
    help="Launch IDE only, skip terminal (optional: specify name)",
)
@click.option("--no-ide", "no_ide", is_flag=True, help="Skip IDE prompt")
def attach(
    name: str | None,
    use_last: bool,
    with_ide: str | None,
    ide_only: str | None,
    no_ide: bool,
) -> None:
    """Attach to a sandbox via tmux."""

    # ------------------------------------------------------------------
    # 1. Handle --last flag
    # ------------------------------------------------------------------
    if use_last:
        name = load_last_attach()
        if not name:
            log_error("No previous sandbox found. Run 'cast attach <name>' first.")
            sys.exit(1)
        click.echo(f"Reattaching to: {name}")

    # ------------------------------------------------------------------
    # 2. Auto-detect sandbox from current directory
    # ------------------------------------------------------------------
    if not name:
        name = _auto_detect_sandbox()
        if name:
            click.echo(f"Auto-detected sandbox: {name}")

    # ------------------------------------------------------------------
    # 3. Interactive fzf selection
    # ------------------------------------------------------------------
    if not name:
        name = _fzf_select_sandbox()
        if not name:
            # Show usage and list sandboxes
            click.echo(f"Usage: cast attach <sandbox-name>")
            click.echo("")
            _list_sandboxes()
            sys.exit(1)

    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        log_error(name_error)
        sys.exit(1)

    # ------------------------------------------------------------------
    # 4. Derive sandbox paths
    # ------------------------------------------------------------------
    paths = derive_sandbox_paths(name)
    worktree_path = paths.worktree_path
    container = paths.container_name

    # ------------------------------------------------------------------
    # 5. Check if worktree exists
    # ------------------------------------------------------------------
    if not worktree_path.is_dir():
        log_error(f"Sandbox '{name}' not found")
        _list_sandboxes()
        sys.exit(1)

    # ------------------------------------------------------------------
    # 6. Check if container is running, start if needed
    # ------------------------------------------------------------------
    container_id = f"{container}-dev-1"

    if not container_is_running(container):
        _start_container(name)
    else:
        # Load metadata to get settings
        load_sandbox_metadata(name)  # May return None, that's ok

        # Optionally sync credentials
        if os.environ.get("SANDBOX_SYNC_ON_ATTACH", "0") == "1":
            _sync_credentials(container_id)
        else:
            log_debug("Skipping credential sync on attach (SANDBOX_SYNC_ON_ATTACH=0)")

    # ------------------------------------------------------------------
    # 7. Ensure metadata is loaded (may not be if container was just started)
    # ------------------------------------------------------------------
    metadata = load_sandbox_metadata(name)
    working_dir = str(metadata.get("working_dir", "")) if metadata else ""
    enable_opencode = _flag_enabled(metadata.get("enable_opencode", False)) if metadata else False

    # ------------------------------------------------------------------
    # 8. Sync OpenCode plugins on first attach
    # ------------------------------------------------------------------
    if enable_opencode:
        _sync_opencode_plugins(name, container_id)

    # ------------------------------------------------------------------
    # 9. Save this sandbox as last attached
    # ------------------------------------------------------------------
    save_last_attach(name)

    # ------------------------------------------------------------------
    # 10. IDE launch logic
    # ------------------------------------------------------------------
    skip_terminal = False

    # Only handle IDE logic if stdin is a TTY
    if os.isatty(0):
        if no_ide:
            # --no-ide: skip IDE prompt entirely
            pass
        elif ide_only and ide_only != "auto":
            # Specific IDE requested via --ide-only=<name>
            if _launch_ide(ide_only, str(worktree_path)):
                skip_terminal = True
                click.echo(f"IDE launched. Run 'cast attach {name}' for terminal.")
        elif with_ide and with_ide != "auto":
            # Specific IDE requested via --with-ide=<name>
            _launch_ide(with_ide, str(worktree_path))
            # Don't skip terminal for --with-ide
        elif ide_only == "auto":
            # --ide-only without specific name: prompt for selection
            if _prompt_ide_selection(str(worktree_path), name):
                skip_terminal = True
                click.echo("")
                click.echo("  Run this in your IDE's terminal to connect:")
                click.echo("")
                click.echo(f"    cast attach {name}")
                click.echo("")
        elif with_ide == "auto":
            # --with-ide without specific name: prompt for selection
            _prompt_ide_selection(str(worktree_path), name)
            # Don't skip terminal for --with-ide
        # Default for attach: go directly to terminal (no IDE prompt)

    # ------------------------------------------------------------------
    # 11. Attach to tmux (unless --ide-only)
    # ------------------------------------------------------------------
    if not skip_terminal:
        _tmux_attach(name, working_dir, paths)
