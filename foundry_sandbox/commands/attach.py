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
import sys

import click

from foundry_sandbox.commands._helpers import auto_detect_sandbox as _auto_detect_sandbox, fzf_select_sandbox as _fzf_select_sandbox_shared
from foundry_sandbox.credential_setup import sync_runtime_credentials
from foundry_sandbox.docker import container_is_running
from foundry_sandbox.paths import SandboxPaths, derive_sandbox_paths
from foundry_sandbox.state import load_last_attach, load_sandbox_metadata, save_last_attach
from foundry_sandbox.tool_configs import sync_opencode_local_plugins_on_first_attach
from foundry_sandbox.tmux import attach as tmux_attach_session
from foundry_sandbox.utils import flag_enabled as _flag_enabled, log_debug, log_error, log_warn
from foundry_sandbox.validate import validate_existing_sandbox_name

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _list_sandboxes() -> None:
    """Display available sandboxes."""
    from foundry_sandbox.commands.list_cmd import list_cmd
    ctx = click.Context(list_cmd, info_name="list")
    ctx.invoke(list_cmd)


def _fzf_select_sandbox() -> str | None:
    """Interactively select a sandbox using fzf."""
    return _fzf_select_sandbox_shared()


def _start_container(name: str) -> None:
    """Start a sandbox container.

    Args:
        name: Sandbox name.
    """
    click.echo("Container not running. Starting...")
    from foundry_sandbox.commands.start import start as start_cmd
    ctx = click.Context(start_cmd, info_name="start")
    ctx.invoke(start_cmd, name=name)


def _sync_credentials(container_id: str) -> None:
    """Sync runtime credentials to container.

    Args:
        container_id: Container ID.
    """
    log_debug(f"Syncing credentials to {container_id}")
    sync_runtime_credentials(container_id)


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


def _tmux_attach(name: str, working_dir: str, paths: SandboxPaths) -> None:
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


def _prompt_ide_selection(worktree_path: str) -> bool:
    """Prompt for IDE selection.

    Args:
        worktree_path: Path to worktree.

    Returns:
        True if IDE was launched.
    """
    from foundry_sandbox.ide import prompt_ide_selection

    return prompt_ide_selection(worktree_path)


def _resolve_sandbox_name(name: str | None, use_last: bool) -> str:
    """Resolve sandbox name from --last flag, auto-detect, or fzf selection.

    Args:
        name: Explicit sandbox name (may be None).
        use_last: Whether --last flag was set.

    Returns:
        Validated sandbox name.

    Raises:
        SystemExit: If no sandbox can be resolved or name is invalid.
    """
    if use_last:
        name = load_last_attach()
        if not name:
            log_error("No previous sandbox found. Run 'cast attach <name>' first.")
            sys.exit(1)
        click.echo(f"Reattaching to: {name}")

    if not name:
        name = _auto_detect_sandbox()
        if name:
            click.echo(f"Auto-detected sandbox: {name}")

    if not name:
        name = _fzf_select_sandbox()
        if not name:
            click.echo("Usage: cast attach <sandbox-name>")
            click.echo("")
            _list_sandboxes()
            sys.exit(1)

    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        log_error(name_error)
        sys.exit(1)

    return name


def _handle_ide_options(
    name: str,
    worktree_path: str,
    no_ide: bool,
    with_ide: str | None,
    ide_only: str | None,
) -> bool:
    """Handle IDE launch options and return whether to skip terminal.

    Args:
        name: Sandbox name.
        worktree_path: Path to worktree directory.
        no_ide: Whether --no-ide flag was set.
        with_ide: Value of --with-ide option (None, "auto", or IDE name).
        ide_only: Value of --ide-only option (None, "auto", or IDE name).

    Returns:
        True if terminal should be skipped (--ide-only launched successfully).
    """
    if not os.isatty(0):
        return False

    if no_ide:
        return False

    if ide_only and ide_only != "auto":
        if _launch_ide(ide_only, worktree_path):
            click.echo(f"IDE launched. Run 'cast attach {name}' for terminal.")
            return True

    if with_ide and with_ide != "auto":
        _launch_ide(with_ide, worktree_path)
        return False

    if ide_only == "auto":
        if _prompt_ide_selection(worktree_path):
            click.echo("")
            click.echo("  Run this in your IDE's terminal to connect:")
            click.echo("")
            click.echo(f"    cast attach {name}")
            click.echo("")
            return True

    if with_ide == "auto":
        _prompt_ide_selection(worktree_path)

    return False


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
    # 1. Resolve sandbox name (--last, auto-detect, fzf, or explicit)
    # ------------------------------------------------------------------
    name = _resolve_sandbox_name(name, use_last)

    # ------------------------------------------------------------------
    # 2. Derive sandbox paths
    # ------------------------------------------------------------------
    paths = derive_sandbox_paths(name)
    worktree_path = paths.worktree_path
    container = paths.container_name

    # ------------------------------------------------------------------
    # 3. Check if worktree exists
    # ------------------------------------------------------------------
    if not worktree_path.is_dir():
        log_error(f"Sandbox '{name}' not found")
        _list_sandboxes()
        sys.exit(1)

    # ------------------------------------------------------------------
    # 4. Check if container is running, start if needed
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
    # 5. Load metadata and feature flags
    # ------------------------------------------------------------------
    metadata = load_sandbox_metadata(name)
    working_dir = str(metadata.get("working_dir", "")) if metadata else ""
    enable_opencode = _flag_enabled(metadata.get("enable_opencode", False)) if metadata else False

    # ------------------------------------------------------------------
    # 6. Sync OpenCode plugins on first attach
    # ------------------------------------------------------------------
    if enable_opencode:
        _sync_opencode_plugins(name, container_id)

    # ------------------------------------------------------------------
    # 7. Save this sandbox as last attached
    # ------------------------------------------------------------------
    save_last_attach(name)

    # ------------------------------------------------------------------
    # 8. IDE launch and tmux attach
    # ------------------------------------------------------------------
    skip_terminal = _handle_ide_options(name, str(worktree_path), no_ide, with_ide, ide_only)
    if not skip_terminal:
        _tmux_attach(name, working_dir, paths)
