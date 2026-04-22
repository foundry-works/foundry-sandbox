"""Attach command — connect to a running sandbox.

Uses `sbx exec --streaming` for interactive sessions instead of tmux.
Auto-starts the sandbox if not running.
"""

from __future__ import annotations

import os
import sys

import click

from foundry_sandbox.commands._helpers import resolve_sandbox_name
from foundry_sandbox.paths import resolve_host_worktree_path
from foundry_sandbox.sbx import sbx_check_available, sbx_exec_streaming, sbx_is_running
from foundry_sandbox.state import load_sandbox_metadata, save_last_attach
from foundry_sandbox.utils import log_error


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _start_sandbox(name: str) -> None:
    """Start a sandbox via sbx run."""
    click.echo("Sandbox not running. Starting...")
    from foundry_sandbox.commands.start import start_sandbox
    start_sandbox(name)


def _handle_ide_options(
    name: str,
    worktree_path: str,
    no_ide: bool,
    with_ide: str | None,
    ide_only: str | None,
) -> bool:
    """Handle IDE launch options. Returns True if terminal should be skipped."""
    if not os.isatty(0):
        return False

    if no_ide:
        return False

    if ide_only and ide_only != "auto":
        from foundry_sandbox.ide import auto_launch_ide
        if auto_launch_ide(ide_only, worktree_path):
            click.echo(f"IDE launched. Run 'cast attach {name}' for terminal.")
            return True

    if with_ide and with_ide != "auto":
        from foundry_sandbox.ide import auto_launch_ide
        auto_launch_ide(with_ide, worktree_path)
        return False

    if ide_only == "auto":
        from foundry_sandbox.ide import prompt_ide_selection
        if prompt_ide_selection(worktree_path):
            click.echo(f"\n  Run this in your IDE's terminal to connect:\n\n    cast attach {name}\n")
            return True

    if with_ide == "auto":
        from foundry_sandbox.ide import prompt_ide_selection
        prompt_ide_selection(worktree_path)

    return False


def _sbx_attach(name: str, working_dir: str) -> None:
    """Attach to sandbox via sbx exec streaming.

    Uses a login shell (-l) to ensure /etc/profile.d scripts are sourced,
    which is required for git safety environment variables to be available.
    """
    if working_dir:
        shell_cmd = ["bash", "-lc", f"cd {working_dir} && exec bash -l"]
    else:
        shell_cmd = ["bash", "-l"]
    proc = sbx_exec_streaming(name, shell_cmd, interactive=True)
    proc.wait()


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
    """Attach to a sandbox."""

    # ------------------------------------------------------------------
    # 1. Resolve sandbox name
    # ------------------------------------------------------------------
    name = resolve_sandbox_name(name, use_last=use_last)

    # ------------------------------------------------------------------
    # 2. Check sandbox exists
    # ------------------------------------------------------------------
    sbx_check_available()
    worktree_path = resolve_host_worktree_path(name)

    if not worktree_path.is_dir():
        log_error(f"Sandbox '{name}' not found")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 3. Start sandbox if not running
    # ------------------------------------------------------------------
    if not sbx_is_running(name):
        _start_sandbox(name)

    # ------------------------------------------------------------------
    # 4. Load metadata
    # ------------------------------------------------------------------
    metadata = load_sandbox_metadata(name)
    working_dir = str(metadata.get("working_dir", "")) if metadata else ""

    # ------------------------------------------------------------------
    # 5. Save as last attached
    # ------------------------------------------------------------------
    save_last_attach(name)

    # ------------------------------------------------------------------
    # 6. IDE launch and attach
    # ------------------------------------------------------------------
    skip_terminal = _handle_ide_options(name, str(worktree_path), no_ide, with_ide, ide_only)
    if not skip_terminal:
        _sbx_attach(name, working_dir)
