"""Attach command — connect to a running sandbox.

Uses `sbx exec --streaming` for interactive sessions instead of tmux.
Auto-starts the sandbox if not running.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from foundry_sandbox.ide import IdeSpec

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


def _resolve_ide_for_attach(
    ide_config: object | None,
    metadata: dict[str, object] | None = None,
) -> "IdeSpec | None":  # noqa: F821
    """Resolve which IDE to use, consulting config, metadata, last-IDE, then auto-detect."""
    from foundry_sandbox.ide import detect_available_ides, resolve_ide
    from foundry_sandbox.state import load_last_ide

    preferred = getattr(ide_config, "preferred", "") if ide_config else ""

    # Try config preferred first
    if preferred:
        spec = resolve_ide(preferred)
        if spec is not None:
            return spec

    # Sandbox metadata IDE (from preset)
    sandbox_ide = str(metadata.get("ide", "")) if metadata else ""
    if sandbox_ide:
        spec = resolve_ide(sandbox_ide)
        if spec is not None:
            return spec

    # Last successful IDE
    last_ide = load_last_ide()
    if last_ide:
        spec = resolve_ide(last_ide)
        if spec is not None:
            return spec

    # Fall back to auto-detect
    available = detect_available_ides()
    if available:
        return resolve_ide(available[0])

    return None


def _get_ide_args(ide_config: object | None) -> list[str]:
    from foundry_sandbox.commands._ide_helpers import get_ide_args
    return get_ide_args(ide_config)


def _handle_ide_options(
    name: str,
    worktree_path: str,
    no_ide: bool,
    with_ide: str | None,
    ide_only: str | None,
    ide_config: object | None,
    metadata: dict[str, object] | None = None,
) -> bool:
    """Handle IDE launch options. Returns True if terminal should be skipped."""
    from foundry_sandbox.commands._ide_helpers import maybe_auto_git_mode
    from foundry_sandbox.ide import launch_ide, resolve_ide

    if not os.isatty(0):
        return False

    if no_ide:
        return False

    # Explicit CLI value (not "auto")
    cli_value = ide_only or with_ide
    if cli_value and cli_value != "auto":
        spec = resolve_ide(cli_value)
        if spec is None:
            click.echo(f"Warning: IDE '{cli_value}' could not be resolved", err=True)
            if ide_only:
                sys.exit(1)
            return False
        extra_args = _get_ide_args(ide_config)
        ok = launch_ide(spec, worktree_path, extra_args)
        if ok:
            maybe_auto_git_mode(name, ide_config)
        if not ok and ide_only:
            sys.exit(1)
        if ide_only and ok:
            click.echo(f"IDE launched. Run 'cast attach {name}' for terminal.")
        return bool(ide_only and ok)

    # "auto" — interactive prompt (preserving existing behavior)
    if cli_value == "auto":
        from foundry_sandbox.ide import prompt_ide_selection
        if prompt_ide_selection(worktree_path):
            if ide_only:
                click.echo(f"\n  Run this in your IDE's terminal to connect:\n\n    cast attach {name}\n")
                return True
        return False

    # No CLI flag — check config-driven auto-open
    if ide_config and getattr(ide_config, "auto_open_on_attach", False):
        spec = _resolve_ide_for_attach(ide_config, metadata)
        if spec is not None:
            extra_args = _get_ide_args(ide_config)
            ok = launch_ide(spec, worktree_path, extra_args)
            if ok:
                maybe_auto_git_mode(name, ide_config)
            if not ok:
                click.echo("Warning: config-driven IDE launch failed", err=True)
            return False
        click.echo("Warning: auto_open_on_attach set but no IDE found", err=True)

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

    # Load user IDE config (user-only, from ~/.foundry/foundry.yaml)
    from foundry_sandbox.foundry_config import load_user_ide_config
    ide_config = load_user_ide_config()

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
    skip_terminal = _handle_ide_options(name, str(worktree_path), no_ide, with_ide, ide_only, ide_config, metadata)
    if not skip_terminal:
        _sbx_attach(name, working_dir)
