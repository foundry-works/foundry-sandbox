"""Up command — start, open IDE, and attach to a sandbox in one step."""

from __future__ import annotations

import os
import sys

import click

from foundry_sandbox.commands._helpers import resolve_sandbox_name
from foundry_sandbox.foundry_config import load_user_ide_config
from foundry_sandbox.ide import IdeSpec, detect_available_ides, launch_ide, resolve_ide
from foundry_sandbox.paths import resolve_host_worktree_path
from foundry_sandbox.sbx import sbx_check_available, sbx_is_running
from foundry_sandbox.state import load_last_ide, load_sandbox_metadata, save_last_attach
from foundry_sandbox.utils import log_error


def _resolve_ide_for_up(
    ide_value: str | None,
    ide_config: object | None,
    metadata: dict[str, object] | None = None,
) -> IdeSpec | None:
    """Resolve IDE for up: CLI override > config > metadata > last IDE > auto-detect."""
    if ide_value:
        return resolve_ide(ide_value)

    preferred = getattr(ide_config, "preferred", "") if ide_config else ""
    if preferred:
        spec = resolve_ide(preferred)
        if spec is not None:
            return spec

    sandbox_ide = str(metadata.get("ide", "")) if metadata else ""
    if sandbox_ide:
        spec = resolve_ide(sandbox_ide)
        if spec is not None:
            return spec

    last_ide = load_last_ide()
    if last_ide:
        spec = resolve_ide(last_ide)
        if spec is not None:
            return spec

    available = detect_available_ides()
    if available:
        return resolve_ide(available[0])

    return None


@click.command()
@click.argument("name", required=False, default=None)
@click.option("--last", "use_last", is_flag=True, help="Resume last sandbox")
@click.option("--no-ide", "no_ide", is_flag=True, help="Skip IDE launch")
@click.option("--ide", "ide_value", default=None, help="Override IDE (alias, path, or command)")
def up(name: str | None, use_last: bool, no_ide: bool, ide_value: str | None) -> None:
    """Start, open in IDE, and attach to a sandbox.

    Convenience wrapper: starts the sandbox if stopped, opens the worktree
    in your configured IDE, then attaches a terminal.
    """
    sbx_check_available()
    ide_config = load_user_ide_config()

    # 1. Resolve sandbox name
    name = resolve_sandbox_name(name, use_last=use_last)

    # 2. Verify sandbox exists
    try:
        worktree_path = resolve_host_worktree_path(name)
    except ValueError as exc:
        log_error(str(exc))
        sys.exit(1)

    if not worktree_path.is_dir():
        log_error(f"Sandbox '{name}' not found. Run 'cast new' to create one.")
        sys.exit(1)

    # 3. Start if not running
    if not sbx_is_running(name):
        click.echo("Sandbox not running. Starting...")
        from foundry_sandbox.commands.start import start_sandbox
        start_sandbox(name)

    # 4. Load metadata
    metadata = load_sandbox_metadata(name)
    working_dir = str(metadata.get("working_dir", "")) if metadata else ""

    # 5. Save as last attached
    save_last_attach(name)

    # 6. IDE launch
    if not no_ide and os.isatty(0):
        from foundry_sandbox.commands._ide_helpers import get_ide_args, maybe_auto_git_mode

        spec = _resolve_ide_for_up(ide_value, ide_config, metadata)
        if spec is not None:
            extra_args = get_ide_args(ide_config)
            ok = launch_ide(spec, str(worktree_path), extra_args)
            if ok:
                maybe_auto_git_mode(name, ide_config)
            elif ide_value:
                log_error(f"IDE '{ide_value}' launch failed")
        elif ide_value:
            log_error(f"IDE '{ide_value}' could not be resolved")

    # 7. Attach terminal
    from foundry_sandbox.commands.attach import _sbx_attach
    _sbx_attach(name, working_dir)
