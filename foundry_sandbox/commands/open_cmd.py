"""Open command — launch IDE for a sandbox worktree without attaching a shell."""

from __future__ import annotations

import sys

import click

from foundry_sandbox.commands._helpers import resolve_sandbox_name
from foundry_sandbox.foundry_config import load_user_ide_config
from foundry_sandbox.ide import IdeSpec, detect_available_ides, launch_ide, resolve_ide
from foundry_sandbox.paths import resolve_host_worktree_path
from foundry_sandbox.utils import log_error


def _resolve_ide_for_open(
    ide_value: str | None,
    ide_config: object | None,
    metadata: dict[str, object] | None = None,
) -> IdeSpec | None:
    """Resolve IDE for open: CLI override > config > metadata > last IDE > auto-detect."""
    # CLI override
    if ide_value:
        return resolve_ide(ide_value)

    # Config preferred
    preferred = getattr(ide_config, "preferred", "") if ide_config else ""
    if preferred:
        spec = resolve_ide(preferred)
        if spec is not None:
            return spec

    # Sandbox metadata IDE (from preset)
    from foundry_sandbox.state import load_last_ide

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

    # Auto-detect
    available = detect_available_ides()
    if available:
        return resolve_ide(available[0])

    return None


def _get_ide_args(ide_config: object | None) -> list[str]:
    from foundry_sandbox.commands._ide_helpers import get_ide_args
    return get_ide_args(ide_config)


@click.command()
@click.argument("name", required=False, default=None)
@click.option("--last", "use_last", is_flag=True, help="Open last sandbox worktree")
@click.option("--ide", "ide_value", default=None, help="IDE alias, path, or command")
def open_cmd(name: str | None, use_last: bool, ide_value: str | None) -> None:
    """Open a sandbox worktree in an IDE."""

    ide_config = load_user_ide_config()

    # Resolve sandbox name
    name = resolve_sandbox_name(name, use_last=use_last)

    # Resolve host worktree path
    try:
        worktree_path = resolve_host_worktree_path(name)
    except ValueError as exc:
        log_error(str(exc))
        sys.exit(1)

    if not worktree_path.is_dir():
        log_error(f"Sandbox '{name}' worktree not found at {worktree_path}")
        sys.exit(1)

    # Load metadata for preset IDE resolution
    from foundry_sandbox.state import load_sandbox_metadata
    metadata = load_sandbox_metadata(name)

    # Resolve IDE
    spec = _resolve_ide_for_open(ide_value, ide_config, metadata)
    if spec is None:
        if ide_value:
            log_error(f"IDE '{ide_value}' could not be resolved")
        else:
            log_error("No IDE found. Set ide.preferred in ~/.foundry/foundry.yaml or use --ide.")
        sys.exit(1)

    extra_args = _get_ide_args(ide_config)
    ok = launch_ide(spec, str(worktree_path), extra_args)
    if not ok:
        sys.exit(1)

    from foundry_sandbox.commands._ide_helpers import maybe_auto_git_mode
    maybe_auto_git_mode(name, ide_config)
