"""Stop command — stop a running sandbox.

Migrated from commands/stop.sh (24 lines).
"""

from __future__ import annotations

import subprocess
import sys

import click

from foundry_sandbox.constants import TIMEOUT_LOCAL_CMD
from foundry_sandbox.docker import compose_down, resolve_metadata_compose_extras
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import log_info, log_warn
from foundry_sandbox.validate import validate_existing_sandbox_name


@click.command()
@click.argument("name")
def stop(name: str) -> None:
    """Stop a running sandbox (keeps worktree)."""
    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        click.echo(f"Error: {name_error}", err=True)
        sys.exit(1)

    paths = derive_sandbox_paths(name)

    if not paths.worktree_path.is_dir():
        click.echo(f"Error: Sandbox '{name}' not found", err=True)
        sys.exit(1)

    log_info(f"Stopping sandbox: {name}...")

    # Load compose extras from metadata for proper teardown.
    # Best-effort: metadata issues must never prevent stopping containers.
    try:
        metadata = load_sandbox_metadata(name) or {}
        extras = resolve_metadata_compose_extras(metadata) or None
    except Exception as exc:
        log_warn(f"Could not load compose extras from metadata: {exc}")
        extras = None

    # Kill tmux session (best effort)
    try:
        subprocess.run(
            ["tmux", "kill-session", "-t", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=TIMEOUT_LOCAL_CMD,
        )
    except OSError:
        pass  # tmux may not be installed

    # Stop containers
    try:
        compose_down(
            str(paths.worktree_path),
            str(paths.claude_config_path),
            paths.container_name,
            override_file=str(paths.override_file),
            remove_volumes=False,
            compose_extras=extras,
        )
    except Exception as exc:
        log_warn(f"Failed to stop containers: {exc}")
