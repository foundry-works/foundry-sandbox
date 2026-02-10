"""Stop command — stop a running sandbox.

Migrated from commands/stop.sh (24 lines).
"""

from __future__ import annotations

import subprocess
import sys

import click

from foundry_sandbox.docker import compose_down
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.utils import log_info
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

    log_info(f"Stopping sandbox: {name}...")

    # Kill tmux session (best effort)
    subprocess.run(
        ["tmux", "kill-session", "-t", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    # Stop containers
    compose_down(
        str(paths.worktree_path),
        str(paths.claude_config_path),
        paths.container_name,
        override_file=str(paths.override_file),
        remove_volumes=False,
    )
