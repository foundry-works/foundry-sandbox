"""Stop command — stop a running sandbox."""

from __future__ import annotations

import sys

import click

from foundry_sandbox.sbx import sbx_check_available, sbx_stop
from foundry_sandbox.utils import log_info, log_warn
from foundry_sandbox.validate import validate_existing_sandbox_name


@click.command()
@click.argument("name")
def stop(name: str) -> None:
    """Stop a running sandbox (keeps worktree)."""
    sbx_check_available()

    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        click.echo(f"Error: {name_error}", err=True)
        sys.exit(1)

    log_info(f"Stopping sandbox: {name}...")

    try:
        sbx_stop(name)
        click.echo(f"Sandbox '{name}' stopped.")
    except Exception as exc:
        log_warn(f"Failed to stop sandbox: {exc}")
