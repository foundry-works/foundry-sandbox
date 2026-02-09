"""Preset management commands for cast new.

Migrated from commands/preset.sh. Provides list, show, and delete
subcommands for managing saved cast-new presets.
"""

from __future__ import annotations

import sys

import click

from foundry_sandbox.state import (
    delete_cast_preset,
    list_cast_presets,
    show_cast_preset,
)
from foundry_sandbox.utils import log_error


def _list_presets() -> None:
    """Print saved presets to stdout."""
    click.echo("Saved presets:")
    click.echo("")
    names = list_cast_presets()
    for name in names:
        click.echo(name)


@click.group(invoke_without_command=True)
@click.pass_context
def preset(ctx: click.Context) -> None:
    """Manage saved presets."""
    if ctx.invoked_subcommand is None:
        _list_presets()


@preset.command("list")
def list_cmd() -> None:
    """List all saved presets."""
    _list_presets()


@preset.command("show")
@click.argument("name")
def show(name: str) -> None:
    """Show preset details."""
    result = show_cast_preset(name)
    if result is None:
        log_error(f"Preset not found: {name}")
        sys.exit(1)
    click.echo(result)


@preset.command("delete")
@click.argument("name")
def delete(name: str) -> None:
    """Delete a preset."""
    deleted = delete_cast_preset(name)
    if not deleted:
        log_error(f"Preset not found: {name}")
        sys.exit(1)
    click.echo(f"Deleted preset: {name}")


@preset.command("rm", hidden=True)
@click.argument("name")
def rm(name: str) -> None:
    """Delete a preset (alias for delete)."""
    deleted = delete_cast_preset(name)
    if not deleted:
        log_error(f"Preset not found: {name}")
        sys.exit(1)
    click.echo(f"Deleted preset: {name}")


@preset.command("remove", hidden=True)
@click.argument("name")
def remove(name: str) -> None:
    """Delete a preset (alias for delete)."""
    deleted = delete_cast_preset(name)
    if not deleted:
        log_error(f"Preset not found: {name}")
        sys.exit(1)
    click.echo(f"Deleted preset: {name}")
