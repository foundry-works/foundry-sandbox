"""Help command — delegates to Click's auto-generated help."""

from __future__ import annotations

import click


@click.command("help")
@click.pass_context
def help_cmd(ctx: click.Context) -> None:
    """Show detailed usage information."""
    parent = ctx.parent
    if parent is not None:
        click.echo(parent.get_help())
