"""List command — display all sandboxes.

Uses `sbx ls` to get sandbox status and merges with foundry metadata.
"""

from __future__ import annotations

import json

import click

from foundry_sandbox.state import collect_sandbox_list
from foundry_sandbox.utils import BOLD, RESET, format_table_row


@click.command("list")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON")
def list_cmd(json_output: bool) -> None:
    """List all sandboxes."""
    sandboxes = collect_sandbox_list()

    if json_output:
        click.echo(json.dumps(sandboxes))
        return

    if not sandboxes:
        click.echo(f"{BOLD}Sandboxes:{RESET}")
        click.echo("  (none)")
        return

    click.echo(f"{BOLD}Sandboxes:{RESET}")
    click.echo("-" * 40)
    for sb in sandboxes:
        name = sb.get("name", "?")
        status = sb.get("status", "unknown")
        agent = sb.get("agent", "")
        branch = sb.get("branch", "")
        drift = ""
        if status == "running" and not sb.get("wrapper_checksum"):
            drift = " !"
        click.echo(format_table_row(name, f"{status} ({agent}){drift}", branch))
