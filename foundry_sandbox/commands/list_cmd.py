"""List command — display all sandboxes.

Uses `sbx ls` to get sandbox status and merges with foundry metadata.
"""

from __future__ import annotations

import json

import click

from foundry_sandbox.sbx import sbx_ls
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import BOLD, RESET, format_table_row


def _collect_sandbox_info() -> list[dict[str, str]]:
    """Collect sandbox info from sbx and foundry metadata.

    Returns:
        List of sandbox info dicts.
    """
    sandboxes = sbx_ls()
    for sb in sandboxes:
        name = sb.get("name", "")
        metadata = load_sandbox_metadata(name)
        if metadata:
            sb["repo"] = metadata.get("repo_url", "")
            sb["from_branch"] = metadata.get("from_branch", "")
            sb["git_safety"] = str(metadata.get("git_safety_enabled", False))
            sb["wrapper_checksum"] = metadata.get("wrapper_checksum", "")
        else:
            sb["repo"] = ""
            sb["from_branch"] = ""
            sb["git_safety"] = str(False)
            sb["wrapper_checksum"] = ""
    return sandboxes


@click.command("list")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON")
def list_cmd(json_output: bool) -> None:
    """List all sandboxes."""
    sandboxes = _collect_sandbox_info()

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
