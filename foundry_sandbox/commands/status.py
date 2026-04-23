"""Status command — show sandbox status.

Uses `sbx ls` for sandbox status and merges with foundry metadata.
"""

from __future__ import annotations

import json

import click

from foundry_sandbox.sbx import sbx_check_available, sbx_is_running
from foundry_sandbox.state import collect_sandbox_list
from foundry_sandbox.utils import BOLD, RESET, format_kv, format_table_row
from foundry_sandbox.validate import validate_existing_sandbox_name


@click.command()
@click.argument("name", required=False, default=None)
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def status(name: str | None, json_output: bool) -> None:
    """Show sandbox status."""
    sbx_check_available()

    if name is None:
        sandboxes = collect_sandbox_list()

        if json_output:
            click.echo(json.dumps(sandboxes))
            return

        click.echo(f"{BOLD}Sandboxes:{RESET}")
        click.echo()
        for sb in sandboxes:
            sb_name = sb.get("name", "?")
            sb_status = sb.get("status", "unknown")
            click.echo(format_table_row(sb_name, sb_status))
        return

    # Single sandbox detail
    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        click.echo(f"Error: {name_error}", err=True)
        raise SystemExit(1)

    results = collect_sandbox_list(name=name)
    info = results[0] if results else None
    if info is None:
        click.echo(f"Error: Sandbox '{name}' not found in sbx", err=True)
        raise SystemExit(1)

    if json_output:
        click.echo(json.dumps(info))
        return

    click.echo(f"{BOLD}Sandbox: {info.get('name', name)}{RESET}")
    click.echo(format_kv("Status", info.get("status", "unknown")))
    click.echo(format_kv("Agent", info.get("agent", "")))
    running = sbx_is_running(name)
    click.echo(format_kv("Running", str(running)))

    if info.get("branch"):
        click.echo(format_kv("Branch", info["branch"]))
    if info.get("from_branch"):
        click.echo(format_kv("From branch", info["from_branch"]))
    if info.get("repo"):
        click.echo(format_kv("Repo", info["repo"]))
    click.echo(format_kv("Git safety", str(info.get("git_safety", False))))

    wrapper_checksum = info.get("wrapper_checksum", "")
    if wrapper_checksum:
        click.echo(format_kv("Wrapper checksum", wrapper_checksum[:16] + "..."))
    wrapper_verified = info.get("wrapper_last_verified", "")
    if wrapper_verified:
        click.echo(format_kv("Wrapper last verified", wrapper_verified))
