"""Status command — show sandbox status.

Uses `sbx ls` for sandbox status and merges with foundry metadata.
"""

from __future__ import annotations

import json

import click

from foundry_sandbox.sbx import sbx_check_available, sbx_is_running, sbx_ls
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import BOLD, RESET, format_kv, format_table_row
from foundry_sandbox.validate import validate_existing_sandbox_name


def _collect_all_sandboxes() -> list[dict[str, str]]:
    """Collect status info for all sandboxes."""
    sandboxes = sbx_ls()
    for sb in sandboxes:
        name = sb.get("name", "")
        metadata = load_sandbox_metadata(name)
        if metadata:
            sb["repo"] = metadata.get("repo_url", "")
            sb["from_branch"] = metadata.get("from_branch", "")
            sb["git_safety"] = str(metadata.get("git_safety_enabled", False))
        else:
            sb["repo"] = ""
            sb["from_branch"] = ""
            sb["git_safety"] = str(False)
    return sandboxes


def _collect_single_sandbox(name: str) -> dict[str, str] | None:
    """Collect detailed status for a single sandbox."""
    # Find this sandbox in sbx ls output
    for sb in sbx_ls():
        if sb.get("name") == name:
            metadata = load_sandbox_metadata(name) or {}
            sb["repo"] = metadata.get("repo_url", "")
            sb["from_branch"] = metadata.get("from_branch", "")
            sb["working_dir"] = metadata.get("working_dir", "")
            sb["pip_requirements"] = metadata.get("pip_requirements", "")
            sb["git_safety"] = str(metadata.get("git_safety_enabled", False))
            sb["allow_pr"] = str(metadata.get("allow_pr", False))
            sb["copies"] = str(metadata.get("copies", []))
            return sb
    return None


@click.command()
@click.argument("name", required=False, default=None)
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def status(name: str | None, json_output: bool) -> None:
    """Show sandbox status."""
    sbx_check_available()

    if name is None:
        # List all sandboxes
        sandboxes = _collect_all_sandboxes()

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

    info = _collect_single_sandbox(name)
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
