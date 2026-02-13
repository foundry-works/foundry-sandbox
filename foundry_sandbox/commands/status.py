"""Status command — show sandbox status.

Migrated from commands/status.sh (89 lines).
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import click

from foundry_sandbox.constants import TIMEOUT_DOCKER_QUERY, TIMEOUT_LOCAL_CMD, get_claude_configs_dir, get_worktrees_dir
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import BOLD, RESET, format_kv, format_table_row
from foundry_sandbox.validate import validate_existing_sandbox_name


def _get_docker_status(container_name: str) -> str:
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name=^{container_name}-dev",
             "--format", "{{.Status}}"],
            capture_output=True, text=True, check=False,
            timeout=TIMEOUT_DOCKER_QUERY,
        )
        status = result.stdout.strip().splitlines()
        return status[0] if status else "no container"
    except OSError:
        return "no container"


def _tmux_session_exists(name: str) -> bool:
    try:
        result = subprocess.run(
            ["tmux", "has-session", "-t", name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            timeout=TIMEOUT_LOCAL_CMD,
        )
        return result.returncode == 0
    except OSError:
        return False


def _collect_sandbox_info(name: str) -> dict[str, Any]:
    paths = derive_sandbox_paths(name)
    worktrees_dir = get_worktrees_dir()
    configs_dir = get_claude_configs_dir()

    worktree = str(worktrees_dir / name)
    config = str(configs_dir / name)
    container_id = f"{paths.container_name}-dev-1"

    info = {
        "name": name,
        "worktree": worktree,
        "worktree_exists": (worktrees_dir / name).is_dir(),
        "claude_config": config,
        "claude_config_exists": (configs_dir / name).is_dir(),
        "container": container_id,
        "docker_status": _get_docker_status(paths.container_name),
        "tmux": "attached" if _tmux_session_exists(name) else "none",
        "repo": "",
        "branch": "",
        "from_branch": "",
        "mounts": [],
        "copies": [],
    }

    metadata = load_sandbox_metadata(name)
    if metadata:
        info["repo"] = metadata.get("repo_url", "")
        info["branch"] = metadata.get("branch", "")
        info["from_branch"] = metadata.get("from_branch", "")
        info["mounts"] = metadata.get("mounts", [])
        info["copies"] = metadata.get("copies", [])

    return info


@click.command()
@click.argument("name", required=False, default=None)
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def status(name: str | None, json_output: bool) -> None:
    """Show sandbox status."""
    worktrees_dir = get_worktrees_dir()

    if name is None:
        # List all sandboxes
        sandboxes = []
        if worktrees_dir.is_dir():
            for worktree_dir in sorted(worktrees_dir.iterdir()):
                if not worktree_dir.is_dir():
                    continue
                sandboxes.append(_collect_sandbox_info(worktree_dir.name))

        if json_output:
            click.echo(json.dumps(sandboxes))
            return

        click.echo(f"{BOLD}Sandboxes:{RESET}")
        click.echo()
        for sb in sandboxes:
            tmux_suffix = " [tmux]" if sb["tmux"] == "attached" else ""
            click.echo(format_table_row(sb["name"], sb["docker_status"], tmux_suffix))
        return

    # Single sandbox detail
    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        click.echo(f"Error: {name_error}", err=True)
        raise SystemExit(1)

    info = _collect_sandbox_info(name)

    if json_output:
        click.echo(json.dumps(info))
        return

    click.echo(f"{BOLD}Sandbox: {info['name']}{RESET}")
    click.echo(format_kv("Worktree", info["worktree"] if info["worktree_exists"] else "missing"))
    click.echo(format_kv("Claude config", info["claude_config"] if info["claude_config_exists"] else "missing"))
    click.echo(format_kv("Container", f"{info['container']} ({info['docker_status']})"))
    click.echo(format_kv("Tmux", info["tmux"]))

    if info["repo"] or info["branch"]:
        if info["repo"]:
            click.echo(format_kv("Repo", info["repo"]))
        if info["branch"]:
            click.echo(format_kv("Branch", info["branch"]))
        if info["from_branch"]:
            click.echo(format_kv("From branch", info["from_branch"]))
        if info["mounts"]:
            click.echo(format_kv("Mounts", ""))
            for mount in info["mounts"]:
                click.echo(f"    - {mount}")
        if info["copies"]:
            click.echo(format_kv("Copies", ""))
            for copy in info["copies"]:
                click.echo(f"    - {copy}")
    else:
        click.echo(format_kv("Metadata", "none"))
