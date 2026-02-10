"""List command — display all sandboxes.

Migrated from commands/list.sh (28 lines). Lists all sandboxes with their status,
optionally outputting as JSON.

Flags:
  --json: Output results as JSON array

Text output shows sandbox name, docker status, and tmux attachment status.
JSON output includes full sandbox metadata (paths, container info, git metadata).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import click

from foundry_sandbox.constants import TIMEOUT_DOCKER_QUERY, TIMEOUT_LOCAL_CMD, get_worktrees_dir
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import BOLD, RESET, format_table_row, log_debug


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_docker_status(container_name: str) -> str:
    """Get docker status for a container.

    Args:
        container_name: Container project name.

    Returns:
        Status string (e.g., "Up 2 hours", "Exited (0) 5 minutes ago"),
        or "no container" if not found.
    """
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name=^{container_name}-dev", "--format", "{{.Status}}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_DOCKER_QUERY,
        )
        status = result.stdout.strip().split("\n")[0] if result.stdout.strip() else ""
        return status if status else "no container"
    except Exception:
        log_debug("Failed to query container status")
        return "no container"


def _tmux_session_exists(name: str) -> bool:
    """Check if a tmux session exists for this sandbox.

    Args:
        name: Sandbox name.

    Returns:
        True if tmux session exists.
    """
    try:
        result = subprocess.run(
            ["tmux", "has-session", "-t", name],
            capture_output=True,
            check=False,
            timeout=TIMEOUT_LOCAL_CMD,
        )
        return result.returncode == 0
    except Exception:
        log_debug("Failed to check tmux session")
        return False


def _collect_sandbox_info(name: str) -> dict[str, Any]:
    """Collect all sandbox information.

    Args:
        name: Sandbox name.

    Returns:
        Dictionary with sandbox information matching shell version structure.
    """
    paths = derive_sandbox_paths(name)
    worktree_path = paths.worktree_path
    claude_config_path = paths.claude_config_path
    container_name = paths.container_name
    container_id = f"{container_name}-dev-1"

    # Check existence
    worktree_exists = worktree_path.is_dir()
    config_exists = claude_config_path.is_dir()

    # Docker status
    docker_status = _get_docker_status(container_name)

    # Tmux status
    tmux_status = "attached" if _tmux_session_exists(name) else "none"

    # Load metadata
    repo = ""
    branch = ""
    from_branch = ""
    mounts: list[str] = []
    copies: list[str] = []

    metadata = load_sandbox_metadata(name)
    if metadata:
        repo = metadata.get("repo_url", "")
        branch = metadata.get("branch", "")
        from_branch = metadata.get("from_branch", "")
        mounts = metadata.get("mounts", [])
        copies = metadata.get("copies", [])

    return {
        "name": name,
        "worktree": str(worktree_path),
        "worktree_exists": worktree_exists,
        "claude_config": str(claude_config_path),
        "claude_config_exists": config_exists,
        "container": container_id,
        "docker_status": docker_status,
        "tmux": tmux_status,
        "repo": repo,
        "branch": branch,
        "from_branch": from_branch,
        "mounts": mounts,
        "copies": copies,
    }


def _format_text_summary(name: str) -> str:
    """Format a one-line text summary for a sandbox.

    Args:
        name: Sandbox name.

    Returns:
        Formatted table row string.
    """
    info = _collect_sandbox_info(name)
    tmux_suffix = " [tmux]" if info["tmux"] == "attached" else ""
    return format_table_row(name, info["docker_status"], tmux_suffix)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


@click.command("list")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON")
def list_cmd(json_output: bool) -> None:
    """List all sandboxes."""
    worktrees_dir = get_worktrees_dir()

    if not worktrees_dir.is_dir():
        if json_output:
            click.echo("[]")
        else:
            click.echo(f"{BOLD}Sandboxes:{RESET}")
            click.echo("─" * 40)
        return

    # Collect all sandbox names
    sandbox_names: list[str] = []
    for worktree in sorted(worktrees_dir.iterdir()):
        if worktree.is_dir():
            sandbox_names.append(worktree.name)

    if json_output:
        # JSON output mode
        sandboxes = []
        for name in sandbox_names:
            info = _collect_sandbox_info(name)
            sandboxes.append(info)
        click.echo(json.dumps(sandboxes))
    else:
        # Text output mode
        click.echo(f"{BOLD}Sandboxes:{RESET}")
        click.echo("─" * 40)
        for name in sandbox_names:
            click.echo(_format_text_summary(name))
