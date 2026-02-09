"""Destroy-all command — tear down all sandboxes and clean up resources.

Migrated from commands/destroy-all.sh. Performs the following for each sandbox:
  1. Kill tmux session
  2. Docker compose down (containers + volumes)
  3. Remove credential isolation networks
  4. Remove config directory (unless --keep-worktree)
  5. Remove worktree (unless --keep-worktree)
  6. Final cleanup: remove orphaned sandbox networks

Requires double confirmation:
  1. "Are you sure you want to destroy all sandboxes? [y/N]"
  2. Type 'destroy all' to confirm
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

import click

from foundry_sandbox.constants import get_worktrees_dir
from foundry_sandbox.docker import compose_down
from foundry_sandbox.git_worktree import remove_worktree
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.utils import log_warn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tmux_session_name(name: str) -> str:
    """Return the tmux session name for a sandbox.

    Mirrors lib/tmux.sh ``tmux_session_name`` — which simply returns the
    sandbox name as-is.
    """
    return name


def _list_all_sandboxes() -> list[str]:
    """List all sandbox names by scanning WORKTREES_DIR.

    Returns:
        List of sandbox names (directory basenames in WORKTREES_DIR).
    """
    worktrees_dir = get_worktrees_dir()
    if not worktrees_dir.exists():
        return []

    sandboxes = []
    for entry in worktrees_dir.iterdir():
        if entry.is_dir():
            sandboxes.append(entry.name)

    return sorted(sandboxes)


def _remove_network(network_name: str) -> bool:
    """Remove a Docker network if it exists.

    Args:
        network_name: Name of the network to remove.

    Returns:
        True if network was removed, False otherwise.
    """
    try:
        # Check if network exists
        inspect_result = subprocess.run(
            ["docker", "network", "inspect", network_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if inspect_result.returncode == 0:
            # Network exists, try to remove it
            rm_result = subprocess.run(
                ["docker", "network", "rm", network_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return rm_result.returncode == 0
    except Exception:
        pass
    return False


def _cleanup_orphaned_networks() -> int:
    """Clean up orphaned sandbox networks matching the pattern.

    Removes networks matching: sandbox-.*_(credential-isolation|proxy-egress)

    Returns:
        Count of orphaned networks cleaned up.
    """
    try:
        # List all docker networks
        result = subprocess.run(
            ["docker", "network", "ls", "--format", "{{.Name}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
        if result.returncode != 0:
            return 0

        # Filter by pattern
        pattern = re.compile(r'^sandbox-.*_(credential-isolation|proxy-egress)$')
        orphaned_count = 0

        for line in result.stdout.splitlines():
            network_name = line.strip()
            if network_name and pattern.match(network_name):
                if _remove_network(network_name):
                    orphaned_count += 1

        return orphaned_count
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


@click.command()
@click.option("--keep-worktree", is_flag=True, help="Keep the git worktrees and configs")
def destroy_all(keep_worktree: bool) -> None:
    """Destroy all sandboxes and clean up all resources."""

    # ------------------------------------------------------------------
    # List all sandboxes
    # ------------------------------------------------------------------
    sandboxes = _list_all_sandboxes()

    if not sandboxes:
        click.echo("No sandboxes to destroy.")
        sys.exit(0)

    # ------------------------------------------------------------------
    # Check SANDBOX_NONINTERACTIVE — skip confirmations in CI
    # ------------------------------------------------------------------
    noninteractive = os.environ.get("SANDBOX_NONINTERACTIVE", "") == "1"
    skip_confirm = noninteractive

    # ------------------------------------------------------------------
    # Show what will be destroyed
    # ------------------------------------------------------------------
    click.echo(f"This will destroy ALL sandboxes ({len(sandboxes)} total):")
    for name in sandboxes:
        click.echo(f"  - {name}")
    click.echo("")
    click.echo("Including:")
    click.echo("  - All Docker containers and volumes")
    if not keep_worktree:
        click.echo("  - All worktrees")
        click.echo("  - All Claude configs")
    click.echo("")

    # ------------------------------------------------------------------
    # First confirmation
    # ------------------------------------------------------------------
    if not skip_confirm:
        try:
            if not click.confirm("Are you sure you want to destroy all sandboxes?", default=False):
                click.echo("Aborted.")
                sys.exit(0)
        except click.Abort:
            click.echo("\nAborted.")
            sys.exit(0)

        # ------------------------------------------------------------------
        # Second confirmation - must type 'destroy all'
        # ------------------------------------------------------------------
        try:
            response = click.prompt("Type 'destroy all' to confirm", type=str)
            if response != "destroy all":
                click.echo("Aborted.")
                sys.exit(0)
        except click.Abort:
            click.echo("\nAborted.")
            sys.exit(0)

    # ------------------------------------------------------------------
    # Destroy each sandbox
    # ------------------------------------------------------------------
    failed = []

    for name in sandboxes:
        click.echo("")
        click.echo(f"Destroying sandbox: {name}...")

        # Derive paths
        paths = derive_sandbox_paths(name)
        worktree_path = paths.worktree_path
        container = paths.container_name
        claude_config_path = paths.claude_config_path
        override_file = paths.override_file
        session = _tmux_session_name(name)

        # 1. Kill tmux session (best effort)
        try:
            subprocess.run(
                ["tmux", "kill-session", "-t", session],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except Exception:
            pass

        # 2. Docker compose down (best effort)
        try:
            compose_down(
                worktree_path=str(worktree_path),
                claude_config_path=str(claude_config_path),
                container=container,
                override_file=str(override_file),
                remove_volumes=True,
            )
        except Exception:
            pass  # Container may already be gone

        # 3. Remove config directory (unless --keep-worktree)
        if not keep_worktree and claude_config_path.is_dir():
            try:
                shutil.rmtree(claude_config_path)
            except Exception:
                pass  # Best effort

        # 4. Remove worktree (unless --keep-worktree)
        if not keep_worktree and worktree_path.is_dir():
            try:
                remove_worktree(str(worktree_path))
            except Exception as exc:
                log_warn(f"Failed to remove worktree for '{name}': {exc}")
                failed.append(name)
                continue  # Skip to next sandbox

        # 5. Remove credential isolation networks for this sandbox
        for network_suffix in ("credential-isolation", "proxy-egress"):
            network_name = f"{container}_{network_suffix}"
            _remove_network(network_name)

        click.echo(f"Sandbox '{name}' destroyed.")

    # ------------------------------------------------------------------
    # Final cleanup: remove orphaned sandbox networks
    # ------------------------------------------------------------------
    orphaned_count = _cleanup_orphaned_networks()

    # ------------------------------------------------------------------
    # Print summary
    # ------------------------------------------------------------------
    click.echo("")
    click.echo(f"Destroyed {len(sandboxes)} sandbox(es).")
    if orphaned_count > 0:
        click.echo(f"Cleaned up {orphaned_count} orphaned network(s).")

    # ------------------------------------------------------------------
    # Report failures and exit
    # ------------------------------------------------------------------
    if failed:
        click.echo(f"Failed to fully remove worktrees for: {' '.join(failed)}")
        sys.exit(1)
