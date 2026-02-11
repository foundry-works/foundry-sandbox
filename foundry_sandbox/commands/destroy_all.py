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
import shutil
import subprocess
import sys

import click

from foundry_sandbox.constants import TIMEOUT_LOCAL_CMD, get_worktrees_dir
from foundry_sandbox.docker import cleanup_orphaned_networks as _cleanup_orphaned_networks_shared, compose_down, proxy_cleanup as _proxy_cleanup, remove_hmac_volume, remove_sandbox_networks, remove_stubs_volume
from foundry_sandbox.git_worktree import cleanup_sandbox_branch, remove_worktree
from foundry_sandbox.paths import derive_sandbox_paths, repo_url_to_bare_path as _repo_url_to_bare_path
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.tmux import tmux_session_name as _tmux_session_name
from foundry_sandbox.utils import log_warn
from foundry_sandbox.commands._helpers import list_sandbox_names as _list_sandbox_names


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _list_all_sandboxes() -> list[str]:
    """List all sandbox names by scanning WORKTREES_DIR."""
    return _list_sandbox_names()


def _cleanup_orphaned_networks() -> int:
    """Clean up orphaned sandbox networks matching the pattern.

    Returns:
        Count of orphaned networks cleaned up.
    """
    return len(_cleanup_orphaned_networks_shared(skip_confirm=True))


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
                timeout=TIMEOUT_LOCAL_CMD,
            )
        except (OSError, subprocess.SubprocessError):
            pass

        # 2. Cleanup proxy registration (best effort)
        container_id = f"{container}-dev-1"
        _proxy_cleanup(container, container_id)

        # 3. Docker compose down (best effort)
        try:
            compose_down(
                worktree_path=str(worktree_path),
                claude_config_path=str(claude_config_path),
                container=container,
                override_file=str(override_file),
                remove_volumes=True,
            )
        except (OSError, subprocess.SubprocessError):
            pass  # Container may already be gone

        # 4. Remove stubs volume (best effort)
        try:
            remove_stubs_volume(container)
        except (OSError, subprocess.SubprocessError):
            pass

        # 5. Remove HMAC secrets volume (best effort)
        try:
            remove_hmac_volume(container)
        except (OSError, subprocess.SubprocessError):
            pass

        # 6. Remove credential isolation networks for this sandbox
        remove_sandbox_networks(container)

        # 7. Load metadata BEFORE deleting config dir (needed for branch cleanup)
        destroy_branch = ""
        destroy_repo_url = ""
        try:
            metadata = load_sandbox_metadata(name)
            if metadata:
                destroy_branch = metadata.get("branch", "")
                destroy_repo_url = metadata.get("repo_url", "")
        except (OSError, ValueError):
            pass

        # 8. Remove config directory (unless --keep-worktree)
        if not keep_worktree and claude_config_path.is_dir():
            try:
                shutil.rmtree(claude_config_path)
            except OSError:
                pass  # Best effort

        # 9. Remove worktree (unless --keep-worktree)
        if not keep_worktree and worktree_path.is_dir():
            try:
                remove_worktree(str(worktree_path))
            except Exception as exc:
                log_warn(f"Failed to remove worktree for '{name}': {exc}")
                failed.append(name)
                continue  # Skip to next sandbox

        # 10. Cleanup sandbox branch from bare repo
        if destroy_branch and destroy_repo_url:
            try:
                bare_path = _repo_url_to_bare_path(destroy_repo_url)
                cleanup_sandbox_branch(destroy_branch, bare_path)
            except Exception as exc:
                log_warn(f"Could not cleanup branch for '{name}': {exc}")

        click.echo(f"Sandbox '{name}' destroyed.")

    # ------------------------------------------------------------------
    # Final cleanup: remove orphaned sandbox networks
    # ------------------------------------------------------------------
    orphaned_count = _cleanup_orphaned_networks()

    # ------------------------------------------------------------------
    # Print summary
    # ------------------------------------------------------------------
    click.echo("")
    click.echo(f"Destroyed {len(sandboxes) - len(failed)} sandbox(es).")
    if orphaned_count > 0:
        click.echo(f"Cleaned up {orphaned_count} orphaned network(s).")

    # ------------------------------------------------------------------
    # Report failures and exit
    # ------------------------------------------------------------------
    if failed:
        click.echo(f"Failed to fully remove worktrees for: {' '.join(failed)}")
        sys.exit(1)
