"""Destroy command — tear down a sandbox and clean up all resources.

Migrated from commands/destroy.sh. Performs the following cleanup sequence:
  1. Kill tmux session
  2. Cleanup proxy registration
  3. Docker compose down (containers + volumes)
  4. Remove stubs volume
  5. Remove HMAC secrets volume
  6. Remove credential isolation networks
  7. Load metadata (before deleting config, needed for branch cleanup)
  8. Remove config directory
  9. Remove worktree (unless --keep-worktree)
  10. Cleanup sandbox branch
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import click

from foundry_sandbox.constants import TIMEOUT_LOCAL_CMD
from foundry_sandbox.docker import compose_down, proxy_cleanup as _proxy_cleanup, remove_hmac_volume, remove_sandbox_networks, remove_stubs_volume
from foundry_sandbox.git_worktree import cleanup_sandbox_branch, remove_worktree
from foundry_sandbox.paths import derive_sandbox_paths, repo_url_to_bare_path as _repo_url_to_bare_path
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.tmux import tmux_session_name as _tmux_session_name
from foundry_sandbox.utils import log_info, log_warn
from foundry_sandbox.validate import validate_existing_sandbox_name


# ---------------------------------------------------------------------------
# Implementation (no Click dependency, no prompting)
# ---------------------------------------------------------------------------


def destroy_impl(
    name: str,
    keep_worktree: bool = False,
    best_effort: bool = True,
    skip_tmux: bool = False,
    skip_branch_cleanup: bool = False,
) -> None:
    """Destroy a sandbox and clean up all resources.

    This is the non-interactive implementation. It never prompts the user.

    Args:
        name: Sandbox name (must pass validate_existing_sandbox_name).
        keep_worktree: If True, keep the git worktree and config directory.
        best_effort: If True (default), catch and log cleanup errors.
            If False (strict), re-raise on first cleanup failure.
        skip_tmux: If True, skip tmux session kill.
        skip_branch_cleanup: If True, skip branch cleanup from bare repo.

    Raises:
        ValueError: If name fails validation.
    """
    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        raise ValueError(f"Invalid sandbox name: {name_error}")

    paths = derive_sandbox_paths(name)
    worktree_path = paths.worktree_path
    container = paths.container_name
    claude_config_path = paths.claude_config_path
    override_file = paths.override_file
    session = _tmux_session_name(name)

    # ------------------------------------------------------------------
    # 1. Kill tmux session
    # ------------------------------------------------------------------
    if not skip_tmux:
        try:
            subprocess.run(
                ["tmux", "kill-session", "-t", session],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=TIMEOUT_LOCAL_CMD,
            )
        except (OSError, subprocess.SubprocessError):
            if not best_effort:
                raise

    # ------------------------------------------------------------------
    # 2. Cleanup proxy registration (best effort)
    # ------------------------------------------------------------------
    container_id = f"{container}-dev-1"
    try:
        _proxy_cleanup(container, container_id)
    except (OSError, subprocess.SubprocessError):
        if not best_effort:
            raise

    # ------------------------------------------------------------------
    # 3. Docker compose down (containers + volumes)
    # ------------------------------------------------------------------
    try:
        compose_down(
            worktree_path=str(worktree_path),
            claude_config_path=str(claude_config_path),
            container=container,
            override_file=str(override_file),
            remove_volumes=True,
        )
    except (OSError, subprocess.SubprocessError):
        if not best_effort:
            raise

    # ------------------------------------------------------------------
    # 4. Remove stubs volume (external, not removed by compose down -v)
    # ------------------------------------------------------------------
    try:
        remove_stubs_volume(container)
    except (OSError, subprocess.SubprocessError):
        if not best_effort:
            raise

    # ------------------------------------------------------------------
    # 5. Remove HMAC secrets volume (git shadow mode)
    # ------------------------------------------------------------------
    try:
        remove_hmac_volume(container)
    except (OSError, subprocess.SubprocessError):
        if not best_effort:
            raise

    # ------------------------------------------------------------------
    # 6. Remove credential isolation networks
    # ------------------------------------------------------------------
    try:
        remove_sandbox_networks(container)
    except (OSError, subprocess.SubprocessError):
        if not best_effort:
            raise

    # ------------------------------------------------------------------
    # 7. Load metadata BEFORE deleting config dir (needed for branch cleanup)
    # ------------------------------------------------------------------
    destroy_branch = ""
    destroy_repo_url = ""
    try:
        metadata = load_sandbox_metadata(name)
        if metadata:
            destroy_branch = metadata.get("branch", "")
            destroy_repo_url = metadata.get("repo_url", "")
    except (OSError, ValueError):
        if not best_effort:
            raise

    # ------------------------------------------------------------------
    # 8. Remove config directory
    # ------------------------------------------------------------------
    if not keep_worktree and claude_config_path.is_dir():
        try:
            log_info("Removing Claude config...")
            shutil.rmtree(claude_config_path)
        except OSError:
            # Try sudo as fallback for uid-mismatch files (Docker creates
            # files as uid 1000 which CI runner uid 1001 can't delete).
            try:
                subprocess.run(
                    ["sudo", "rm", "-rf", str(claude_config_path)],
                    check=True, capture_output=True, timeout=30,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                if not best_effort:
                    raise
                log_warn(f"Could not remove config directory: {exc}")

    # ------------------------------------------------------------------
    # 9. Remove worktree (unless --keep-worktree)
    # ------------------------------------------------------------------
    if not keep_worktree and worktree_path.is_dir():
        try:
            log_info("Removing worktree...")
            remove_worktree(str(worktree_path))
        except Exception as exc:
            if not best_effort:
                raise
            log_warn(f"Could not remove worktree: {exc}")

    # ------------------------------------------------------------------
    # 10. Cleanup sandbox branch from bare repo
    #     (after worktree removal so the worktree-in-use check doesn't
    #     find our own worktree)
    # ------------------------------------------------------------------
    if not skip_branch_cleanup and destroy_branch and destroy_repo_url:
        try:
            bare_path = _repo_url_to_bare_path(destroy_repo_url)
            cleanup_sandbox_branch(destroy_branch, bare_path)
        except Exception as exc:
            if not best_effort:
                raise
            log_warn(f"Could not cleanup branch: {exc}")


# ---------------------------------------------------------------------------
# Click Command
# ---------------------------------------------------------------------------


@click.command()
@click.argument("name")
@click.option("--keep-worktree", is_flag=True, help="Keep the git worktree")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def destroy(name: str, keep_worktree: bool, force: bool, yes: bool) -> None:
    """Destroy a sandbox and clean up all resources."""
    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        click.echo(f"Error: {name_error}", err=True)
        sys.exit(1)

    # ------------------------------------------------------------------
    # Confirmation
    # ------------------------------------------------------------------
    noninteractive = os.environ.get("SANDBOX_NONINTERACTIVE", "") == "1"
    skip_confirm = force or yes or noninteractive

    if not skip_confirm:
        paths = derive_sandbox_paths(name)
        click.echo(f"This will destroy sandbox '{name}' including:")
        click.echo("  - Docker container and volumes")
        if not keep_worktree:
            click.echo(f"  - Worktree at {paths.worktree_path}")
            click.echo(f"  - Claude config at {paths.claude_config_path}")
        click.echo("")
        try:
            if not click.confirm("Are you sure?", default=False):
                click.echo("Aborted.")
                sys.exit(0)
        except click.Abort:
            click.echo("\nAborted.")
            sys.exit(0)

    click.echo(f"Destroying sandbox: {name}...")

    destroy_impl(
        name,
        keep_worktree=keep_worktree,
        best_effort=True,
    )

    click.echo(f"Sandbox '{name}' destroyed.")
