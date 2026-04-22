"""Destroy command — tear down a sandbox and clean up all resources.

Delegates to `sbx rm` for sandbox removal. Cleans up local resources
(config directory, branch cleanup, git safety registration).
"""

from __future__ import annotations

import os
import shutil
import sys

import click

from foundry_sandbox.git_safety import unregister_sandbox_from_git_safety
from foundry_sandbox.git import cleanup_sandbox_branch_repo
from foundry_sandbox.paths import (
    derive_sandbox_paths,
    resolve_host_worktree_path,
)
from foundry_sandbox.sbx import sbx_check_available, sbx_rm
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import log_info, log_warn
from foundry_sandbox.validate import validate_existing_sandbox_name


# ---------------------------------------------------------------------------
# Implementation (no Click dependency, no prompting)
# ---------------------------------------------------------------------------


def destroy_impl(
    name: str,
    keep_worktree: bool = False,
    best_effort: bool = True,
) -> None:
    """Destroy a sandbox and clean up all resources.

    This is the non-interactive implementation. It never prompts the user.

    Sbx owns worktree cleanup — this function handles branch deletion against
    the shared repo.

    Args:
        name: Sandbox name.
        keep_worktree: If True, keep the git worktree and config directory.
        best_effort: If True (default), catch and log cleanup errors.
            If False (strict), re-raise on first cleanup failure.

    Raises:
        ValueError: If name fails validation.
    """
    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        raise ValueError(f"Invalid sandbox name: {name_error}")

    paths = derive_sandbox_paths(name)
    claude_config_path = paths.claude_config_path

    # ------------------------------------------------------------------
    # 1. Load metadata BEFORE removing anything (needed for branch cleanup)
    # ------------------------------------------------------------------
    destroy_branch = ""
    host_worktree_path = ""
    try:
        metadata = load_sandbox_metadata(name)
        if metadata:
            destroy_branch = metadata.get("branch", "")
            host_worktree_path = metadata.get("host_worktree_path", "")
    except (OSError, ValueError):
        if not best_effort:
            raise

    # ------------------------------------------------------------------
    # 2. Remove sandbox via sbx (best effort)
    # ------------------------------------------------------------------
    try:
        sbx_rm(name)
    except Exception as exc:
        if not best_effort:
            raise
        log_warn(f"sbx rm failed: {exc}")

    # ------------------------------------------------------------------
    # 3. Unregister from git safety server (best effort)
    # ------------------------------------------------------------------
    try:
        unregister_sandbox_from_git_safety(name)
    except Exception as exc:
        if not best_effort:
            raise
        log_warn(f"Git safety unregister failed: {exc}")

    # ------------------------------------------------------------------
    # 4. Remove config directory
    # ------------------------------------------------------------------
    if not keep_worktree and claude_config_path.is_dir():
        try:
            log_info("Removing Claude config...")
            shutil.rmtree(claude_config_path)
        except OSError:
            try:
                os.chmod(str(claude_config_path), 0o755)
                shutil.rmtree(claude_config_path)
            except OSError as exc:
                if not best_effort:
                    raise
                log_warn(f"Could not remove config directory: {exc}")

    # ------------------------------------------------------------------
    # 5. Cleanup branch (sbx owns worktree removal)
    # ------------------------------------------------------------------
    if not keep_worktree:
        if destroy_branch and host_worktree_path:
            try:
                parts = host_worktree_path.split("/.sbx/")
                repo_root = parts[0] if parts else ""
                if repo_root:
                    cleanup_sandbox_branch_repo(destroy_branch, repo_root)
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
    sbx_check_available()

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
        workspace = resolve_host_worktree_path(name)
        click.echo(f"This will destroy sandbox '{name}' including:")
        click.echo("  - Sandbox container (sbx rm)")
        if not keep_worktree:
            click.echo(f"  - Worktree at {workspace}")
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
