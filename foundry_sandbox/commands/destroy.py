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
from pathlib import Path

import click

from foundry_sandbox.constants import get_repos_dir
from foundry_sandbox.docker import compose_down, remove_hmac_volume, remove_stubs_volume
from foundry_sandbox.git_worktree import cleanup_sandbox_branch, remove_worktree
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.proxy import cleanup_proxy_registration
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import log_info, log_warn
from foundry_sandbox.validate import validate_existing_sandbox_name


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _repo_url_to_bare_path(repo_url: str) -> str:
    """Convert a repository URL to its bare-clone path under REPOS_DIR.

    Mirrors lib/utils.sh ``repo_to_path``.  Handles https://, git@, and
    local filesystem paths.

    Args:
        repo_url: Repository URL or local path.

    Returns:
        Absolute path string to the bare repository.
    """
    repos_dir = str(get_repos_dir())

    if not repo_url:
        return f"{repos_dir}/unknown.git"

    # Local filesystem path
    if repo_url.startswith(("~/", "/", "./", "../")):
        expanded = repo_url
        if expanded.startswith("~/"):
            expanded = str(Path.home()) + expanded[1:]
        p = Path(expanded)
        if p.exists():
            try:
                expanded = str(p.resolve())
            except OSError:
                pass
        # Strip leading slash for path construction
        stripped = expanded.lstrip("/")
        return f"{repos_dir}/local/{stripped}.git"

    # HTTPS or git@ URL
    path = repo_url
    path = path.removeprefix("https://")
    path = path.removeprefix("git@")
    path = path.replace(":", "/", 1) if ":" in path else path
    if path.endswith(".git"):
        path = path[:-4]
    return f"{repos_dir}/{path}.git"


def _tmux_session_name(name: str) -> str:
    """Return the tmux session name for a sandbox.

    Mirrors lib/tmux.sh ``tmux_session_name`` — which simply returns the
    sandbox name as-is.
    """
    return name


# ---------------------------------------------------------------------------
# Command
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
    # Derive paths
    # ------------------------------------------------------------------
    paths = derive_sandbox_paths(name)
    worktree_path = paths.worktree_path
    container = paths.container_name
    claude_config_path = paths.claude_config_path
    override_file = paths.override_file
    session = _tmux_session_name(name)

    # ------------------------------------------------------------------
    # Check SANDBOX_NONINTERACTIVE — treat as --yes
    # ------------------------------------------------------------------
    noninteractive = os.environ.get("SANDBOX_NONINTERACTIVE", "") == "1"
    skip_confirm = force or yes or noninteractive

    # ------------------------------------------------------------------
    # Confirmation prompt
    # ------------------------------------------------------------------
    if not skip_confirm:
        click.echo(f"This will destroy sandbox '{name}' including:")
        click.echo("  - Docker container and volumes")
        if not keep_worktree:
            click.echo(f"  - Worktree at {worktree_path}")
            click.echo(f"  - Claude config at {claude_config_path}")
        click.echo("")
        try:
            if not click.confirm("Are you sure?", default=False):
                click.echo("Aborted.")
                sys.exit(0)
        except click.Abort:
            click.echo("\nAborted.")
            sys.exit(0)

    click.echo(f"Destroying sandbox: {name}...")

    # ------------------------------------------------------------------
    # 1. Kill tmux session
    # ------------------------------------------------------------------
    try:
        subprocess.run(
            ["tmux", "kill-session", "-t", session],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        pass  # tmux may not be installed or session may not exist

    # ------------------------------------------------------------------
    # 2. Cleanup proxy registration (best effort)
    # ------------------------------------------------------------------
    try:
        container_id = f"{container}-dev-1"
        os.environ["CONTAINER_NAME"] = container
        cleanup_proxy_registration(container_id)
    except Exception:
        pass  # Proxy may not be running

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
    except Exception:
        pass  # Container may already be gone

    # ------------------------------------------------------------------
    # 4. Remove stubs volume (external, not removed by compose down -v)
    # ------------------------------------------------------------------
    try:
        remove_stubs_volume(container)
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 5. Remove HMAC secrets volume (git shadow mode)
    # ------------------------------------------------------------------
    try:
        remove_hmac_volume(container)
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 6. Remove credential isolation networks
    # ------------------------------------------------------------------
    for network_suffix in ("credential-isolation", "proxy-egress"):
        network_name = f"{container}_{network_suffix}"
        try:
            inspect_result = subprocess.run(
                ["docker", "network", "inspect", network_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if inspect_result.returncode == 0:
                subprocess.run(
                    ["docker", "network", "rm", network_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
        except Exception:
            pass

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
    except Exception:
        pass

    # ------------------------------------------------------------------
    # 8. Remove config directory
    # ------------------------------------------------------------------
    if not keep_worktree and claude_config_path.is_dir():
        try:
            log_info("Removing Claude config...")
            shutil.rmtree(claude_config_path)
        except Exception as exc:
            log_warn(f"Could not remove config directory: {exc}")

    # ------------------------------------------------------------------
    # 9. Remove worktree (unless --keep-worktree)
    # ------------------------------------------------------------------
    if not keep_worktree and worktree_path.is_dir():
        try:
            log_info("Removing worktree...")
            remove_worktree(str(worktree_path))
        except Exception as exc:
            log_warn(f"Could not remove worktree: {exc}")

    # ------------------------------------------------------------------
    # 10. Cleanup sandbox branch from bare repo
    #     (after worktree removal so the worktree-in-use check doesn't
    #     find our own worktree)
    # ------------------------------------------------------------------
    if destroy_branch and destroy_repo_url:
        try:
            bare_path = _repo_url_to_bare_path(destroy_repo_url)
            cleanup_sandbox_branch(destroy_branch, bare_path)
        except Exception as exc:
            log_warn(f"Could not cleanup branch: {exc}")

    click.echo(f"Sandbox '{name}' destroyed.")
