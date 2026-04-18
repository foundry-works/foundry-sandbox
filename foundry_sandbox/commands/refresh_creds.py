"""Refresh credentials command — sync credentials from host to running sandbox.

Migrated from commands/refresh-credentials.sh. Supports:
  - Direct mode: Syncs credential files from host to container
  - Isolation mode: Recreates unified-proxy to reload credentials
  - Auto-detection of sandbox from current directory
  - fzf selection fallback when no sandbox name is provided
  - --last flag to reuse last attached sandbox
  - --all flag to refresh all running sandboxes
"""

from __future__ import annotations

import subprocess
import sys

import click

from foundry_sandbox.commands._helpers import (
    auto_detect_sandbox as _auto_detect_sandbox,
    fzf_select_sandbox as _fzf_select_sandbox_shared,
    list_sandbox_names as _list_sandbox_names_shared,
)
from foundry_sandbox.docker import uses_credential_isolation as _uses_credential_isolation_shared
from foundry_sandbox.credential_setup import sync_runtime_credentials
from foundry_sandbox.constants import TIMEOUT_DOCKER_COMPOSE
from foundry_sandbox.docker import container_is_running, get_compose_command
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.state import load_last_attach, load_sandbox_metadata
from foundry_sandbox.utils import log_error
from foundry_sandbox.validate import validate_existing_sandbox_name


def _fzf_select_sandbox() -> str | None:
    """Interactively select a sandbox using fzf."""
    return _fzf_select_sandbox_shared()


def _list_sandboxes_simple() -> None:
    """Print simple list of sandboxes."""
    sandboxes = _list_sandbox_names_shared()
    if sandboxes:
        click.echo("Available sandboxes:")
        for name in sandboxes:
            click.echo(f"  - {name}")
    else:
        click.echo("No sandboxes found.")


def _check_isolation_mode(container: str) -> bool:
    """Check if credential isolation is enabled for this sandbox."""
    return _uses_credential_isolation_shared(container)


def _refresh_direct_mode(container_id: str) -> None:
    """Refresh credentials in direct mode by syncing from host.

    Args:
        container_id: Full container ID (e.g., container-dev-1).
    """
    click.echo("  Syncing credentials to sandbox...")

    try:
        sync_runtime_credentials(container_id)
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        raise RuntimeError(f"Failed to sync credentials: {exc}") from exc

    click.echo("  Credentials refreshed successfully.")


def _refresh_isolation_mode(name: str, container: str, override_file: str) -> None:
    """Refresh credentials in isolation mode by recreating unified-proxy.

    Uses ``up --force-recreate`` instead of ``restart`` so the container is
    fully recreated.  This guarantees that bind-mounted credential files
    (including read-only mounts like Gemini oauth_creds.json) are re-read
    from the host filesystem on startup.

    Args:
        name: Sandbox name.
        container: Container name prefix.
        override_file: Path to docker-compose override file.
    """
    click.echo("  Recreating unified-proxy to reload credentials...")

    # Get compose command
    compose_cmd = get_compose_command(override_file, isolate_credentials=True)

    # Recreate unified-proxy (force-recreate ensures fresh bind mounts)
    try:
        subprocess.run(
            compose_cmd + [
                "-p", container,
                "up", "-d", "--force-recreate", "--no-deps", "unified-proxy",
            ],
            check=True,
            timeout=TIMEOUT_DOCKER_COMPOSE,
        )
        click.echo("  Credentials refreshed (unified-proxy recreated).")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Failed to recreate unified-proxy: {exc}") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Error recreating unified-proxy: {exc}") from exc


def _refresh_one(name: str) -> bool:
    """Refresh credentials for a single sandbox.

    Returns:
        True on success, False on failure (error is logged).
    """
    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        log_error(f"{name}: {name_error}")
        return False

    paths = derive_sandbox_paths(name)
    container = paths.container_name
    override_file = paths.override_file

    metadata = load_sandbox_metadata(name)
    if not metadata:
        log_error(f"{name}: failed to load metadata")
        return False

    if not container_is_running(container):
        log_error(f"{name}: not running")
        return False

    uses_isolation = _check_isolation_mode(container)
    container_id = f"{container}-dev-1"

    try:
        if uses_isolation:
            _refresh_isolation_mode(name, container, str(override_file))
        else:
            _refresh_direct_mode(container_id)
    except RuntimeError as exc:
        log_error(f"{name}: {exc}")
        return False

    return True


def _refresh_all() -> None:
    """Refresh credentials for all running sandboxes."""
    sandboxes = _list_sandbox_names_shared()
    if not sandboxes:
        click.echo("No sandboxes found.")
        return

    # Filter to running sandboxes
    running = []
    for name in sandboxes:
        paths = derive_sandbox_paths(name)
        if container_is_running(paths.container_name):
            running.append(name)

    if not running:
        click.echo("No running sandboxes found.")
        return

    click.echo(f"Refreshing credentials for {len(running)} running sandbox(es)...\n")
    ok = 0
    failed = 0
    for name in running:
        click.echo(f"[{name}]")
        if _refresh_one(name):
            ok += 1
        else:
            failed += 1
        click.echo("")

    click.echo(f"Done: {ok} succeeded, {failed} failed.")
    if failed:
        sys.exit(1)


@click.command("refresh-credentials")
@click.argument("name", required=False, default=None)
@click.option("--last", "-l", is_flag=True, help="Refresh last attached sandbox")
@click.option("--all", "all_sandboxes", is_flag=True, help="Refresh all running sandboxes")
def refresh_creds(name: str | None, last: bool, all_sandboxes: bool) -> None:
    """Refresh credentials for a running sandbox.

    Syncs credentials from host to container in direct mode, or recreates
    unified-proxy in isolation mode to reload credentials.

    NAME is the sandbox name. If not provided, will try to auto-detect from
    current directory or prompt with fzf.

    Use --all to refresh every running sandbox at once.
    """

    # --all mode: iterate over all running sandboxes
    if all_sandboxes:
        if name or last:
            log_error("--all cannot be combined with NAME or --last")
            sys.exit(1)
        _refresh_all()
        return

    # Handle --last flag
    if last:
        name = load_last_attach()
        if not name:
            log_error("No last attached sandbox found.")
            sys.exit(1)
        click.echo(f"Refreshing credentials for: {name}")

    # Auto-detect from current directory if no name
    if not name:
        name = _auto_detect_sandbox()

    # fzf selection fallback
    if not name:
        name = _fzf_select_sandbox()
        if not name:
            click.echo("Usage: cast refresh-credentials <sandbox-name>")
            click.echo("")
            _list_sandboxes_simple()
            sys.exit(1)

    click.echo(f"[{name}]")
    if not _refresh_one(name):
        sys.exit(1)
