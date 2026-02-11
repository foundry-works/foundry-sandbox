"""Refresh credentials command — sync credentials from host to running sandbox.

Migrated from commands/refresh-credentials.sh. Supports:
  - Direct mode: Syncs credential files from host to container
  - Isolation mode: Restarts unified-proxy to reload credentials
  - Auto-detection of sandbox from current directory
  - fzf selection fallback when no sandbox name is provided
  - --last flag to reuse last attached sandbox
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import click

from foundry_sandbox.commands._helpers import (
    auto_detect_sandbox as _auto_detect_sandbox,
    fzf_select_sandbox as _fzf_select_sandbox_shared,
    list_sandbox_names as _list_sandbox_names_shared,
)
from foundry_sandbox.docker import uses_credential_isolation as _uses_credential_isolation_shared
from foundry_sandbox.credential_setup import sync_runtime_credentials
from foundry_sandbox.constants import TIMEOUT_DOCKER_COMPOSE, get_worktrees_dir
from foundry_sandbox.docker import container_is_running, get_compose_command
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.state import load_last_attach, load_sandbox_metadata
from foundry_sandbox.utils import log_error, log_info
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
    click.echo("Syncing credentials to sandbox...")

    try:
        sync_runtime_credentials(container_id)
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        log_error(f"Failed to sync credentials: {exc}")
        sys.exit(1)

    click.echo("Credentials refreshed successfully.")


def _refresh_isolation_mode(name: str, container: str, override_file: str) -> None:
    """Refresh credentials in isolation mode by restarting unified-proxy.

    Args:
        name: Sandbox name.
        container: Container name prefix.
        override_file: Path to docker-compose override file.
    """
    click.echo("Restarting unified-proxy to reload credentials...")

    # Get compose command
    compose_cmd = get_compose_command(override_file, isolate_credentials=True)

    # Restart unified-proxy
    try:
        subprocess.run(
            compose_cmd + ["-p", container, "restart", "unified-proxy"],
            check=True,
            timeout=TIMEOUT_DOCKER_COMPOSE,
        )
        click.echo("Credentials refreshed (unified-proxy restarted).")
    except subprocess.CalledProcessError as exc:
        log_error(f"Failed to restart unified-proxy: {exc}")
        sys.exit(1)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log_error(f"Error restarting unified-proxy: {exc}")
        sys.exit(1)


@click.command("refresh-credentials")
@click.argument("name", required=False, default=None)
@click.option("--last", "-l", is_flag=True, help="Refresh last attached sandbox")
def refresh_creds(name: str | None, last: bool) -> None:
    """Refresh credentials for a running sandbox.

    Syncs credentials from host to container in direct mode, or restarts
    unified-proxy in isolation mode to reload credentials.

    NAME is the sandbox name. If not provided, will try to auto-detect from
    current directory or prompt with fzf.
    """

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

    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        log_error(name_error)
        sys.exit(1)

    # Derive paths
    paths = derive_sandbox_paths(name)
    container = paths.container_name
    override_file = paths.override_file

    # Load metadata
    metadata = load_sandbox_metadata(name)
    if not metadata:
        log_error(f"Failed to load sandbox metadata for '{name}'")
        sys.exit(1)

    # Check if container is running
    if not container_is_running(container):
        log_error(f"Sandbox '{name}' is not running")
        sys.exit(1)

    # Determine credential isolation mode
    uses_isolation = _check_isolation_mode(container)

    # Full container ID
    container_id = f"{container}-dev-1"

    # Refresh based on mode
    if uses_isolation:
        _refresh_isolation_mode(name, container, str(override_file))
    else:
        _refresh_direct_mode(container_id)
