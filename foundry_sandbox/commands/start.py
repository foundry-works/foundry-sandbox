"""Start command — start a stopped sandbox.

Delegates to `sbx run`. Verifies git safety server is running and
re-injects git wrapper if missing.
"""

from __future__ import annotations

import sys

import click

from foundry_sandbox.git_safety import (
    git_safety_server_is_running,
    git_safety_server_start,
    inject_git_wrapper,
    verify_git_wrapper,
)
from foundry_sandbox.sbx import sbx_check_available, sbx_exec, sbx_run, sbx_sandbox_exists
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import log_info, log_warn
from foundry_sandbox.validate import validate_existing_sandbox_name


def _install_pip_requirements_sbx(name: str, requirements: str) -> None:
    """Install pip requirements inside an sbx sandbox."""
    log_info(f"Installing pip requirements: {requirements}")
    try:
        sbx_exec(name, ["pip", "install", "-r", requirements])
    except Exception as exc:
        log_warn(f"Failed to install pip requirements: {exc}")


@click.command()
@click.argument("name")
def start(name: str) -> None:
    """Start a stopped sandbox."""
    sbx_check_available()

    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        click.echo(f"Error: {name_error}", err=True)
        sys.exit(1)

    if not sbx_sandbox_exists(name):
        click.echo(f"Error: Sandbox '{name}' not found in sbx", err=True)
        sys.exit(1)

    metadata = load_sandbox_metadata(name) or {}

    # Ensure git safety server is running
    if not git_safety_server_is_running():
        click.echo("Starting git safety server...")
        try:
            git_safety_server_start()
        except Exception as exc:
            log_warn(f"Failed to start git safety server: {exc}")

    # Start the sandbox
    click.echo(f"Starting sandbox: {name}...")
    try:
        sbx_run(name)
    except Exception as exc:
        click.echo(f"Error: Failed to start sandbox: {exc}", err=True)
        sys.exit(1)

    # Verify git wrapper is installed; re-inject if missing
    if not verify_git_wrapper(name):
        sandbox_id = metadata.get("sbx_name", name)
        workspace_dir = metadata.get("workspace_dir", "/workspace")
        try:
            inject_git_wrapper(name, sandbox_id=sandbox_id, workspace_dir=workspace_dir)
        except Exception as exc:
            log_warn(f"Failed to inject git wrapper: {exc}")

    # Install pip requirements if configured
    pip_req = metadata.get("pip_requirements", "")
    if pip_req:
        _install_pip_requirements_sbx(name, pip_req)

    click.echo(f"Sandbox '{name}' started.")
