"""Start command — start a stopped sandbox.

Delegates to `sbx run`. Verifies git safety server is running and
re-injects git wrapper if missing or tampered.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

import click

from foundry_sandbox.git_safety import (
    compute_wrapper_checksum,
    git_safety_server_is_running,
    git_safety_server_start,
    inject_git_wrapper,
    verify_wrapper_integrity,
)
from foundry_sandbox.sbx import sbx_check_available, sbx_exec, sbx_run, sbx_sandbox_exists
from foundry_sandbox.state import load_sandbox_metadata, patch_sandbox_metadata
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
@click.option("--watchdog", is_flag=True, help="Start wrapper integrity watchdog")
def start(name: str, watchdog: bool) -> None:
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

    # Ensure git safety server is running (fail closed)
    if not git_safety_server_is_running():
        click.echo("Starting git safety server...")
        try:
            git_safety_server_start()
        except OSError:
            click.echo(
                "Error: foundry-git-safety is not installed. "
                "Run: pip install foundry-git-safety[server]",
                err=True,
            )
            sys.exit(1)
        except Exception as exc:
            click.echo(f"Error: Failed to start git safety server: {exc}", err=True)
            sys.exit(1)

        if not git_safety_server_is_running():
            click.echo(
                "Error: Git safety server did not become healthy after start. "
                "Check `foundry-git-safety status` for details.",
                err=True,
            )
            sys.exit(1)

    # Start the sandbox
    click.echo(f"Starting sandbox: {name}...")
    try:
        sbx_run(name)
    except Exception as exc:
        click.echo(f"Error: Failed to start sandbox: {exc}", err=True)
        sys.exit(1)

    # Verify git wrapper integrity; re-inject on checksum mismatch or absence
    expected_checksum = metadata.get("wrapper_checksum", "")
    try:
        is_ok, _actual = verify_wrapper_integrity(
            name, expected_checksum=expected_checksum,
        )
    except FileNotFoundError:
        is_ok = True

    if not is_ok:
        sandbox_id = metadata.get("sbx_name", name)
        workspace_dir = metadata.get("workspace_dir", "/workspace")
        try:
            inject_git_wrapper(name, sandbox_id=sandbox_id, workspace_dir=workspace_dir)
            new_checksum = compute_wrapper_checksum()
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            patch_sandbox_metadata(
                name,
                wrapper_checksum=new_checksum,
                wrapper_last_verified=now,
            )
            log_info("Git wrapper re-injected (checksum mismatch)")
        except Exception as exc:
            log_warn(f"Failed to re-inject git wrapper: {exc}")
    else:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            patch_sandbox_metadata(name, wrapper_last_verified=now)
        except Exception:
            pass

    # Install pip requirements if configured
    pip_req = metadata.get("pip_requirements", "")
    if pip_req:
        _install_pip_requirements_sbx(name, pip_req)

    click.echo(f"Sandbox '{name}' started.")

    if watchdog:
        from foundry_sandbox.watchdog import start_watchdog
        start_watchdog()
        click.echo("Wrapper integrity watchdog started (30s poll interval).")
