"""Start command — start a stopped sandbox.

Delegates to `sbx run`. Verifies git safety server is running and
re-injects git wrapper if missing or tampered.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

import click

from foundry_sandbox.git_safety import (
    git_safety_server_is_running,
    git_safety_server_start,
    is_template_stale,
    repair_git_safety,
    verify_wrapper_integrity,
)
from foundry_sandbox.sbx import (
    bootstrap_packages,
    install_pip_requirements,
    sbx_check_available,
    sbx_run,
    sbx_sandbox_exists,
)
from foundry_sandbox.state import load_sandbox_metadata, patch_sandbox_metadata
from foundry_sandbox.utils import log_info
from foundry_sandbox.validate import validate_existing_sandbox_name


def _ensure_git_safety_server() -> None:
    """Start the git safety server if not running. Exits on failure."""
    if git_safety_server_is_running():
        return

    click.echo("Starting git safety server...")
    try:
        git_safety_server_start(deep_policy=True)
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



def start_sandbox(name: str, watchdog: bool = False) -> None:
    """Start a stopped sandbox (core logic, no CLI validation).

    Callers must ensure the sandbox name is valid and the sandbox exists.
    """
    # Ensure git safety server is running (fail closed)
    _ensure_git_safety_server()

    # Start the sandbox
    click.echo(f"Starting sandbox: {name}...")
    try:
        sbx_run(name)
    except Exception as exc:
        click.echo(f"Error: Failed to start sandbox: {exc}", err=True)
        sys.exit(1)

    # Verify git wrapper integrity; re-inject on checksum mismatch or absence
    metadata = load_sandbox_metadata(name) or {}
    expected_checksum = metadata.get("wrapper_checksum", "")
    needs_repair = False
    if is_template_stale():
        log_info("Template digest is stale — forcing re-provisioning of wrapper")
        needs_repair = True
    else:
        try:
            is_ok, _actual = verify_wrapper_integrity(
                name, expected_checksum=expected_checksum,
            )
        except FileNotFoundError:
            is_ok = False
        needs_repair = not is_ok

    if needs_repair:
        sandbox_id = metadata.get("sbx_name", name)
        workspace_dir = metadata.get("workspace_dir", "/workspace")
        result = repair_git_safety(
            name,
            sandbox_id=sandbox_id,
            workspace_dir=workspace_dir,
            expected_checksum=expected_checksum,
        )
        if result.success:
            log_info("Git wrapper re-injected (checksum mismatch)")
        else:
            click.echo(
                f"Error: Git wrapper re-injection failed: {result.error}. "
                "Sandbox started without git safety enforcement.",
                err=True,
            )
            patch_sandbox_metadata(name, git_safety_enabled=False)
    else:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            patch_sandbox_metadata(name, wrapper_last_verified=now)
        except Exception:
            pass

    # Install packages if configured
    packages = metadata.get("packages", {})
    if packages:
        bootstrap_packages(name, packages)
    else:
        pip_req = metadata.get("pip_requirements", "")
        if pip_req:
            install_pip_requirements(name, pip_req)

    click.echo(f"Sandbox '{name}' started.")

    if watchdog:
        from foundry_sandbox.watchdog import start_watchdog
        start_watchdog()
        click.echo("Wrapper integrity watchdog started (default poll interval).")


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

    metadata = load_sandbox_metadata(name) or {}
    sandbox_exists = sbx_sandbox_exists(name)

    if not sandbox_exists:
        if not metadata:
            click.echo(f"Error: Sandbox '{name}' not found", err=True)
            sys.exit(1)
        click.echo(
            f"Error: Sandbox '{name}' has metadata but no sbx sandbox. "
            "This indicates a corrupted or pre-0.21 state. "
            f"Destroy and recreate: cast destroy {name} && cast new <repo>",
            err=True,
        )
        sys.exit(1)

    start_sandbox(name, watchdog=watchdog)
