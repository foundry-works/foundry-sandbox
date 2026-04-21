"""Start command — start a stopped sandbox.

Delegates to `sbx run`. Verifies git safety server is running and
re-injects git wrapper if missing or tampered. For migrated sandboxes
that have metadata but no sbx sandbox, runs full lazy provisioning.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click

from foundry_sandbox.git import ensure_bare_repo
from foundry_sandbox.git_safety import (
    FOUNDRY_TEMPLATE_TAG,
    ensure_foundry_template,
    git_safety_server_is_running,
    git_safety_server_start,
    is_template_stale,
    provision_git_safety,
    repair_git_safety,
    verify_wrapper_integrity,
)
from foundry_sandbox.git_worktree import create_worktree
from foundry_sandbox.paths import (
    path_worktree,
    repo_url_to_bare_path,
    strip_github_url,
)
from foundry_sandbox.sbx import (
    sbx_check_available,
    sbx_create,
    sbx_exec,
    sbx_run,
    sbx_sandbox_exists,
)
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


def _ensure_git_safety_server() -> None:
    """Start the git safety server if not running. Exits on failure."""
    if git_safety_server_is_running():
        return

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


def _provision_migrated_sandbox(name: str, metadata: dict[str, Any]) -> None:
    """Provision an sbx sandbox for a migrated-but-unprovisioned sandbox.

    Runs the same steps as `new_sbx_setup()` but reuses existing bare repos
    and worktrees from the 0.20.x layout when present.

    Only called when metadata exists, sbx sandbox does not, and
    git_safety_enabled is False.
    """
    repo_url = metadata.get("repo_url", "")
    if not repo_url:
        click.echo(
            f"Error: Cannot provision sandbox '{name}': metadata has no repo_url. "
            "This sandbox may have been created from a local path that is no "
            "longer available. Destroy and recreate: "
            f"cast destroy {name} && cast new <repo>",
            err=True,
        )
        sys.exit(1)

    branch = metadata.get("branch", "")
    from_branch = metadata.get("from_branch", "")
    agent = metadata.get("agent", "claude")
    allow_pr = metadata.get("allow_pr", False)
    template = metadata.get("template", "") or None

    click.echo(f"Provisioning migrated sandbox '{name}'...")

    # 1. Bare repo (idempotent — reuses existing)
    bare_path = repo_url_to_bare_path(repo_url)
    log_info("  Repository: fetching")
    ensure_bare_repo(repo_url, bare_path)

    # 2. Worktree (idempotent — pulls --ff-only on existing)
    worktree_path = path_worktree(name)
    log_info("  Worktree: creating/reusing")
    create_worktree(bare_path, str(worktree_path), branch, from_branch)

    # 3. Template + sbx create
    use_template = template if template and template.lower() != "none" else None
    if not use_template:
        use_template = FOUNDRY_TEMPLATE_TAG
    if use_template == FOUNDRY_TEMPLATE_TAG:
        log_info("  Template: ensuring foundry template is available...")
        if not ensure_foundry_template():
            log_warn("  Template build failed; falling back to runtime injection")
            use_template = None

    log_info(f"  Sandbox: creating sbx sandbox: {name}")
    try:
        sbx_create(
            name, agent, str(worktree_path), branch=branch, template=use_template
        )
    except Exception as exc:
        click.echo(f"Error: sbx create failed: {exc}", err=True)
        sys.exit(1)

    # 4. Git safety server
    _ensure_git_safety_server()

    # 5. Provision git safety (helper writes git_safety_enabled=True)
    log_info("  Git Safety: provisioning")
    repo_spec = strip_github_url(repo_url)
    result = provision_git_safety(
        name,
        sandbox_id=name,
        workspace_dir="/workspace",
        branch=branch,
        repo_spec=repo_spec,
        from_branch=from_branch,
        allow_pr=allow_pr,
        repo_root=str(worktree_path),
    )
    if not result.success:
        click.echo(
            f"Error: Git safety provisioning failed: {result.error}. "
            "Sandbox created without git safety enforcement.",
            err=True,
        )
        sys.exit(1)

    # 6. User service env injection
    try:
        from foundry_sandbox.user_services import get_proxy_env_overrides

        user_service_overrides = get_proxy_env_overrides()
        if user_service_overrides:
            lines = [f"export {k}={v}" for k, v in sorted(user_service_overrides.items())]
            env_script = "\n".join(lines) + "\n"
            sbx_exec(
                name,
                ["tee", "/etc/profile.d/foundry-user-services.sh"],
                user="root",
                input=env_script,
                quiet=True,
            )
            sbx_exec(
                name,
                ["chmod", "644", "/etc/profile.d/foundry-user-services.sh"],
                user="root",
                quiet=True,
            )
    except Exception as exc:
        log_warn(f"User service env injection failed: {exc}")

    # 7. Copy files
    copies = metadata.get("copies", [])
    for copy_spec in copies:
        parts = copy_spec.split(":", 1)
        if len(parts) != 2:
            log_warn(f"Invalid --copy spec (expected host:container): {copy_spec}")
            continue
        host_path, container_path = parts
        if not Path(host_path).exists():
            log_warn(f"Copy source not found: {host_path}")
            continue
        try:
            content = Path(host_path).read_text()
            sbx_exec(name, ["tee", container_path], user="root", input=content, quiet=True)
        except Exception as exc:
            log_warn(f"Failed to copy {host_path}: {exc}")

    click.echo(f"Provisioning complete for '{name}'.")


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
        if metadata.get("git_safety_enabled") is False:
            # Migrated sandbox — needs full provisioning
            _provision_migrated_sandbox(name, metadata)
            # After provisioning, sandbox is created but not running.
            # Fall through to normal start path.
        else:
            # Metadata claims provisioned but sbx sandbox is missing — corrupted.
            click.echo(
                f"Error: Sandbox '{name}' metadata claims it was provisioned "
                "(git_safety_enabled=True) but the sbx sandbox does not exist. "
                "This indicates a corrupted state. "
                f"Run: cast destroy {name} && cast new <repo> <branch>",
                err=True,
            )
            sys.exit(1)

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

    # Install pip requirements if configured
    pip_req = metadata.get("pip_requirements", "")
    if pip_req:
        _install_pip_requirements_sbx(name, pip_req)

    click.echo(f"Sandbox '{name}' started.")

    if watchdog:
        from foundry_sandbox.watchdog import start_watchdog
        start_watchdog()
        click.echo("Wrapper integrity watchdog started (30s poll interval).")
