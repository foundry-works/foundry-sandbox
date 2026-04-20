"""SBX-specific sandbox creation logic.

Replaces new_setup.py's docker-compose-based creation with sbx-based creation.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from foundry_sandbox.git import ensure_bare_repo
from foundry_sandbox.git_safety import (
    FOUNDRY_TEMPLATE_TAG,
    compute_wrapper_checksum,
    ensure_foundry_template,
    generate_hmac_secret,
    git_safety_server_is_running,
    git_safety_server_start,
    inject_git_wrapper,
    register_sandbox_with_git_safety,
    write_hmac_secret_to_worktree,
    write_hmac_secret_for_server,
)
from foundry_sandbox.git_worktree import create_worktree
from foundry_sandbox.paths import ensure_dir
from foundry_sandbox.sbx import sbx_check_available, sbx_create, sbx_exec, sbx_rm
from foundry_sandbox.state import write_sandbox_metadata
from foundry_sandbox.utils import log_info, log_section, log_warn
from foundry_sandbox.paths import strip_github_url


class SetupError(Exception):
    """Raised when sandbox setup fails."""


def _install_pip_requirements_sbx(name: str, requirements: str) -> None:
    """Install pip requirements inside an sbx sandbox."""
    try:
        sbx_exec(name, ["pip", "install", "-r", requirements])
    except Exception as exc:
        log_warn(f"Failed to install pip requirements: {exc}")


def new_sbx_setup(
    *,
    repo_url: str,
    bare_path: str,
    worktree_path: Path,
    branch: str,
    from_branch: str,
    name: str,
    agent: str,
    claude_config_path: Path,
    copies: list[str],
    allow_pr: bool,
    pip_requirements: str,
    with_opencode: bool,
    with_zai: bool,
    wd: str,
    template: str | None = FOUNDRY_TEMPLATE_TAG,
) -> None:
    """Create a new sbx-based sandbox.

    Steps:
    1. Check sbx available
    2. Clone/fetch bare repo
    3. Create worktree
    4. Ensure template + create sbx sandbox
    5. Start git safety server if needed
    6. Generate HMAC secret and register with git safety
    7. Inject git wrapper env vars
    8. Copy files, install pip requirements
    9. Write metadata
    """
    # ------------------------------------------------------------------
    # 1. Check sbx
    # ------------------------------------------------------------------
    sbx_check_available()

    # ------------------------------------------------------------------
    # 2. Clone/fetch bare repo
    # ------------------------------------------------------------------
    log_section("Repository")
    ensure_bare_repo(repo_url, bare_path)

    # ------------------------------------------------------------------
    # 3. Create worktree
    # ------------------------------------------------------------------
    log_info(f"Creating worktree for branch: {branch}")
    create_worktree(bare_path, str(worktree_path), branch, from_branch)

    if not worktree_path.is_dir():
        raise SetupError(f"Worktree creation failed: {worktree_path}")

    # ------------------------------------------------------------------
    # 4. Ensure template exists, then create sbx sandbox
    # ------------------------------------------------------------------
    log_section("Sandbox")
    use_template = template if template and template.lower() != "none" else None
    if use_template:
        log_info("Ensuring foundry template is available...")
        if not ensure_foundry_template():
            log_warn("Template build failed; falling back to runtime injection")
            use_template = None
    log_info(f"Creating sbx sandbox: {name}")
    try:
        sbx_create(
            name, agent, str(worktree_path), branch=branch, template=use_template
        )
    except Exception as exc:
        raise SetupError(f"sbx create failed: {exc}") from exc

    # ------------------------------------------------------------------
    # 5. Start git safety server if needed
    # ------------------------------------------------------------------
    log_section("Git Safety")
    if not git_safety_server_is_running():
        log_info("Starting git safety server...")
        try:
            git_safety_server_start()
        except Exception as exc:
            log_warn(f"Git safety server start failed: {exc}")

    # ------------------------------------------------------------------
    # 6. Generate HMAC secret and register
    # ------------------------------------------------------------------
    hmac_secret = generate_hmac_secret()
    write_hmac_secret_to_worktree(worktree_path, hmac_secret)
    write_hmac_secret_for_server(name, hmac_secret)

    repo_spec = strip_github_url(repo_url)
    register_sandbox_with_git_safety(
        name,
        branch=branch,
        repo_spec=repo_spec,
        from_branch=from_branch,
        allow_pr=allow_pr,
    )

    # ------------------------------------------------------------------
    # 7. Inject git wrapper
    # ------------------------------------------------------------------
    log_info("Injecting git wrapper...")
    try:
        inject_git_wrapper(name, sandbox_id=name, workspace_dir="/workspace")
    except Exception as exc:
        log_warn(f"Git wrapper injection failed: {exc}")

    wrapper_checksum = ""
    try:
        wrapper_checksum = compute_wrapper_checksum()
    except FileNotFoundError:
        pass

    # ------------------------------------------------------------------
    # 7.5. Inject user service environment overrides
    # ------------------------------------------------------------------
    user_service_overrides: dict[str, str] = {}
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
            log_info(f"Injected {len(user_service_overrides)} user service proxy URLs")
    except Exception as exc:
        log_warn(f"User service env injection failed: {exc}")

    # ------------------------------------------------------------------
    # 8. Copy files and install pip requirements
    # ------------------------------------------------------------------
    if copies:
        log_section("Files")
        for copy_spec in copies:
            parts = copy_spec.split(":", 1)
            if len(parts) != 2:
                log_warn(f"Invalid --copy spec (expected host:container): {copy_spec}")
                continue
            host_path, container_path = parts
            if not os.path.exists(host_path):
                log_warn(f"Copy source not found: {host_path}")
                continue
            try:
                content = Path(host_path).read_text()
                sbx_exec(name, ["tee", container_path], user="root", input=content, quiet=True)
            except Exception as exc:
                log_warn(f"Failed to copy {host_path}: {exc}")

    if pip_requirements:
        log_section("Dependencies")
        _install_pip_requirements_sbx(name, pip_requirements)

    # ------------------------------------------------------------------
    # 9. Write metadata
    # ------------------------------------------------------------------
    ensure_dir(claude_config_path)
    write_sandbox_metadata(
        name,
        sbx_name=name,
        agent=agent,
        repo_url=repo_url,
        branch=branch,
        from_branch=from_branch,
        git_safety_enabled=True,
        workspace_dir="/workspace",
        working_dir=wd,
        pip_requirements=pip_requirements,
        allow_pr=allow_pr,
        enable_opencode=with_opencode,
        enable_zai=with_zai,
        copies=copies,
        template=use_template or "",
        user_services=user_service_overrides,
        wrapper_checksum=wrapper_checksum,
    )


def rollback_new_sbx(
    worktree_path: Path,
    claude_config_path: Path,
    name: str,
) -> None:
    """Clean up partial sandbox resources on failure."""
    # Remove sbx sandbox (best effort)
    try:
        sbx_rm(name)
    except Exception:
        pass

    # Remove worktree
    if worktree_path.is_dir():
        try:
            shutil.rmtree(worktree_path)
        except OSError:
            pass

    # Remove config directory
    if claude_config_path.is_dir():
        try:
            shutil.rmtree(claude_config_path)
        except OSError:
            pass
