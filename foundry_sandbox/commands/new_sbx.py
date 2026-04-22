"""SBX-specific sandbox creation logic.

Replaces new_setup.py's docker-compose-based creation with sbx-based creation.
Delegates worktree management to sbx — cast passes the repo root and sbx
creates the worktree under ``<repo_root>/.sbx/<name>-worktrees/<branch>/``.
"""

from __future__ import annotations

import os
from pathlib import Path

from foundry_sandbox.atomic_io import file_lock
from foundry_sandbox.git_safety import (
    FOUNDRY_TEMPLATE_TAG,
    ensure_foundry_template,
    git_safety_server_is_running,
    git_safety_server_start,
    provision_git_safety,
)
from foundry_sandbox.paths import ensure_dir
from foundry_sandbox.sbx import (
    sbx_check_available,
    sbx_create,
    sbx_exec,
    sbx_get_workspace_info,
    sbx_rm,
    sbx_template_ls,
    sbx_worktree_path,
)
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
    repo_root: str,
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
) -> str:
    """Create a new sbx-based sandbox.

    Steps:
    1. Check sbx available
    2. Ensure template + create sbx sandbox (sbx manages worktree)
    3. Start git safety server if needed
    4. Generate HMAC secret and register with git safety
    5. Inject git wrapper env vars
    6. Copy files, install pip requirements
    7. Write metadata

    Returns:
        The workspace_path (host-side path to the sbx-managed worktree).
    """
    # ------------------------------------------------------------------
    # 1. Check sbx
    # ------------------------------------------------------------------
    sbx_check_available()

    # ------------------------------------------------------------------
    # 2. Ensure template exists, then create sbx sandbox
    # ------------------------------------------------------------------
    log_section("Sandbox")
    use_template = template if template and template.lower() != "none" else None
    if use_template:
        if use_template == FOUNDRY_TEMPLATE_TAG:
            log_info("Ensuring foundry template is available...")
            if not ensure_foundry_template():
                log_warn("Template build failed; falling back to runtime injection")
                use_template = None
        else:
            log_info(f"Using template: {use_template}")
            # Custom/managed templates must exist — no silent fallback.
            templates = sbx_template_ls()
            if not any(use_template in t for t in templates):
                raise SetupError(
                    f"Template '{use_template}' not found in sbx. "
                    f"Run `sbx template ls` to see available tags, or recreate "
                    f"it via `cast preset save` / `sbx template save`."
                )
    log_info(f"Creating sbx sandbox: {name}")
    try:
        # Acquire per-repo lock to serialize concurrent git worktree add.
        repo_lock_path = Path(repo_root)
        with file_lock(repo_lock_path):
            result = sbx_create(
                name, agent, repo_root, branch=branch, template=use_template
            )
    except Exception as exc:
        raise SetupError(f"sbx create failed: {exc}") from exc

    # sbx may truncate the sandbox name internally, so the actual worktree
    # path can differ from our deterministic formula.  Use the parsed stdout
    # as ground truth and fall back to the formula only when parsing fails.
    info = sbx_get_workspace_info(result.stdout or "")
    if info["worktree"]:
        workspace_path = info["worktree"]
        expected = sbx_worktree_path(repo_root, name, branch)
        if workspace_path != expected:
            log_warn(
                f"sbx worktree path differs from deterministic formula: "
                f"{workspace_path} vs {expected} (sbx may have truncated the name)"
            )
    else:
        workspace_path = sbx_worktree_path(repo_root, name, branch)

    # ------------------------------------------------------------------
    # 3. Start git safety server if needed (fail closed)
    # ------------------------------------------------------------------
    log_section("Git Safety")
    if not git_safety_server_is_running():
        log_info("Starting git safety server...")
        try:
            git_safety_server_start(deep_policy=True)
        except OSError as exc:
            raise SetupError(
                "foundry-git-safety is not installed. "
                "Run: pip install foundry-git-safety[server]"
            ) from exc
        except Exception as exc:
            raise SetupError(f"Git safety server start failed: {exc}") from exc

        if not git_safety_server_is_running():
            raise SetupError(
                "Git safety server did not become healthy after start. "
                "Check `foundry-git-safety status` for details."
            )
    log_info("Git safety server running.")

    # ------------------------------------------------------------------
    # 4. Write initial metadata (git safety not yet provisioned)
    # ------------------------------------------------------------------
    ensure_dir(claude_config_path)
    write_sandbox_metadata(
        name,
        sbx_name=name,
        agent=agent,
        repo_url=repo_url,
        branch=branch,
        from_branch=from_branch,
        git_safety_enabled=False,
        workspace_dir="/workspace",
        working_dir=wd,
        pip_requirements=pip_requirements,
        allow_pr=allow_pr,
        enable_opencode=with_opencode,
        enable_zai=with_zai,
        copies=copies,
        template=use_template or "",
        workspace_path=workspace_path,
    )

    # ------------------------------------------------------------------
    # 5. Provision git safety (helper writes git_safety_enabled=True)
    # ------------------------------------------------------------------
    log_info("Provisioning git safety...")
    repo_spec = strip_github_url(repo_url)
    prov_result = provision_git_safety(
        name,
        sandbox_id=name,
        workspace_dir="/workspace",
        branch=branch,
        repo_spec=repo_spec,
        from_branch=from_branch,
        allow_pr=allow_pr,
        repo_root=workspace_path,
    )
    if not prov_result.success:
        raise SetupError(
            f"Git safety provisioning failed: {prov_result.error}. "
            "Sandbox creation aborted — git safety cannot be enforced."
        )

    # ------------------------------------------------------------------
    # 5.5. Inject user service environment overrides
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
    # 6. Copy files and install pip requirements
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
    # 7. Final metadata patch (user services)
    # ------------------------------------------------------------------
    if user_service_overrides:
        from foundry_sandbox.state import patch_sandbox_metadata
        patch_sandbox_metadata(name, user_services=user_service_overrides)

    return workspace_path


def rollback_new_sbx(
    claude_config_path: Path,
    name: str,
) -> None:
    """Clean up partial sandbox resources on failure."""
    # Remove sbx sandbox (best effort)
    try:
        sbx_rm(name)
    except Exception:
        pass

    # Remove config directory
    if claude_config_path.is_dir():
        try:
            import shutil
            shutil.rmtree(claude_config_path)
        except OSError:
            pass
