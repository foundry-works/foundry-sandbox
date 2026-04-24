"""SBX-based sandbox creation and worktree setup."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from foundry_sandbox.api_keys import check_claude_key_required
from foundry_sandbox.validate import validate_git_url
from foundry_sandbox.atomic_io import file_lock
from foundry_sandbox.utils import log_error, log_info, log_section, log_warn
from foundry_sandbox.git_safety import (
    FOUNDRY_TEMPLATE_TAG,
    ensure_foundry_template,
    git_safety_server_is_running,
    git_safety_server_start,
    provision_git_safety,
)
from foundry_sandbox.paths import ensure_dir
from foundry_sandbox.sbx import (
    bootstrap_packages,
    install_pip_requirements,
    sbx_check_available,
    sbx_create,
    sbx_exec,
    sbx_get_workspace_info,
    sbx_rm,
    sbx_template_ls,
    sbx_worktree_path,
)
from foundry_sandbox.state import write_sandbox_metadata
from foundry_sandbox.models import SbxSandboxMetadata
from foundry_sandbox.paths import strip_github_url


def _validate_preconditions(
    repo_url: str,
    copies: tuple[str, ...],
    skip_key_check: bool,
) -> None:
    """Validate API keys and copy sources before sandbox creation."""
    ok, msg = validate_git_url(repo_url)
    if not ok:
        log_error(msg)
        sys.exit(1)

    if not skip_key_check:
        ok, msg = check_claude_key_required()
        if not ok:
            log_error("Sandbox creation cancelled - Claude authentication required.")
            sys.exit(1)

    for copy_spec in copies:
        src, _, _ = copy_spec.partition(":")
        if not os.path.exists(src):
            log_error(f"Copy source does not exist: {src}")
            sys.exit(1)



def new_sbx_setup(
    *,
    repo_url: str,
    repo_root: str,
    branch: str,
    from_branch: str,
    name: str,
    agent: str,
    sandbox_config_path: Path,
    copies: list[str],
    allow_pr: bool,
    pip_requirements: str,
    with_opencode: bool,
    with_zai: bool,
    wd: str,
    template: str | None = FOUNDRY_TEMPLATE_TAG,
    ide: str = "",
    packages: dict[str, object] | None = None,
    profile_name: str = "",
    skip_package_bootstrap: bool = False,
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
        The host_worktree_path (host-side path to the sbx-managed worktree).
    """
    # ------------------------------------------------------------------
    # 1. Check sbx
    # ------------------------------------------------------------------
    sbx_check_available()

    # ------------------------------------------------------------------
    # 2. Start git safety server if needed (fail closed)
    # ------------------------------------------------------------------
    log_section("Git Safety")
    if not git_safety_server_is_running():
        log_info("Starting git safety server...")
        try:
            git_safety_server_start(deep_policy=True)
        except OSError as exc:
            raise RuntimeError(
                "foundry-git-safety is not installed. "
                "Run: pip install foundry-git-safety[server]"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"Git safety server start failed: {exc}") from exc

        if not git_safety_server_is_running():
            raise RuntimeError(
                "Git safety server did not become healthy after start. "
                "Check `foundry-git-safety status` for details."
            )
    log_info("Git safety server running.")

    # ------------------------------------------------------------------
    # 3. Ensure template exists, then create sbx sandbox
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
                raise RuntimeError(
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
        raise RuntimeError(f"sbx create failed: {exc}") from exc

    # sbx may truncate the sandbox name internally, so the actual worktree
    # path can differ from our deterministic formula.  Use the parsed stdout
    # as ground truth and fall back to the formula only when parsing fails.
    info = sbx_get_workspace_info(result.stdout or "")
    if info["worktree"]:
        host_worktree_path = info["worktree"]
        expected = sbx_worktree_path(repo_root, name, branch)
        if host_worktree_path != expected:
            log_warn(
                f"sbx worktree path differs from deterministic formula: "
                f"{host_worktree_path} vs {expected} (sbx may have truncated the name)"
            )
    else:
        host_worktree_path = sbx_worktree_path(repo_root, name, branch)

    # ------------------------------------------------------------------
    # 4. Write initial metadata (git safety not yet provisioned)
    # ------------------------------------------------------------------
    ensure_dir(sandbox_config_path)
    write_sandbox_metadata(
        name,
        SbxSandboxMetadata(
            sbx_name=name,
            agent=agent,
            repo_url=repo_url,
            branch=branch,
            from_branch=from_branch,
            git_safety_enabled=False,
            workspace_dir="/workspace",
            working_dir=wd,
            pip_requirements=pip_requirements,
            packages=packages or {},
            allow_pr=allow_pr,
            enable_opencode=with_opencode,
            enable_zai=with_zai,
            copies=copies,
            template=use_template or "",
            host_worktree_path=host_worktree_path,
            ide=ide,
        ),
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
        repo_root=host_worktree_path,
    )
    if not prov_result.success:
        raise RuntimeError(
            f"Git safety provisioning failed: {prov_result.error}. "
            "Sandbox creation aborted — git safety cannot be enforced."
        )

    # ------------------------------------------------------------------
    # 5.1. Apply foundry.yaml artifacts (git-safety overlay + user services)
    # ------------------------------------------------------------------
    user_service_overrides: dict[str, str] = {}
    try:
        from foundry_sandbox.foundry_config import (
            compile_claude_code,
            compile_git_safety,
            compile_mcp_servers,
            compile_user_services,
            resolve_foundry_config,
        )
        from foundry_sandbox.artifacts import apply_artifacts, _merge_bundles

        # Resolve against the actual sandbox worktree so branch-specific
        # foundry.yaml contents drive compiled artifacts.
        config = resolve_foundry_config(Path(host_worktree_path))

        # Expand tooling bundles if a profile is active
        if profile_name:
            from foundry_sandbox.foundry_config import (
                DevProfile,
                expand_bundles,
                normalize_profile_packages,
                resolve_profile,
            )
            try:
                profile = resolve_profile(config, profile_name)
                config, bundle_packages = expand_bundles(config, profile)
                if bundle_packages:
                    bp = normalize_profile_packages(DevProfile(packages=bundle_packages))
                    if packages is None:
                        packages = bp
                    else:
                        for k, v in bp.items():
                            if k not in packages:
                                packages[k] = v
            except ValueError as exc:
                log_warn(f"Bundle expansion skipped: {exc}")

        bundles = []
        if config.git_safety:
            bundles.append(compile_git_safety(config.git_safety))
        if config.user_services:
            bundles.append(compile_user_services(config.user_services))
        if config.mcp_servers:
            bundles.append(compile_mcp_servers(config.mcp_servers))
        if config.claude_code:
            bundles.append(compile_claude_code(config.claude_code))

        if bundles:
            merged = _merge_bundles(bundles)
            apply_artifacts(name, merged, sandbox_id=name)
            user_service_overrides = merged.env_vars
            log_info(f"Applied {len(merged.policy_patches)} policy patch(es), "
                     f"{len(merged.env_vars)} env var(s), "
                     f"{len(merged.file_writes)} file write(s) from foundry.yaml")
    except NotImplementedError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Foundry.yaml artifact apply failed: {exc}") from exc

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

    if packages and not skip_package_bootstrap:
        bootstrap_packages(name, packages)
    elif pip_requirements and not skip_package_bootstrap:
        log_section("Dependencies")
        install_pip_requirements(name, pip_requirements)

    # ------------------------------------------------------------------
    # 7. Final metadata patch (user services)
    # ------------------------------------------------------------------
    if user_service_overrides:
        from foundry_sandbox.state import patch_sandbox_metadata
        patch_sandbox_metadata(name, user_services=user_service_overrides)

    return host_worktree_path


def rollback_new_sbx(
    sandbox_config_path: Path,
    name: str,
) -> None:
    """Clean up partial sandbox resources on failure."""
    # Remove sbx sandbox (best effort)
    try:
        sbx_rm(name)
    except Exception:
        pass

    # Remove config directory
    if sandbox_config_path.is_dir():
        try:
            import shutil
            shutil.rmtree(sandbox_config_path)
        except OSError:
            pass
