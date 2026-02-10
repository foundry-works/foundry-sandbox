"""Setup and rollback logic for the ``new`` command.

Contains the resource-creation phase (_new_setup) and best-effort
cleanup (_rollback_new) extracted from new.py for maintainability.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

import click

from foundry_sandbox.commands._helpers import (
    apply_network_restrictions,
    generate_sandbox_id,
    strip_github_url,
)
from foundry_sandbox.api_keys import export_gh_token, show_cli_status
from foundry_sandbox.constants import get_repos_dir
from foundry_sandbox.container_io import copy_dir_to_container, copy_file_to_container
from foundry_sandbox.container_setup import install_pip_requirements
from foundry_sandbox.credential_setup import copy_configs_to_container
from foundry_sandbox.docker import compose_up
from foundry_sandbox.foundry_plugin import prepopulate_foundry_global
from foundry_sandbox.git import ensure_bare_repo
from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths
from foundry_sandbox.git_worktree import create_worktree
from foundry_sandbox.network import (
    add_claude_home_to_override,
    add_network_to_override,
    add_ssh_agent_to_override,
    add_timezone_to_override,
)
from foundry_sandbox.paths import ensure_dir, path_claude_home
from foundry_sandbox.permissions import install_workspace_permissions
from foundry_sandbox.proxy import setup_proxy_registration
from foundry_sandbox.state import write_sandbox_metadata
from foundry_sandbox.validate import validate_git_remotes
from foundry_sandbox.utils import log_section, log_step, log_warn


class _SetupError(Exception):
    """Raised by ``_new_setup`` to signal a failure that should trigger rollback."""


def _rollback_new(
    worktree_path: Path,
    claude_config_path: Path,
    container: str,
    override_file: Path,
) -> None:
    """Best-effort cleanup of partially-created sandbox resources.

    Called when the ``new`` command fails after beginning resource creation.
    Cleans up containers, config directories, and worktrees so the user
    is not left with orphaned state.
    """
    import shutil
    import subprocess as _sp
    from foundry_sandbox.docker import compose_down, remove_stubs_volume, remove_hmac_volume
    from foundry_sandbox.git_worktree import remove_worktree

    # 1. Stop and remove containers
    try:
        compose_down(
            worktree_path=str(worktree_path),
            claude_config_path=str(claude_config_path),
            container=container,
            override_file=str(override_file),
            remove_volumes=True,
        )
    except Exception as exc:
        log_warn(f"Rollback: failed to stop containers: {exc}")

    # 2. Remove Docker networks (best-effort)
    for suffix in ("credential-isolation", "proxy-egress"):
        try:
            _sp.run(
                ["docker", "network", "rm", f"{container}_{suffix}"],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                check=False, timeout=30,
            )
        except Exception as exc:
            log_warn(f"Rollback: failed to remove network {container}_{suffix}: {exc}")

    # 3. Remove stubs and HMAC volumes (best-effort)
    try:
        remove_stubs_volume(container)
    except Exception as exc:
        log_warn(f"Rollback: failed to remove stubs volume: {exc}")
    try:
        remove_hmac_volume(container)
    except Exception as exc:
        log_warn(f"Rollback: failed to remove HMAC volume: {exc}")

    # 4. Remove config directory
    if claude_config_path.is_dir():
        try:
            shutil.rmtree(claude_config_path)
        except Exception as exc:
            log_warn(f"Rollback: failed to remove config directory: {exc}")

    # 5. Remove worktree
    if worktree_path.is_dir():
        try:
            remove_worktree(str(worktree_path))
        except Exception as exc:
            log_warn(f"Rollback: failed to remove worktree: {exc}")


def _new_setup(
    *,
    repo_url: str,
    bare_path: str,
    worktree_path: Path,
    branch: str,
    from_branch: str,
    sparse: bool,
    wd: str,
    claude_config_path: Path,
    override_file: Path,
    name: str,
    container: str,
    mounts: list[str],
    copies: list[str],
    allow_dangerous_mount: bool,
    network_mode: str,
    sync_ssh_enabled: bool,
    ssh_agent_sock: str,
    ssh_mode: str,
    isolate_credentials: bool,
    allow_pr: bool,
    pip_requirements: str,
    enable_opencode_flag: str,
    enable_zai_flag: str,
) -> None:
    """Inner setup logic for the ``new`` command, extracted for rollback."""
    # Clone/fetch bare repo
    ensure_bare_repo(repo_url, bare_path)

    # Create worktree
    create_worktree(
        bare_path,
        str(worktree_path),
        branch,
        from_branch or None,
        sparse,
        wd or None,
    )

    # Add specs/.backups to gitignore
    gitignore_file = worktree_path / ".gitignore"
    gitignore_content = gitignore_file.read_text() if gitignore_file.exists() else ""
    if "specs/.backups" not in gitignore_content:
        with gitignore_file.open("a") as f:
            f.write("specs/.backups\n")

    # Setup override file
    ensure_dir(claude_config_path)

    log_section("Configuration")

    # Add mounts
    if mounts:
        log_step("Custom mounts added")
        if allow_dangerous_mount:
            click.echo("WARNING: --allow-dangerous-mount bypasses credential directory protection. Use with caution.")

        with override_file.open("w") as f:
            f.write("services:\n")
            f.write("  dev:\n")
            f.write("    volumes:\n")
            for mount in mounts:
                escaped = mount.replace('"', '\\"')
                f.write(f'      - "{escaped}"\n')

    # Add network mode
    if network_mode:
        log_step(f"Network mode: {network_mode}")
        add_network_to_override(network_mode, str(override_file))

    # Add Claude home
    claude_home_path = path_claude_home(name)
    ensure_dir(claude_home_path)
    add_claude_home_to_override(str(override_file), str(claude_home_path))
    add_timezone_to_override(str(override_file))

    # Pre-populate foundry global
    prepopulate_foundry_global(str(claude_home_path))

    # Show CLI status
    show_cli_status()

    # Add SSH agent
    runtime_enable_ssh = "0"
    if sync_ssh_enabled and ssh_agent_sock:
        log_step("SSH agent forwarding: enabled")
        add_ssh_agent_to_override(str(override_file), ssh_agent_sock)
        runtime_enable_ssh = "1"
    else:
        add_ssh_agent_to_override(str(override_file), "")

    # Write metadata
    write_sandbox_metadata(
        name=name,
        repo_url=repo_url,
        branch=branch,
        from_branch=from_branch or "",
        working_dir=wd or "",
        sparse_checkout="1" if sparse else "0",
        pip_requirements=pip_requirements or "",
        allow_pr="1" if allow_pr else "0",
        network_mode=network_mode or "",
        sync_ssh=1 if sync_ssh_enabled else 0,
        ssh_mode=ssh_mode,
        enable_opencode=enable_opencode_flag,
        enable_zai=enable_zai_flag,
        mounts=list(mounts),
        copies=list(copies),
    )

    container_id = f"{container}-dev-1"

    # Export GH token
    token = export_gh_token()
    if token:
        os.environ["GITHUB_TOKEN"] = token
        os.environ["GH_TOKEN"] = token

    log_section("Container")
    log_step("Starting container...")

    if isolate_credentials:
        log_step("Credential isolation: enabled")

        # Check for auth files
        codex_auth = Path.home() / ".codex/auth.json"
        if not codex_auth.is_file():
            log_warn("Credential isolation: ~/.codex/auth.json not found; Codex CLI will not work.")

        opencode_auth = Path.home() / ".local/share/opencode/auth.json"
        if enable_opencode_flag != "1" and not opencode_auth.is_file():
            log_warn("Credential isolation: ~/.local/share/opencode/auth.json not found; OpenCode CLI will not work.")

        gemini_oauth = Path.home() / ".gemini/oauth_creds.json"
        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        if not gemini_oauth.is_file() and not gemini_key:
            log_warn("Credential isolation: ~/.gemini/oauth_creds.json not found and GEMINI_API_KEY not set; Gemini CLI will not work.")

        # Validate git remotes
        ok, msg = validate_git_remotes(str(worktree_path / ".git"))
        if not ok:
            raise _SetupError("Cannot enable credential isolation with embedded git credentials")

        # Set ALLOW_PR_OPERATIONS
        if allow_pr:
            os.environ["ALLOW_PR_OPERATIONS"] = "true"
            log_step("PR operations: allowed")
        else:
            os.environ["ALLOW_PR_OPERATIONS"] = ""
            log_step("PR operations: blocked (default)")

        # Generate sandbox ID
        seed = f"{container}:{name}:{int(datetime.now().timestamp() * 1e9)}"
        sandbox_id = generate_sandbox_id(seed)
        if not sandbox_id:
            raise _SetupError("Failed to generate sandbox identity")

        log_step(f"Sandbox ID: {sandbox_id}")
    else:
        sandbox_id = ""

    # Start containers
    compose_up(
        worktree_path=str(worktree_path),
        claude_config_path=str(claude_config_path),
        container=container,
        override_file=str(override_file),
        isolate_credentials=isolate_credentials,
        repos_dir=str(get_repos_dir()) if isolate_credentials else "",
        sandbox_id=sandbox_id,
    )

    # Register with proxy
    if isolate_credentials:
        os.environ["SANDBOX_GATEWAY_ENABLED"] = "true"

        # Fix proxy worktree paths
        proxy_container = f"{container}-unified-proxy-1"
        os.environ["PROXY_CONTAINER_NAME"] = proxy_container
        username = os.environ.get("USER", "ubuntu")
        fix_proxy_worktree_paths(proxy_container, username)

        # Extract repo spec
        repo_spec = strip_github_url(repo_url)

        metadata_json = {
            "repo": repo_spec,
            "allow_pr": allow_pr,
            "sandbox_branch": branch,
            "from_branch": from_branch or "",
        }

        try:
            setup_proxy_registration(container_id, metadata_json)
        except Exception as e:
            raise _SetupError(
                f"Failed to register container with unified-proxy: {e}\n"
                "Container registration failed. See error messages above for remediation.\n"
                "To create sandbox without credential isolation, use --no-isolate-credentials flag."
            ) from e

    # Copy configs to container
    copy_configs_to_container(
        container_id,
        skip_plugins=False,
        enable_ssh=runtime_enable_ssh == "1",
        working_dir=wd or "",
        isolate_credentials=isolate_credentials,
        from_branch=from_branch or "",
        branch=branch,
        repo_url=repo_url,
    )

    # Copy files
    if copies:
        click.echo("Copying files into container...")
        for copy_spec in copies:
            parts = copy_spec.split(":", 1)
            if len(parts) != 2:
                continue
            src, dst = parts
            if not os.path.exists(src):
                click.echo(f"  Warning: Source '{src}' does not exist, skipping")
                continue

            click.echo(f"  {src} -> {dst}")
            if os.path.isdir(src):
                copy_dir_to_container(container_id, src, dst)
            else:
                copy_file_to_container(container_id, src, dst)

    # Install workspace permissions
    install_workspace_permissions(container_id)

    # Install pip requirements
    if pip_requirements:
        install_pip_requirements(container_id, pip_requirements)

    # Apply network restrictions
    if network_mode:
        apply_network_restrictions(container_id, network_mode)
