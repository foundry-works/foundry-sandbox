"""Config and credential orchestration for sandbox containers.

Migrated from lib/container_config.sh: copy_configs_to_container,
sync_runtime_credentials, merge_claude_settings.

SECURITY-CRITICAL: Must never leak real credentials into sandbox.
Only placeholders are injected in credential isolation mode.
"""
from __future__ import annotations

import getpass
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from foundry_sandbox.constants import (
    CONTAINER_HOME,
    CONTAINER_READY_ATTEMPTS,
    CONTAINER_READY_DELAY,
    CONTAINER_USER,
    TIMEOUT_DOCKER_EXEC,
    get_sandbox_debug,
    get_sandbox_home,
)
from foundry_sandbox.container_io import (
    copy_dir_to_container,
    copy_dir_to_container_quiet,
    copy_file_to_container,
    copy_file_to_container_quiet,
    docker_exec_text,  # noqa: F401 — re-exported for test mocking
)
from foundry_sandbox.utils import log_debug, log_step, log_warn

import json as _json_mod
from datetime import datetime, timezone


def _audit_credential_op(operation: str, container_id: str, target: str, *, success: bool) -> None:
    """Log a structured audit entry for credential operations.

    Uses the existing debug logging infrastructure. Can be promoted to a
    dedicated audit log file later if needed.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "container": container_id,
        "target": target,
        "success": success,
    }
    log_debug(f"CREDENTIAL_AUDIT: {_json_mod.dumps(entry)}")


def _merge_claude_settings_in_container(container_id: str, host_settings: str) -> bool:
    """Merge host Claude settings into container settings via docker exec.

    Delegates to settings_merge.merge_claude_settings_in_container.
    """
    from foundry_sandbox.settings_merge import merge_claude_settings_in_container
    return merge_claude_settings_in_container(container_id, host_settings)


def _merge_claude_settings_safe(container_id: str, host_settings: str) -> bool:
    """Merge host Claude settings into container, stripping credential-bearing keys.

    Delegates to settings_merge.merge_claude_settings_safe.
    """
    from foundry_sandbox.settings_merge import merge_claude_settings_safe
    return merge_claude_settings_safe(container_id, host_settings)


def _file_exists(path: str) -> bool:
    """Check if a host file exists."""
    return os.path.isfile(Path(path).expanduser())


def _dir_exists(path: str) -> bool:
    """Check if a host directory exists."""
    return os.path.isdir(Path(path).expanduser())


def _opencode_enabled() -> bool:
    """Check if OpenCode is enabled."""
    # Check if opencode is in PATH
    result = shutil.which("opencode")
    if result:
        return True
    # Check environment variable
    return os.environ.get("OPENCODE_ENABLED", "").lower() in ("1", "true", "yes")


def _stage_setup_user(container_id: str) -> None:
    """Stage 1: Create container user and wait for home directory."""
    from foundry_sandbox.container_setup import ensure_container_user

    log_step("Setting up container user")
    ensure_container_user(container_id)

    log_step("Waiting for container home directory")
    for attempt in range(CONTAINER_READY_ATTEMPTS):
        result = subprocess.run(
            ["docker", "exec", container_id, "test", "-d", CONTAINER_HOME],
            capture_output=True,
            timeout=TIMEOUT_DOCKER_EXEC,
        )
        if result.returncode == 0:
            break
        if attempt < CONTAINER_READY_ATTEMPTS - 1:
            time.sleep(CONTAINER_READY_DELAY)
    else:
        log_warn(f"Container home {CONTAINER_HOME} not ready after 5 attempts")


def _stage_create_config_dirs(container_id: str) -> list[str]:
    """Stage 2: Create config directories. Returns the list for later chown."""
    log_step("Creating config directories")
    dirs = [
        f"{CONTAINER_HOME}/.claude",
        f"{CONTAINER_HOME}/.config/gh",
        f"{CONTAINER_HOME}/.gemini",
        f"{CONTAINER_HOME}/.config/opencode",
        f"{CONTAINER_HOME}/.local/share/opencode",
        f"{CONTAINER_HOME}/.codex",
        f"{CONTAINER_HOME}/.ssh",
        f"{CONTAINER_HOME}/.ssh/sockets",
    ]
    for dir_path in dirs:
        subprocess.run(
            ["docker", "exec", "-u", CONTAINER_USER, container_id, "mkdir", "-p", dir_path],
            check=False,
            capture_output=True,
            timeout=TIMEOUT_DOCKER_EXEC,
        )
    return dirs


def _stage_setup_claude_config(
    container_id: str,
    home: Path,
    *,
    isolate_credentials: bool,
    skip_plugins: bool,
) -> None:
    """Stage 3: Claude config, settings merge, statusline, plugins."""
    from foundry_sandbox.foundry_plugin import (
        ensure_foundry_mcp_config,
        sync_marketplace_manifests,
    )
    from foundry_sandbox.tool_configs import (
        ensure_claude_onboarding,
        ensure_claude_statusline,
    )

    # Copy ~/.claude.json to container (both locations)
    log_step("Copying Claude config")
    claude_json = home / ".claude.json"
    if claude_json.exists():
        copy_file_to_container(container_id, str(claude_json), f"{CONTAINER_HOME}/.claude.json")
        try:
            copy_file_to_container(container_id, str(claude_json), f"{CONTAINER_HOME}/.claude/.claude.json")
        except (OSError, subprocess.SubprocessError):
            log_debug("Could not copy .claude.json to secondary path (non-fatal)")
    else:
        log_debug("~/.claude.json not found, skipping")

    # Fix ownership on .claude dir — needed because it is bind-mounted from
    # the host (~/.sandboxes/claude-config/<name>/claude/) and the host UID
    # may differ from the container's ubuntu user (UID 1000).  Run as root
    # explicitly so the chown succeeds regardless of the container's default
    # user (root in credential-isolation mode, ubuntu otherwise).
    subprocess.run(
        [
            "docker", "exec", "-u", "root", container_id,
            "chown", "-R", f"{CONTAINER_USER}:{CONTAINER_USER}",
            f"{CONTAINER_HOME}/.claude",
        ],
        check=False,
        capture_output=True,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    log_step("Ensuring Claude onboarding")
    ensure_claude_onboarding(container_id)

    log_step("Ensuring Foundry MCP config")
    ensure_foundry_mcp_config(container_id)

    # Merge host settings — strip secrets when credential isolation is active
    log_step("Merging Claude settings")
    settings_json = home / ".claude" / "settings.json"
    if settings_json.exists():
        if isolate_credentials:
            log_debug("Credential isolation: merging settings with secret-bearing keys stripped")
            ok = _merge_claude_settings_safe(container_id, str(settings_json))
        else:
            ok = _merge_claude_settings_in_container(container_id, str(settings_json))
        if not ok:
            log_warn("Claude settings merge was incomplete; some settings may be missing")
    else:
        log_debug("~/.claude/settings.json not found, skipping")

    # Statusline
    log_step("Copying statusline config")
    statusline_conf = home / ".claude" / "statusline.conf"
    if not statusline_conf.exists():
        script_dir = Path(os.environ.get("SCRIPT_DIR", "/workspace"))
        statusline_conf = script_dir / "statusline.conf"
    if statusline_conf.exists():
        copy_file_to_container(
            container_id, str(statusline_conf),
            f"{CONTAINER_HOME}/.claude/statusline.conf",
        )
    else:
        log_debug("statusline.conf not found, skipping")

    log_step("Ensuring Claude statusline")
    ensure_claude_statusline(container_id)

    # Marketplace plugins
    if not skip_plugins:
        log_step("Copying marketplace plugins")
        marketplace_plugins = home / ".claude" / "marketplace_plugins"
        if marketplace_plugins.exists():
            copy_dir_to_container(
                container_id, str(marketplace_plugins),
                f"{CONTAINER_HOME}/.claude/marketplace_plugins",
            )
        else:
            log_debug("marketplace_plugins dir not found, skipping")

        log_step("Syncing marketplace manifests")
        sync_marketplace_manifests(container_id, f"{CONTAINER_HOME}/.claude/marketplace_plugins")
    else:
        log_debug("Skipping marketplace plugins (skip_plugins=True)")


def _stage_setup_tool_configs(container_id: str, home: Path) -> None:
    """Stage 4: GitHub, OpenCode, Codex, Gemini tool configs."""
    from foundry_sandbox.tool_configs import (
        ensure_codex_config,
        ensure_gemini_settings,
    )

    # GitHub CLI config
    log_step("Copying GitHub CLI config")
    gh_config = home / ".config" / "gh"
    if gh_config.exists():
        copy_dir_to_container(
            container_id, str(gh_config), f"{CONTAINER_HOME}/.config/gh",
        )
    else:
        log_debug("~/.config/gh not found, skipping")

    # OpenCode config (non-credential; always copied)
    log_step("Copying OpenCode config")
    opencode_config = home / ".config" / "opencode" / "config.json"
    if opencode_config.exists():
        copy_file_to_container(
            container_id, str(opencode_config),
            f"{CONTAINER_HOME}/.config/opencode/config.json",
        )
    else:
        log_debug("OpenCode config not found, skipping")

    log_step("Ensuring Codex config")
    ensure_codex_config(container_id)

    log_step("Ensuring Gemini settings")
    ensure_gemini_settings(container_id)

    # OpenCode extended setup (if enabled)
    if _opencode_enabled():
        log_step("Configuring OpenCode")
        opencode_settings = home / ".config" / "opencode" / "settings.json"
        if opencode_settings.exists():
            copy_file_to_container(
                container_id, str(opencode_settings),
                f"{CONTAINER_HOME}/.config/opencode/settings.json",
            )

        opencode_foundry = home / ".local" / "share" / "opencode" / "foundry-mcp"
        if opencode_foundry.exists():
            copy_dir_to_container(
                container_id, str(opencode_foundry),
                f"{CONTAINER_HOME}/.local/share/opencode/foundry-mcp",
            )

        opencode_tavily = home / ".config" / "opencode" / "tavily-mcp"
        if opencode_tavily.exists():
            copy_dir_to_container(
                container_id, str(opencode_tavily),
                f"{CONTAINER_HOME}/.config/opencode/tavily-mcp",
            )

        opencode_model = home / ".config" / "opencode" / "default-model.json"
        if opencode_model.exists():
            copy_file_to_container(
                container_id, str(opencode_model),
                f"{CONTAINER_HOME}/.config/opencode/default-model.json",
            )

        log_debug("OpenCode npm plugin prefetch not implemented yet")
    else:
        log_debug("OpenCode not enabled, skipping OpenCode config")


def _stage_setup_credentials(
    container_id: str,
    home: Path,
    *,
    isolate_credentials: bool,
    enable_ssh: bool,
) -> None:
    """Stage 5: Real credentials + SSH keys.

    SECURITY-CRITICAL: The ``if not isolate_credentials`` guard is the single
    auditable boundary that prevents real secrets from leaking into sandboxes.
    """
    if not isolate_credentials:
        log_step("Copying credentials (isolation disabled)")

        # Gemini OAuth
        gemini_oauth = home / ".gemini" / "oauth_creds.json"
        if gemini_oauth.exists():
            copy_file_to_container(
                container_id, str(gemini_oauth),
                f"{CONTAINER_HOME}/.gemini/oauth_creds.json",
            )
            _audit_credential_op("copy_gemini_oauth", container_id, "gemini/oauth_creds.json", success=True)
        else:
            log_debug("Gemini OAuth not found, skipping")

        # OpenCode auth
        opencode_auth = home / ".config" / "opencode" / "auth.json"
        if opencode_auth.exists():
            copy_file_to_container(
                container_id, str(opencode_auth),
                f"{CONTAINER_HOME}/.config/opencode/auth.json",
            )
            _audit_credential_op("copy_opencode_auth", container_id, "opencode/auth.json", success=True)
        else:
            log_debug("OpenCode auth not found, skipping")

        # Codex dir
        codex_dir = home / ".codex"
        if codex_dir.exists():
            copy_dir_to_container(
                container_id, str(codex_dir), f"{CONTAINER_HOME}/.codex",
            )
            _audit_credential_op("copy_codex_dir", container_id, ".codex/", success=True)
        else:
            log_debug("~/.codex not found, skipping")

        # SSH keys (only when SSH is also requested)
        if enable_ssh:
            log_step("Setting up SSH keys")
            ssh_dir = home / ".ssh"
            if ssh_dir.exists():
                for key_file in ["id_rsa", "id_ed25519", "id_ecdsa"]:
                    key_path = ssh_dir / key_file
                    pub_path = ssh_dir / f"{key_file}.pub"
                    if key_path.exists():
                        copy_file_to_container(
                            container_id, str(key_path),
                            f"{CONTAINER_HOME}/.ssh/{key_file}",
                            mode="0600",
                        )
                        _audit_credential_op("copy_ssh_key", container_id, f".ssh/{key_file}", success=True)
                    if pub_path.exists():
                        copy_file_to_container(
                            container_id, str(pub_path),
                            f"{CONTAINER_HOME}/.ssh/{key_file}.pub",
                        )

                known_hosts = ssh_dir / "known_hosts"
                if known_hosts.exists():
                    copy_file_to_container(
                        container_id, str(known_hosts),
                        f"{CONTAINER_HOME}/.ssh/known_hosts",
                    )

                ssh_config = ssh_dir / "config"
                if ssh_config.exists():
                    copy_file_to_container(
                        container_id, str(ssh_config),
                        f"{CONTAINER_HOME}/.ssh/config",
                    )
            else:
                log_debug("~/.ssh not found, skipping SSH keys")
        else:
            log_debug("SSH not enabled, skipping SSH key setup")
    else:
        _audit_credential_op("isolation_active", container_id, "*", success=True)
        log_debug("Credential isolation enabled, skipping real credentials")


def _stage_setup_git_config(container_id: str, home: Path, host_user: str) -> None:
    """Stage 6: gitconfig, repos, worktree paths, HTTPS git, branch context."""
    from foundry_sandbox.git_path_fixer import detect_nested_git_repos, fix_worktree_paths
    from foundry_sandbox.tool_configs import ensure_github_https_git

    log_step("Copying git config")
    gitconfig = home / ".gitconfig"
    if gitconfig.exists():
        copy_file_to_container(
            container_id, str(gitconfig), f"{CONTAINER_HOME}/.gitconfig",
        )
    else:
        log_debug("~/.gitconfig not found, skipping")

    # Re-apply git security hardening after host gitconfig copy.
    # The entrypoint sets these in ~/.gitconfig, but the host copy above
    # overwrites the file, so we must re-apply them here.
    # Run through sh -c with explicit HOME to avoid Docker HOME inheritance
    # issues (credential isolation sets compose user:root, and docker exec
    # may not reset HOME from /etc/passwd for the -u override).
    log_step("Applying git security hardening")
    _hardening_script = " && ".join(
        f"/usr/bin/git config --global {key} {shlex.quote(value)}"
        for key, value in [
            ("core.hooksPath", "/dev/null"),
            ("init.templateDir", ""),
            ("core.fsmonitor", "false"),
            ("core.fsmonitorHookVersion", "0"),
            ("receive.denyCurrentBranch", "refuse"),
        ]
    )
    try:
        docker_exec_text(
            container_id, "sh", "-c",
            f"export HOME={CONTAINER_HOME} && {_hardening_script}",
        )
    except subprocess.CalledProcessError:
        log_warn("Failed to apply git security hardening")

    log_step("Copying sandbox repos")
    sandbox_home = get_sandbox_home()
    repos_dir = Path(sandbox_home) / "repos"
    if repos_dir.exists():
        copy_dir_to_container(
            container_id, str(repos_dir), f"{CONTAINER_HOME}/.sandboxes/repos",
        )
    else:
        log_debug(f"{repos_dir} not found, skipping")

    log_step("Fixing git worktree paths")
    fix_worktree_paths(container_id, host_user)

    log_step("Detecting nested git repos")
    detect_nested_git_repos(container_id)

    log_step("Ensuring GitHub HTTPS Git")
    ensure_github_https_git(container_id)


def _stage_setup_foundry(
    container_id: str,
    home: Path,
    *,
    working_dir: str,
    from_branch: str,
    branch: str,
    repo_url: str,
) -> None:
    """Stage 7: foundry-mcp, research providers, workspace docs."""
    from foundry_sandbox.foundry_plugin import (
        ensure_claude_foundry_mcp,
        ensure_foundry_mcp_workspace_dirs,
        configure_foundry_research_providers,
    )
    from foundry_sandbox.stub_manager import (
        inject_sandbox_branch_context,
        install_foundry_workspace_docs,
    )

    log_step("Copying foundry-mcp config")
    foundry_mcp_config = home / ".config" / "foundry-mcp"
    if foundry_mcp_config.exists():
        copy_dir_to_container(
            container_id, str(foundry_mcp_config),
            f"{CONTAINER_HOME}/.config/foundry-mcp",
        )
    else:
        log_debug("~/.config/foundry-mcp not found, skipping")

    log_step("Configuring Foundry research providers")
    configure_foundry_research_providers(container_id)

    log_step("Ensuring Claude Foundry MCP")
    ensure_claude_foundry_mcp(container_id)

    log_step("Ensuring Foundry MCP workspace dirs")
    ensure_foundry_mcp_workspace_dirs(container_id, working_dir)

    log_step("Installing Foundry workspace docs")
    install_foundry_workspace_docs(container_id)

    log_step("Injecting sandbox branch context")
    inject_sandbox_branch_context(
        container_id,
        from_branch=from_branch,
        branch=branch,
        repo_url=repo_url,
    )


def _stage_fix_ownership(
    container_id: str,
    dirs: list[str],
    *,
    enable_ssh: bool,
    isolate_credentials: bool = True,
) -> None:
    """Stage 8: chown operations and SSH preflight."""
    from foundry_sandbox.container_setup import ssh_agent_preflight

    # Fix ownership on config dirs.  Always run as root explicitly so the
    # chown succeeds even when the container's default user is non-root
    # (i.e., when credential isolation is disabled).  Bind-mounted dirs
    # (e.g. .claude) may have a host UID that differs from UID 1000.
    log_step("Fixing ownership")
    for dir_path in dirs:
        subprocess.run(
            [
                "docker", "exec", "-u", "root", container_id,
                "chown", "-R", f"{CONTAINER_USER}:{CONTAINER_USER}",
                dir_path,
            ],
            check=False,
            capture_output=True,
            timeout=TIMEOUT_DOCKER_EXEC,
        )

    if enable_ssh:
        log_step("SSH agent preflight")
        ssh_agent_preflight(container_id)


def copy_configs_to_container(
    container_id: str,
    *,
    skip_plugins: bool = False,
    enable_ssh: bool = False,
    working_dir: str = "",
    isolate_credentials: bool = False,
    from_branch: str = "",
    branch: str = "",
    repo_url: str = "",
) -> None:
    """Copy configs and credentials to container.

    Master orchestrator for all config setup. Delegates to stage functions.

    Args:
        container_id: Container ID
        skip_plugins: Skip marketplace plugins sync
        enable_ssh: Enable SSH agent forwarding
        working_dir: Working directory for foundry workspace
        isolate_credentials: Use placeholder credentials instead of real ones
        from_branch: Source branch for git context
        branch: Current branch name
        repo_url: Repository URL
    """
    host_user = getpass.getuser()
    home = Path.home()

    _stage_setup_user(container_id)
    dirs = _stage_create_config_dirs(container_id)
    _stage_setup_claude_config(
        container_id, home,
        isolate_credentials=isolate_credentials,
        skip_plugins=skip_plugins,
    )
    _stage_setup_tool_configs(container_id, home)
    _stage_setup_credentials(
        container_id, home,
        isolate_credentials=isolate_credentials,
        enable_ssh=enable_ssh,
    )
    _stage_setup_git_config(container_id, home, host_user)
    _stage_setup_foundry(
        container_id, home,
        working_dir=working_dir,
        from_branch=from_branch,
        branch=branch,
        repo_url=repo_url,
    )
    _stage_fix_ownership(
        container_id, dirs,
        enable_ssh=enable_ssh,
        isolate_credentials=isolate_credentials,
    )

    if get_sandbox_debug():
        log_debug("Config copy complete")
        result = subprocess.run(
            ["docker", "exec", container_id, "ls", "-la", f"{CONTAINER_HOME}/.claude"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_DOCKER_EXEC,
        )
        if result.returncode == 0:
            log_debug(f"~/.claude contents:\n{result.stdout}")


def sync_runtime_credentials(
    container_id: str,
    isolate_credentials: bool = False,
) -> None:
    """Sync credentials when attaching to running container.

    Idempotent sync of credentials and configs. Uses quiet mode.
    When isolate_credentials is True, skips copying real credentials
    (gh config, Gemini OAuth, OpenCode auth) to preserve isolation.

    Args:
        container_id: Container ID
        isolate_credentials: If True, skip real credential copies
    """
    # Lazy imports
    from foundry_sandbox.foundry_plugin import (
        ensure_claude_foundry_mcp,
        ensure_foundry_mcp_config,
        sync_marketplace_manifests,
        configure_foundry_research_providers,
    )
    from foundry_sandbox.git_path_fixer import detect_nested_git_repos
    from foundry_sandbox.tool_configs import (
        ensure_claude_onboarding,
        ensure_claude_statusline,
        ensure_codex_config,
        ensure_gemini_settings,
    )
    home = Path.home()

    # Copy .codex dir (quiet) — only when NOT in isolation mode
    if not isolate_credentials:
        codex_dir = home / ".codex"
        if codex_dir.exists():
            copy_dir_to_container_quiet(
                container_id,
                str(codex_dir),
                f"{CONTAINER_HOME}/.codex",
            )

    # Copy .claude.json (quiet, to both locations)
    claude_json = home / ".claude.json"
    if claude_json.exists():
        copy_file_to_container_quiet(
            container_id,
            str(claude_json),
            f"{CONTAINER_HOME}/.claude.json",
        )
        copy_file_to_container_quiet(
            container_id,
            str(claude_json),
            f"{CONTAINER_HOME}/.claude/.claude.json",
        )

    # Ensure Claude onboarding (quiet)
    ensure_claude_onboarding(container_id, quiet=True)

    # Ensure foundry MCP config (quiet)
    ensure_foundry_mcp_config(container_id, quiet=True)

    # Merge host settings.json into container settings (quiet)
    settings_json = home / ".claude" / "settings.json"
    if settings_json.exists():
        if isolate_credentials:
            ok = _merge_claude_settings_safe(container_id, str(settings_json))
        else:
            ok = _merge_claude_settings_in_container(container_id, str(settings_json))
        if not ok:
            log_warn("Claude settings merge was incomplete; some settings may be missing")

    # Copy statusline.conf (quiet)
    statusline_conf = home / ".claude" / "statusline.conf"
    if not statusline_conf.exists():
        script_dir = Path(os.environ.get("SCRIPT_DIR", "/workspace"))
        statusline_conf = script_dir / "statusline.conf"
    if statusline_conf.exists():
        copy_file_to_container_quiet(
            container_id,
            str(statusline_conf),
            f"{CONTAINER_HOME}/.claude/statusline.conf",
        )

    # Ensure Claude Foundry MCP (quiet)
    ensure_claude_foundry_mcp(container_id, quiet=True)

    # Ensure Claude statusline (quiet)
    ensure_claude_statusline(container_id, quiet=True)

    # Sync marketplace manifests (quiet)
    sync_marketplace_manifests(container_id, f"{CONTAINER_HOME}/.claude/marketplace_plugins", quiet=True)

    # Copy real credentials only when NOT in isolation mode
    if not isolate_credentials:
        # Copy gh config (quiet)
        gh_config = home / ".config" / "gh"
        if gh_config.exists():
            copy_dir_to_container_quiet(
                container_id,
                str(gh_config),
                f"{CONTAINER_HOME}/.config/gh",
            )

        # Copy Gemini config (quiet)
        gemini_oauth = home / ".gemini" / "oauth_creds.json"
        if gemini_oauth.exists():
            copy_file_to_container_quiet(
                container_id,
                str(gemini_oauth),
                f"{CONTAINER_HOME}/.gemini/oauth_creds.json",
            )

        # Copy OpenCode auth (quiet)
        opencode_auth = home / ".config" / "opencode" / "auth.json"
        if opencode_auth.exists():
            copy_file_to_container_quiet(
                container_id,
                str(opencode_auth),
                f"{CONTAINER_HOME}/.config/opencode/auth.json",
            )

    # Ensure Gemini settings (quiet)
    ensure_gemini_settings(container_id, quiet=True)

    # Ensure Codex config (quiet)
    ensure_codex_config(container_id, quiet=True)

    # Copy foundry-mcp config (quiet)
    foundry_mcp_config = home / ".config" / "foundry-mcp"
    if foundry_mcp_config.exists():
        copy_dir_to_container_quiet(
            container_id,
            str(foundry_mcp_config),
            f"{CONTAINER_HOME}/.config/foundry-mcp",
        )

    # Configure research providers
    configure_foundry_research_providers(container_id, quiet=True)

    # Detect nested git repos
    detect_nested_git_repos(container_id)

    if get_sandbox_debug():
        log_debug("Runtime credential sync complete")
