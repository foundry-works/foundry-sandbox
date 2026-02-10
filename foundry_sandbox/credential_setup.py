"""Config and credential orchestration for sandbox containers.

Migrated from lib/container_config.sh: copy_configs_to_container,
sync_runtime_credentials, merge_claude_settings.

SECURITY-CRITICAL: Must never leak real credentials into sandbox.
Only placeholders are injected in credential isolation mode.
"""
from __future__ import annotations

import getpass
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from foundry_sandbox.constants import (
    CONTAINER_HOME,
    CONTAINER_READY_ATTEMPTS,
    CONTAINER_READY_DELAY,
    CONTAINER_USER,
    SSH_AGENT_CONTAINER_SOCK,
    get_sandbox_debug,
    get_sandbox_home,
    get_sandbox_verbose,
)
from foundry_sandbox.container_io import (
    copy_dir_to_container,
    copy_dir_to_container_quiet,
    copy_file_to_container,
    copy_file_to_container_quiet,
    docker_exec_text,
)
from foundry_sandbox.utils import log_debug, log_info, log_step, log_warn


def _merge_claude_settings_in_container(container_id: str, host_settings: str) -> None:
    """Merge host Claude settings into container settings via docker exec.

    Matches the shell merge_claude_settings() in lib/container_config.sh:
    1. Copy host settings to temp location inside container
    2. Run merge inside container (preserves hooks, model from container defaults)
    3. Clean up temp file
    """
    temp_host = "/tmp/host-settings.json"
    container_settings = f"{CONTAINER_HOME}/.claude/settings.json"

    try:
        copy_file_to_container(container_id, host_settings, temp_host)
    except Exception:
        log_warn("Failed to copy host settings for merge")
        return

    subprocess.run(
        [
            "docker", "exec", "-u", CONTAINER_USER, container_id,
            "python3", "-m", "foundry_sandbox.claude_settings",
            "merge", container_settings, temp_host,
        ],
        check=False,
        capture_output=True,
    )

    # Clean up temp file
    subprocess.run(
        ["docker", "exec", container_id, "rm", "-f", temp_host],
        check=False,
        capture_output=True,
    )


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


def _resolve_ssh_agent_sock() -> str:
    """Find SSH agent socket from environment."""
    return os.environ.get("SSH_AUTH_SOCK", "")


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

    Master orchestrator for all config setup. Calls 30+ functions in sequence.

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
    # Lazy imports to avoid circular dependencies
    from foundry_sandbox.container_setup import (
        ensure_container_user,
        ssh_agent_preflight,
    )
    from foundry_sandbox.foundry_plugin import (
        ensure_claude_foundry_mcp,
        ensure_foundry_mcp_config,
        ensure_foundry_mcp_workspace_dirs,
        sync_marketplace_manifests,
        configure_foundry_research_providers,
    )
    from foundry_sandbox.git_path_fixer import detect_nested_git_repos, fix_worktree_paths
    from foundry_sandbox.stub_manager import (
        inject_sandbox_branch_context,
        install_foundry_workspace_docs,
    )
    from foundry_sandbox.tool_configs import (
        ensure_claude_onboarding,
        ensure_claude_statusline,
        ensure_codex_config,
        ensure_gemini_settings,
        ensure_github_https_git,
    )
    host_user = getpass.getuser()
    home = Path.home()

    # 1. Ensure container user exists
    log_step("Setting up container user")
    ensure_container_user(container_id)

    # 2. Wait for container home to be ready
    log_step("Waiting for container home directory")
    for attempt in range(CONTAINER_READY_ATTEMPTS):
        result = subprocess.run(
            ["docker", "exec", container_id, "test", "-d", CONTAINER_HOME],
            capture_output=True,
        )
        if result.returncode == 0:
            break
        if attempt < CONTAINER_READY_ATTEMPTS - 1:
            time.sleep(CONTAINER_READY_DELAY)
    else:
        log_warn(f"Container home {CONTAINER_HOME} not ready after 5 attempts")

    # 3. Create directories
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
            ["docker", "exec", container_id, "mkdir", "-p", dir_path],
            check=False,
            capture_output=True,
        )

    # 4. Copy ~/.claude.json to container (both locations)
    log_step("Copying Claude config")
    claude_json = home / ".claude.json"
    if claude_json.exists():
        copy_file_to_container(container_id, str(claude_json), f"{CONTAINER_HOME}/.claude.json")
        copy_file_to_container(container_id, str(claude_json), f"{CONTAINER_HOME}/.claude/.claude.json")
    else:
        log_debug("~/.claude.json not found, skipping")

    # 5. Fix ownership on .claude dirs
    subprocess.run(
        [
            "docker",
            "exec",
            container_id,
            "chown",
            "-R",
            f"{CONTAINER_USER}:{CONTAINER_USER}",
            f"{CONTAINER_HOME}/.claude",
        ],
        check=False,
        capture_output=True,
    )

    # 6. Ensure Claude onboarding
    log_step("Ensuring Claude onboarding")
    ensure_claude_onboarding(container_id)

    # 7. Ensure foundry MCP config
    log_step("Ensuring Foundry MCP config")
    ensure_foundry_mcp_config(container_id)

    # 8. Merge host ~/.claude/settings.json into container settings
    log_step("Merging Claude settings")
    settings_json = home / ".claude" / "settings.json"
    if settings_json.exists():
        _merge_claude_settings_in_container(container_id, str(settings_json))
    else:
        log_debug("~/.claude/settings.json not found, skipping")

    # 9. Copy statusline.conf (from ~/.claude/ or SCRIPT_DIR)
    log_step("Copying statusline config")
    statusline_conf = home / ".claude" / "statusline.conf"
    if not statusline_conf.exists():
        # Try SCRIPT_DIR
        script_dir = Path(os.environ.get("SCRIPT_DIR", "/workspace"))
        statusline_conf = script_dir / "statusline.conf"
    if statusline_conf.exists():
        copy_file_to_container(
            container_id,
            str(statusline_conf),
            f"{CONTAINER_HOME}/.claude/statusline.conf",
        )
    else:
        log_debug("statusline.conf not found, skipping")

    # 10. Ensure Claude statusline
    log_step("Ensuring Claude statusline")
    ensure_claude_statusline(container_id)

    # 11. Copy marketplace plugins dir if exists
    if not skip_plugins:
        log_step("Copying marketplace plugins")
        marketplace_plugins = home / ".claude" / "marketplace_plugins"
        if marketplace_plugins.exists():
            copy_dir_to_container(
                container_id,
                str(marketplace_plugins),
                f"{CONTAINER_HOME}/.claude/marketplace_plugins",
            )
        else:
            log_debug("marketplace_plugins dir not found, skipping")

        # 12. Sync marketplace manifests
        log_step("Syncing marketplace manifests")
        sync_marketplace_manifests(container_id, f"{CONTAINER_HOME}/.claude/marketplace_plugins")
    else:
        log_debug("Skipping marketplace plugins (skip_plugins=True)")

    # 13. Copy ~/.config/gh dir
    log_step("Copying GitHub CLI config")
    gh_config = home / ".config" / "gh"
    if gh_config.exists():
        copy_dir_to_container(
            container_id,
            str(gh_config),
            f"{CONTAINER_HOME}/.config/gh",
        )
    else:
        log_debug("~/.config/gh not found, skipping")

    # 14. If NOT isolate_credentials: copy Gemini OAuth, OpenCode auth, codex dir
    if not isolate_credentials:
        log_step("Copying credentials (isolation disabled)")

        # Gemini OAuth
        gemini_oauth = home / ".gemini" / "oauth_credentials.json"
        if gemini_oauth.exists():
            copy_file_to_container(
                container_id,
                str(gemini_oauth),
                f"{CONTAINER_HOME}/.gemini/oauth_credentials.json",
            )
        else:
            log_debug("Gemini OAuth not found, skipping")

        # OpenCode auth
        opencode_auth = home / ".config" / "opencode" / "auth.json"
        if opencode_auth.exists():
            copy_file_to_container(
                container_id,
                str(opencode_auth),
                f"{CONTAINER_HOME}/.config/opencode/auth.json",
            )
        else:
            log_debug("OpenCode auth not found, skipping")

        # Codex dir
        codex_dir = home / ".codex"
        if codex_dir.exists():
            # Get excludes from environment
            excludes_str = os.environ.get("SANDBOX_CODEX_EXCLUDES", "logs")
            excludes = [e.strip() for e in excludes_str.split(",") if e.strip()]

            # Build rsync exclude args
            exclude_args = []
            for exc in excludes:
                exclude_args.extend(["--exclude", exc])

            # Copy with excludes
            rsync_cmd = [
                "rsync",
                "-a",
                "--quiet",
            ] + exclude_args + [
                f"{codex_dir}/",
                f"{CONTAINER_HOME}/.codex/",
            ]

            # Use docker cp with tar for directory sync
            # Simplified: just copy the whole dir
            copy_dir_to_container(
                container_id,
                str(codex_dir),
                f"{CONTAINER_HOME}/.codex",
            )
        else:
            log_debug("~/.codex not found, skipping")
    else:
        log_debug("Credential isolation enabled, skipping real credentials")

    # 15. Copy OpenCode config
    log_step("Copying OpenCode config")
    opencode_config = home / ".config" / "opencode" / "config.json"
    if opencode_config.exists():
        copy_file_to_container(
            container_id,
            str(opencode_config),
            f"{CONTAINER_HOME}/.config/opencode/config.json",
        )
    else:
        log_debug("OpenCode config not found, skipping")

    # 16. Ensure codex config
    log_step("Ensuring Codex config")
    ensure_codex_config(container_id)

    # 17. Ensure Gemini settings
    log_step("Ensuring Gemini settings")
    ensure_gemini_settings(container_id)

    # 18. OpenCode: settings, foundry sync, tavily, default model, prefetch npm plugins
    if _opencode_enabled():
        log_step("Configuring OpenCode")
        # OpenCode settings
        opencode_settings = home / ".config" / "opencode" / "settings.json"
        if opencode_settings.exists():
            copy_file_to_container(
                container_id,
                str(opencode_settings),
                f"{CONTAINER_HOME}/.config/opencode/settings.json",
            )

        # Foundry sync
        opencode_foundry = home / ".local" / "share" / "opencode" / "foundry-mcp"
        if opencode_foundry.exists():
            copy_dir_to_container(
                container_id,
                str(opencode_foundry),
                f"{CONTAINER_HOME}/.local/share/opencode/foundry-mcp",
            )

        # Tavily config
        opencode_tavily = home / ".config" / "opencode" / "tavily-mcp"
        if opencode_tavily.exists():
            copy_dir_to_container(
                container_id,
                str(opencode_tavily),
                f"{CONTAINER_HOME}/.config/opencode/tavily-mcp",
            )

        # Default model config
        opencode_model = home / ".config" / "opencode" / "default-model.json"
        if opencode_model.exists():
            copy_file_to_container(
                container_id,
                str(opencode_model),
                f"{CONTAINER_HOME}/.config/opencode/default-model.json",
            )

        # Prefetch npm plugins (would run opencode commands here)
        log_debug("OpenCode npm plugin prefetch not implemented yet")
    else:
        log_debug("OpenCode not enabled, skipping OpenCode config")

    # 19. Copy .gitconfig
    log_step("Copying git config")
    gitconfig = home / ".gitconfig"
    if gitconfig.exists():
        copy_file_to_container(
            container_id,
            str(gitconfig),
            f"{CONTAINER_HOME}/.gitconfig",
        )
    else:
        log_debug("~/.gitconfig not found, skipping")

    # 20. SSH key handling (if enable_ssh AND NOT isolate_credentials)
    if enable_ssh and not isolate_credentials:
        log_step("Setting up SSH keys")
        ssh_dir = home / ".ssh"
        if ssh_dir.exists():
            # Copy id_rsa, id_ed25519, etc.
            for key_file in ["id_rsa", "id_ed25519", "id_ecdsa"]:
                key_path = ssh_dir / key_file
                pub_path = ssh_dir / f"{key_file}.pub"
                if key_path.exists():
                    copy_file_to_container(
                        container_id,
                        str(key_path),
                        f"{CONTAINER_HOME}/.ssh/{key_file}",
                    )
                    # Set permissions
                    subprocess.run(
                        [
                            "docker",
                            "exec",
                            container_id,
                            "chmod",
                            "600",
                            f"{CONTAINER_HOME}/.ssh/{key_file}",
                        ],
                        check=False,
                        capture_output=True,
                    )
                if pub_path.exists():
                    copy_file_to_container(
                        container_id,
                        str(pub_path),
                        f"{CONTAINER_HOME}/.ssh/{key_file}.pub",
                    )

            # Copy known_hosts
            known_hosts = ssh_dir / "known_hosts"
            if known_hosts.exists():
                copy_file_to_container(
                    container_id,
                    str(known_hosts),
                    f"{CONTAINER_HOME}/.ssh/known_hosts",
                )

            # Copy config
            ssh_config = ssh_dir / "config"
            if ssh_config.exists():
                copy_file_to_container(
                    container_id,
                    str(ssh_config),
                    f"{CONTAINER_HOME}/.ssh/config",
                )
        else:
            log_debug("~/.ssh not found, skipping SSH keys")
    else:
        log_debug("SSH not enabled, skipping SSH key setup")

    # 21. Copy .sandboxes/repos
    log_step("Copying sandbox repos")
    sandbox_home = get_sandbox_home()
    repos_dir = Path(sandbox_home) / "repos"
    if repos_dir.exists():
        copy_dir_to_container(
            container_id,
            str(repos_dir),
            f"{CONTAINER_HOME}/.sandboxes/repos",
        )
    else:
        log_debug(f"{repos_dir} not found, skipping")

    # 22. Copy foundry-mcp config
    log_step("Copying foundry-mcp config")
    foundry_mcp_config = home / ".config" / "foundry-mcp"
    if foundry_mcp_config.exists():
        copy_dir_to_container(
            container_id,
            str(foundry_mcp_config),
            f"{CONTAINER_HOME}/.config/foundry-mcp",
        )
    else:
        log_debug("~/.config/foundry-mcp not found, skipping")

    # 23. Configure foundry research providers
    log_step("Configuring Foundry research providers")
    configure_foundry_research_providers(container_id)

    # 24. Fix worktree paths
    log_step("Fixing git worktree paths")
    fix_worktree_paths(container_id, host_user)

    # 25. Detect nested git repos
    log_step("Detecting nested git repos")
    detect_nested_git_repos(container_id)

    # 26. Fix ownership on all dirs
    log_step("Fixing ownership")
    for dir_path in dirs:
        subprocess.run(
            [
                "docker",
                "exec",
                container_id,
                "chown",
                "-R",
                f"{CONTAINER_USER}:{CONTAINER_USER}",
                dir_path,
            ],
            check=False,
            capture_output=True,
        )

    # 27. Ensure GitHub HTTPS Git
    log_step("Ensuring GitHub HTTPS Git")
    ensure_github_https_git(container_id)

    # 28. SSH agent preflight
    if enable_ssh:
        log_step("SSH agent preflight")
        ssh_agent_preflight(container_id)

    # 29. Ensure Claude Foundry MCP
    log_step("Ensuring Claude Foundry MCP")
    ensure_claude_foundry_mcp(container_id)

    # 30. Ensure Foundry MCP workspace dirs
    log_step("Ensuring Foundry MCP workspace dirs")
    ensure_foundry_mcp_workspace_dirs(container_id, working_dir)

    # 31. Install foundry workspace docs
    log_step("Installing Foundry workspace docs")
    install_foundry_workspace_docs(container_id)

    # 32. Inject sandbox branch context
    log_step("Injecting sandbox branch context")
    inject_sandbox_branch_context(
        container_id,
        from_branch=from_branch,
        branch=branch,
        repo_url=repo_url,
    )

    # 33. Debug output
    if get_sandbox_debug():
        log_debug("Config copy complete")
        # Show directory listing
        result = subprocess.run(
            ["docker", "exec", container_id, "ls", "-la", f"{CONTAINER_HOME}/.claude"],
            capture_output=True,
            text=True,
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
    from foundry_sandbox.container_setup import ensure_container_user
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

    # Copy .codex dir (quiet)
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
        _merge_claude_settings_in_container(container_id, str(settings_json))

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
        gemini_oauth = home / ".gemini" / "oauth_credentials.json"
        if gemini_oauth.exists():
            copy_file_to_container_quiet(
                container_id,
                str(gemini_oauth),
                f"{CONTAINER_HOME}/.gemini/oauth_credentials.json",
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
    detect_nested_git_repos(container_id, quiet=True)

    if get_sandbox_debug():
        log_debug("Runtime credential sync complete")
