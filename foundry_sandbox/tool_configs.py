"""Tool-specific configuration for sandbox containers.

Migrated from lib/container_config.sh: ensure_claude_onboarding, ensure_claude_statusline,
ensure_github_https_git, configure_gh_credential_helper, ensure_codex_config,
ensure_gemini_settings, ensure_opencode_settings, ensure_opencode_default_model,
ensure_opencode_tavily_mcp, sync_opencode_foundry, prefetch_opencode_npm_plugins,
sync_opencode_local_plugins_on_first_attach.
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from foundry_sandbox.constants import (
    CONTAINER_HOME,
    CONTAINER_OPENCODE_PLUGIN_DIR,
    CONTAINER_USER,
    TIMEOUT_DOCKER_EXEC,
    get_sandbox_home,
    get_sandbox_opencode_default_model,
    get_sandbox_opencode_disable_npm_plugins,
    get_sandbox_opencode_plugin_dir,
    get_sandbox_opencode_prefetch_npm_plugins,
)
from foundry_sandbox.paths import ensure_dir, path_opencode_plugins_marker
from foundry_sandbox.utils import log_debug, log_info, log_step, log_warn


# Directory containing extracted Python scripts for in-container execution
_SCRIPT_DIR = Path(__file__).resolve().parent.parent / "lib" / "python"


def _read_script(name: str) -> str:
    """Read a Python script from lib/python/ for in-container execution."""
    return (_SCRIPT_DIR / name).read_text()


# ============================================================================
# Helper Functions
# ============================================================================


def _docker_exec_python(
    container_id: str,
    script: str,
    *,
    quiet: bool = False,
) -> None:
    """Execute a Python script inside the container via docker exec.

    Args:
        container_id: Container ID
        script: Python script to execute
        quiet: If True, suppress output
    """
    cmd = ["docker", "exec", "-u", CONTAINER_USER, "-i", container_id, "python3", "-"]

    if not quiet:
        log_debug(f"Running Python script in container {container_id}")

    result = subprocess.run(
        cmd,
        input=script,
        text=True,
        capture_output=quiet,
        check=True,
        timeout=TIMEOUT_DOCKER_EXEC,
    )


def _docker_exec_sh(
    container_id: str,
    command: str,
    *,
    quiet: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Execute a shell command inside the container.

    Args:
        container_id: Container ID
        command: Shell command to execute
        quiet: If True, suppress output
        check: If True, raise on non-zero exit

    Returns:
        CompletedProcess instance
    """
    cmd = ["docker", "exec", "-u", CONTAINER_USER, container_id, "sh", "-c", command]

    return subprocess.run(
        cmd,
        capture_output=quiet,
        text=True,
        check=check,
        timeout=TIMEOUT_DOCKER_EXEC,
    )


# ============================================================================
# Claude Configuration
# ============================================================================


def ensure_claude_onboarding(container_id: str, *, quiet: bool = False) -> None:
    """Set Claude onboarding flags and defaults in ~/.claude.json.

    Migrated from lib/container_config.sh:ensure_claude_onboarding (L1230-1284).
    Sets hasCompletedOnboarding=True, githubRepoPaths={}, projects={},
    skillUsage={}, autoUpdates=False, autoCompactEnabled=False in both
    ~/.claude.json and ~/.claude/.claude.json.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    _docker_exec_python(container_id, _read_script("ensure_claude_onboarding.py"), quiet=quiet)


def ensure_claude_statusline(container_id: str, *, quiet: bool = False) -> None:
    """Configure claude-statusline in Claude settings if binary exists.

    Migrated from lib/container_config.sh:ensure_claude_statusline (L1141-1228).
    If claude-statusline binary exists, sets statusLine config to use it.
    If binary is missing, removes statusLine config.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    # Check if binary exists
    check_binary = (
        f"command -v claude-statusline >/dev/null 2>&1 || "
        f"[ -x {CONTAINER_HOME}/.local/bin/claude-statusline ]"
    )
    binary_result = _docker_exec_sh(
        container_id, check_binary, quiet=True, check=False
    )
    binary_exists = binary_result.returncode == 0

    # Check if statusLine is configured
    check_config = (
        f"test -f {CONTAINER_HOME}/.claude/settings.json && "
        f"grep -q '\"statusLine\"' {CONTAINER_HOME}/.claude/settings.json"
    )
    config_result = _docker_exec_sh(
        container_id, check_config, quiet=True, check=False
    )
    statusline_configured = config_result.returncode == 0

    if binary_exists:
        # Binary exists - ensure config uses the bundled binary
        if statusline_configured:
            # Check if current command uses bundled binary
            check_bundled = (
                f"grep -q '\"command\": \"claude-statusline\"' "
                f"{CONTAINER_HOME}/.claude/settings.json 2>/dev/null"
            )
            bundled_result = _docker_exec_sh(
                container_id, check_bundled, quiet=True, check=False
            )
            if bundled_result.returncode == 0:
                return  # Already using bundled binary

        # Set statusLine configuration to use bundled binary
        script = '_ACTION = "set"\n' + _read_script("ensure_claude_statusline.py")
        _docker_exec_python(container_id, script, quiet=quiet)
    else:
        # Binary missing - remove config if present
        if not statusline_configured:
            return  # Not configured, nothing to do

        script = '_ACTION = "remove"\n' + _read_script("ensure_claude_statusline.py")
        _docker_exec_python(container_id, script, quiet=quiet)
        if not quiet:
            log_warn(
                "claude-statusline not found; removing statusLine from Claude settings "
                "inside sandbox. Install cc-context-stats in the container to enable it."
            )


# ============================================================================
# GitHub Configuration
# ============================================================================


def ensure_github_https_git(
    container_id: str, *, quiet: bool = False, enable_ssh: bool = False
) -> None:
    """Force HTTPS for GitHub Git remotes (unless SSH is enabled).

    Migrated from lib/container_config.sh:ensure_github_https_git (L1085-1114).
    Unsets SSH insteadOf configs and adds HTTPS insteadOf.
    Calls configure_gh_credential_helper after.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
        enable_ssh: If True, skip HTTPS forcing (SSH handles auth)
    """
    if enable_ssh:
        return

    if not quiet:
        log_debug("Forcing HTTPS for GitHub Git remotes (SSH disabled)...")

    command = f"""
        export HOME='{CONTAINER_HOME}'
        cd '{CONTAINER_HOME}' || exit 0
        git config --global --unset-all url."git@github.com:".insteadOf 2>/dev/null || true
        git config --global --unset-all url."ssh://git@github.com/".insteadOf 2>/dev/null || true
        git config --global --unset-all url."git@github.com:".pushInsteadOf 2>/dev/null || true
        git config --global --unset-all url."ssh://git@github.com/".pushInsteadOf 2>/dev/null || true
        git config --global --unset-all url."https://github.com/".insteadOf 2>/dev/null || true
        git config --global --add url."https://github.com/".insteadOf git@github.com: 2>/dev/null || true
        git config --global --add url."https://github.com/".insteadOf ssh://git@github.com/ 2>/dev/null || true
    """
    _docker_exec_sh(container_id, command, quiet=quiet)

    # Configure gh as credential helper after URL rewriting
    configure_gh_credential_helper(container_id, quiet=quiet)


def configure_gh_credential_helper(container_id: str, *, quiet: bool = False) -> None:
    """Configure gh as the git credential helper for HTTPS authentication.

    Migrated from lib/container_config.sh:configure_gh_credential_helper (L1119-1139).
    Leverages existing gh auth credentials from ~/.config/gh.
    Skips when SANDBOX_GATEWAY_ENABLED=true.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    # Skip when credential isolation gateway is enabled
    if os.environ.get("SANDBOX_GATEWAY_ENABLED") == "true":
        if not quiet:
            log_debug("Skipping gh credential helper (gateway enabled)")
        return

    # Only configure if gh config exists in container
    command = f"""
        export HOME='{CONTAINER_HOME}'
        if [ -d '{CONTAINER_HOME}/.config/gh' ] && command -v gh >/dev/null 2>&1; then
            git config --global credential.helper '!gh auth git-credential'
        fi
    """
    subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, container_id, "sh", "-c", command],
        capture_output=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )


# ============================================================================
# Codex Configuration
# ============================================================================


def ensure_codex_config(container_id: str, *, quiet: bool = False) -> None:
    """Configure Codex defaults in ~/.codex/config.toml.

    Migrated from lib/container_config.sh:ensure_codex_config (L1382-1509).
    Sets approval_policy="on-failure", sandbox_mode="danger-full-access",
    check_for_update_on_startup=false, analytics.enabled=false.
    Adds tavily-mcp if SANDBOX_ENABLE_TAVILY=1.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    if not quiet:
        log_step("Codex: setting defaults (no updates/analytics)")

    # Pass SANDBOX_ENABLE_TAVILY to container
    enable_tavily = os.environ.get("SANDBOX_ENABLE_TAVILY", "0")

    script = _read_script("ensure_codex_config.py")

    cmd = [
        "docker", "exec",
        "-u", CONTAINER_USER,
        "-e", f"SANDBOX_ENABLE_TAVILY={enable_tavily}",
        "-i", container_id,
        "python3", "-"
    ]

    subprocess.run(
        cmd,
        input=script,
        text=True,
        capture_output=quiet,
        check=True,
        timeout=TIMEOUT_DOCKER_EXEC,
    )


# ============================================================================
# Gemini Configuration
# ============================================================================


def ensure_gemini_settings(container_id: str, *, quiet: bool = False) -> None:
    """Configure Gemini defaults in ~/.gemini/settings.json.

    Migrated from lib/container_config.sh:ensure_gemini_settings (L1512-1597).
    Sets general.disableAutoUpdate=true, general.disableUpdateNag=true,
    general.previewFeatures=true, telemetry.enabled=false,
    privacy.usageStatisticsEnabled=false.
    Adds tavily-mcp to mcpServers if SANDBOX_ENABLE_TAVILY=1.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    if not quiet:
        log_step("Gemini: setting defaults (no updates/telemetry)")

    enable_tavily = os.environ.get("SANDBOX_ENABLE_TAVILY", "0")

    script = _read_script("ensure_gemini_settings.py")

    cmd = [
        "docker", "exec",
        "-u", CONTAINER_USER,
        "-e", f"SANDBOX_ENABLE_TAVILY={enable_tavily}",
        "-i", container_id,
        "python3", "-"
    ]

    subprocess.run(
        cmd,
        input=script,
        text=True,
        capture_output=quiet,
        check=True,
        timeout=TIMEOUT_DOCKER_EXEC,
    )


# ============================================================================
# OpenCode Configuration
# ============================================================================


def ensure_opencode_settings(container_id: str, *, quiet: bool = False) -> None:
    """Set OpenCode autoupdate to off in ~/.config/opencode/opencode.json.

    Migrated from lib/container_config.sh:ensure_opencode_settings (L601-644).

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    if not quiet:
        log_step("OpenCode: setting defaults (no autoupdate)")

    _docker_exec_python(container_id, _read_script("ensure_opencode_settings.py"), quiet=quiet)


def ensure_opencode_default_model(container_id: str, *, quiet: bool = False) -> None:
    """Set default model in OpenCode config if not already set.

    Migrated from lib/container_config.sh:ensure_opencode_default_model (L646-687).
    Uses SANDBOX_OPENCODE_DEFAULT_MODEL environment variable.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    default_model = get_sandbox_opencode_default_model()
    if not default_model:
        return

    script = _read_script("ensure_opencode_default_model.py")

    cmd = [
        "docker", "exec",
        "-u", CONTAINER_USER,
        "-e", f"SANDBOX_OPENCODE_DEFAULT_MODEL={default_model}",
        "-i", container_id,
        "python3", "-"
    ]

    subprocess.run(
        cmd,
        input=script,
        text=True,
        capture_output=quiet,
        check=True,
        timeout=TIMEOUT_DOCKER_EXEC,
    )


def ensure_opencode_tavily_mcp(container_id: str, *, quiet: bool = False) -> None:
    """Add tavily-mcp to OpenCode's MCP configuration.

    Migrated from lib/container_config.sh:ensure_opencode_tavily_mcp (L551-599).
    Only configures if SANDBOX_ENABLE_TAVILY=1.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    # Skip if Tavily is not enabled
    if os.environ.get("SANDBOX_ENABLE_TAVILY", "0") != "1":
        return

    _docker_exec_python(container_id, _read_script("ensure_opencode_tavily.py"), quiet=quiet)


def sync_opencode_foundry(container_id: str, *, quiet: bool = False) -> None:
    """Sync opencode-foundry config from vendor repo.

    Migrated from lib/container_config.sh:sync_opencode_foundry (L455-549).
    This is a stub that calls the opencode_sync module inside the container.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    # This function is complex and depends on external repo checkout
    # For now, we'll implement a minimal version that logs a warning
    # The full implementation would need:
    # 1. Check/clone opencode-foundry repo
    # 2. Copy skills dir to container
    # 3. Run opencode_sync module inside container

    if not quiet:
        log_debug("sync_opencode_foundry: not fully implemented yet")


def prefetch_opencode_npm_plugins(container_id: str, *, quiet: bool = False) -> None:
    """Prefetch OpenCode npm plugins inside container.

    Migrated from lib/container_config.sh:prefetch_opencode_npm_plugins (L689-829).
    Only runs if SANDBOX_OPENCODE_PREFETCH_NPM_PLUGINS=1.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    if get_sandbox_opencode_prefetch_npm_plugins() != 1:
        return

    if not quiet:
        log_info("Prefetching OpenCode npm plugins...")

    script = _read_script("prefetch_opencode_plugins.py")

    result = subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, "-i", container_id, "python3", "-"],
        input=script,
        text=True,
        capture_output=quiet,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    if result.returncode != 0 and not quiet:
        log_warn("Failed to prefetch OpenCode npm plugins")


def sync_opencode_local_plugins_on_first_attach(
    name: str, container_id: str, *, quiet: bool = False
) -> None:
    """Copy local plugin directory to container on first attach.

    Migrated from lib/container_config.sh:sync_opencode_local_plugins_on_first_attach (L831-886).

    Args:
        name: Sandbox name
        container_id: Container ID
        quiet: If True, suppress output
    """
    host_dir = get_sandbox_opencode_plugin_dir()
    if not host_dir:
        return

    host_path = Path(host_dir).expanduser()
    if not host_path.is_dir():
        if not quiet:
            log_warn(f"OpenCode local plugin dir not found: {host_path}")
        return

    marker = path_opencode_plugins_marker(name)

    has_container_plugins = (
        subprocess.run(
            [
                "docker",
                "exec",
                container_id,
                "sh",
                "-c",
                f"test -d '{CONTAINER_OPENCODE_PLUGIN_DIR}' && "
                f"[ \"$(ls -A '{CONTAINER_OPENCODE_PLUGIN_DIR}' 2>/dev/null)\" ]",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=TIMEOUT_DOCKER_EXEC,
        ).returncode
        == 0
    )

    if marker.exists() and has_container_plugins:
        if not quiet:
            log_debug("OpenCode local plugins already synced.")
        return

    if not quiet:
        log_info(f"Syncing OpenCode local plugins from {host_path}...")

    subprocess.run(
        ["docker", "exec", container_id, "mkdir", "-p", CONTAINER_OPENCODE_PLUGIN_DIR],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    copy_result = subprocess.run(
        ["docker", "cp", f"{host_path}/.", f"{container_id}:{CONTAINER_OPENCODE_PLUGIN_DIR}"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    if copy_result.returncode != 0:
        if not quiet:
            log_warn(f"Failed to sync OpenCode local plugins from {host_path}")
        return

    chown_result = subprocess.run(
        [
            "docker",
            "exec",
            "-u",
            "root",
            container_id,
            "chown",
            "-R",
            f"{CONTAINER_USER}:{CONTAINER_USER}",
            CONTAINER_OPENCODE_PLUGIN_DIR,
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=TIMEOUT_DOCKER_EXEC,
    )
    if chown_result.returncode != 0:
        if not quiet:
            log_warn(f"Failed to set ownership on synced OpenCode plugins in {container_id}")
        return

    ensure_dir(marker.parent)
    marker.write_text(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") + "\n")
    try:
        marker.chmod(0o600)
    except OSError:
        pass

    sync_opencode_foundry(container_id, quiet=quiet)
    ensure_opencode_tavily_mcp(container_id, quiet=quiet)


# ============================================================================
# Wrapper Functions (for test compatibility)
# ============================================================================


def configure_claude(container_id: str, *, quiet: bool = False) -> None:
    """Configure Claude inside the container.

    Wrapper function that calls ensure_claude_onboarding and ensure_claude_statusline.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    ensure_claude_onboarding(container_id, quiet=quiet)
    ensure_claude_statusline(container_id, quiet=quiet)


def configure_codex(container_id: str, *, quiet: bool = False) -> None:
    """Configure Codex inside the container.

    Wrapper function that calls ensure_codex_config.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    ensure_codex_config(container_id, quiet=quiet)


def configure_gemini(container_id: str, *, quiet: bool = False) -> None:
    """Configure Gemini inside the container.

    Wrapper function that calls ensure_gemini_settings.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    ensure_gemini_settings(container_id, quiet=quiet)


def configure_gh(
    container_id: str, *, quiet: bool = False, enable_ssh: bool = False
) -> None:
    """Configure GitHub CLI inside the container.

    Wrapper function that calls ensure_github_https_git.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
        enable_ssh: If True, skip HTTPS forcing (SSH handles auth)
    """
    ensure_github_https_git(container_id, quiet=quiet, enable_ssh=enable_ssh)


def configure_opencode(container_id: str, *, quiet: bool = False) -> None:
    """Configure OpenCode inside the container.

    Wrapper function that calls ensure_opencode_settings, ensure_opencode_default_model,
    and ensure_opencode_tavily_mcp.

    Args:
        container_id: Container ID
        quiet: If True, suppress output
    """
    ensure_opencode_settings(container_id, quiet=quiet)
    ensure_opencode_default_model(container_id, quiet=quiet)
    ensure_opencode_tavily_mcp(container_id, quiet=quiet)
