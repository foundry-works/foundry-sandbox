"""Start command — start a stopped sandbox container.

Migrated from commands/start.sh. Performs the following sequence:
  1. Derive sandbox paths and check worktree exists
  2. Check image freshness (shell fallback)
  3. Load sandbox metadata and export enable flags
  4. Detect credential isolation mode
  5. Log credential warnings
  6. Setup override file from metadata (shell fallback)
  7. Setup Claude home directory
  8. Handle SSH agent forwarding
  9. Export GitHub token (shell fallback)
  10. Handle credential isolation: stubs volume, HMAC secrets, ALLOW_PR_OPERATIONS
  11. Start containers via compose_up
  12. Register container with proxy (if credential isolation)
  13. Copy configs to container (shell fallback)
  14. Log sparse checkout reminder if enabled
  15. Install pip requirements if configured (shell fallback)
  16. Apply network restrictions
"""

from __future__ import annotations

import getpass
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import click

from foundry_sandbox import api_keys
from foundry_sandbox.docker import (
    apply_network_restrictions as _apply_network_restrictions_shared,
    uses_credential_isolation as _uses_credential_isolation_shared,
)
from foundry_sandbox.paths import resolve_ssh_agent_sock
from foundry_sandbox.utils import flag_enabled as _flag_enabled, generate_sandbox_id
from foundry_sandbox.constants import get_repos_dir, TIMEOUT_DOCKER_QUERY
from foundry_sandbox.container_setup import install_pip_requirements
from foundry_sandbox.credential_setup import copy_configs_to_container
from foundry_sandbox.docker import (
    compose_up,
    hmac_secret_file_count,
    populate_stubs_volume,
    repair_hmac_secret_permissions,
)
from foundry_sandbox.foundry_plugin import prepopulate_foundry_global
from foundry_sandbox.git import ensure_bare_repo
from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths
from foundry_sandbox.image import check_image_freshness
from foundry_sandbox.network import (
    add_claude_home_to_override,
    add_ssh_agent_to_override,
    add_timezone_to_override,
    ensure_override_from_metadata,
)
from foundry_sandbox.paths import derive_sandbox_paths, ensure_dir, path_claude_home, repo_url_to_bare_path
from foundry_sandbox.proxy import setup_proxy_registration
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import environment_scope, log_error, log_info, log_step, log_warn
from foundry_sandbox.validate import validate_existing_sandbox_name


def _string_value(value: object) -> str:
    """Convert metadata value to a safe string."""
    return "" if value is None else str(value)


def _export_feature_flags(
    metadata: dict[str, object],
    env: dict[str, str],
) -> tuple[bool, bool]:
    """Set feature flags in *env* dict and return normalized booleans.

    Mutates the provided *env* dict instead of the global os.environ so
    that side-effects are explicit and scoped to the caller.
    """
    enable_opencode = _flag_enabled(metadata.get("enable_opencode", False))
    enable_zai = _flag_enabled(metadata.get("enable_zai", False))
    env["SANDBOX_ENABLE_OPENCODE"] = "1" if enable_opencode else "0"
    env["SANDBOX_ENABLE_ZAI"] = "1" if enable_zai else "0"
    return enable_opencode, enable_zai


def _has_zai_key() -> bool:
    """Check if ZHIPU_API_KEY is set.

    Returns:
        True if ZHIPU_API_KEY is set and non-empty.
    """
    return bool(os.environ.get("ZHIPU_API_KEY"))


def _has_opencode_key() -> bool:
    """Check if OpenCode auth file exists.

    Returns:
        True if OpenCode auth file exists.
    """
    auth_file = Path.home() / ".local/share/opencode/auth.json"
    return auth_file.is_file()


def _uses_credential_isolation(container: str) -> bool:
    """Check if a sandbox uses credential isolation."""
    return _uses_credential_isolation_shared(container)


def _generate_sandbox_id(seed: str) -> str:
    """Generate a sandbox ID from a seed string.

    Args:
        seed: Seed string for ID generation.

    Returns:
        Generated sandbox ID.
    """
    return generate_sandbox_id(seed)


def _apply_network_restrictions(container_id: str, network_mode: str) -> None:
    """Apply network restrictions to container."""
    click.echo(f"Applying network mode: {network_mode}")
    _apply_network_restrictions_shared(container_id, network_mode)


def _log_credential_warnings(
    uses_isolation: bool,
    enable_opencode: bool,
    enable_zai: bool,
) -> None:
    """Log warnings about missing credential files.

    Args:
        uses_isolation: Whether credential isolation is enabled.
        enable_opencode: Whether OpenCode is enabled.
        enable_zai: Whether ZAI is enabled.
    """
    if uses_isolation:
        codex_auth = Path.home() / ".codex/auth.json"
        if not codex_auth.is_file():
            log_warn("Credential isolation: ~/.codex/auth.json not found; Codex CLI will not work.")
            log_warn("Run 'codex auth' to create it if you plan to use Codex.")

        opencode_auth = Path.home() / ".local/share/opencode/auth.json"
        if not opencode_auth.is_file():
            if enable_opencode:
                if _has_zai_key():
                    log_warn("OpenCode enabled but auth file not found; relying on ZHIPU_API_KEY fallback (credential isolation).")
                else:
                    log_warn("OpenCode enabled but auth file not found; OpenCode CLI will not work in credential isolation.")
            else:
                log_warn("Credential isolation: ~/.local/share/opencode/auth.json not found; OpenCode CLI will not work.")
                log_warn("Run 'opencode auth login' to create it if you plan to use OpenCode.")

        gemini_oauth = Path.home() / ".gemini/oauth_creds.json"
        gemini_api_key = os.environ.get("GEMINI_API_KEY", "")
        if not gemini_oauth.is_file() and not gemini_api_key:
            log_warn("Credential isolation: ~/.gemini/oauth_creds.json not found and GEMINI_API_KEY not set; Gemini CLI will not work.")
            log_warn("Run 'gemini auth' or set GEMINI_API_KEY if you plan to use Gemini.")

    if enable_zai and not _has_zai_key():
        log_warn("ZAI enabled but ZHIPU_API_KEY not set on host; claude-zai will not work.")

    if enable_opencode and not _has_opencode_key() and not uses_isolation:
        log_warn("OpenCode enabled but auth file not found; OpenCode setup will be skipped.")
        log_warn("Run 'opencode auth login' or re-run with --with-opencode after configuring ~/.local/share/opencode/auth.json.")


def _setup_ssh_forwarding(
    metadata: dict[str, object],
    override_file: str,
) -> bool:
    """Handle SSH agent forwarding setup.

    Args:
        metadata: Sandbox metadata dictionary.
        override_file: Path to docker-compose override file.

    Returns:
        True if SSH forwarding was enabled.
    """
    sync_ssh = _flag_enabled(metadata.get("sync_ssh", False))
    ssh_mode = _string_value(metadata.get("ssh_mode", ""))

    if not sync_ssh:
        add_ssh_agent_to_override(override_file, "")
        return False

    if ssh_mode in ("init", "disabled"):
        log_warn(f"SSH mode '{ssh_mode}' disables forwarding; use --with-ssh to enable.")
        add_ssh_agent_to_override(override_file, "")
        return False

    ssh_agent_sock = resolve_ssh_agent_sock()
    if ssh_agent_sock:
        add_ssh_agent_to_override(override_file, ssh_agent_sock)
        return True

    log_warn("SSH agent not detected; SSH forwarding disabled (agent-only mode).")
    add_ssh_agent_to_override(override_file, "")
    return False


def _setup_credential_isolation(
    container: str,
    name: str,
    metadata: dict[str, object],
) -> tuple[str, str]:
    """Handle credential isolation: stubs volume, HMAC secrets, ALLOW_PR.

    Mutates os.environ for SANDBOX_ID and ALLOW_PR_OPERATIONS.

    Args:
        container: Container name prefix.
        name: Sandbox name.
        metadata: Sandbox metadata dictionary.

    Returns:
        Tuple of (isolate_credentials flag, sandbox_id string).

    Raises:
        SystemExit: On HMAC secret errors or generation failure.
    """
    populate_stubs_volume(container)

    sandbox_id = ""
    hmac_volume_name = f"{container}_hmac"
    volume_exists = subprocess.run(
        ["docker", "volume", "inspect", hmac_volume_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=TIMEOUT_DOCKER_QUERY,
    ).returncode == 0

    if volume_exists:
        try:
            repair_hmac_secret_permissions(container)
        except (OSError, subprocess.SubprocessError, RuntimeError) as e:
            log_error(f"Failed to repair HMAC secret permissions for {hmac_volume_name}: {e}")
            sys.exit(1)

        try:
            hmac_count = hmac_secret_file_count(container)
        except (OSError, subprocess.SubprocessError, RuntimeError) as e:
            log_error(f"Failed to inspect HMAC secrets in {hmac_volume_name}: {e}")
            sys.exit(1)

        if hmac_count == 1:
            os.environ.pop("SANDBOX_ID", None)
        elif hmac_count == 0:
            seed = f"{container}:{name}:{time.time_ns()}"
            sandbox_id = _generate_sandbox_id(seed)
            if not sandbox_id:
                log_error("Failed to generate sandbox identity (missing SHA-256 toolchain)")
                sys.exit(1)
            log_warn(f"HMAC volume {hmac_volume_name} had no secrets; provisioning a new git shadow secret")
            log_step(f"Sandbox ID: {sandbox_id}")
        else:
            log_error(f"HMAC volume {hmac_volume_name} has {hmac_count} secrets (expected 1)")
            sys.exit(1)
    else:
        seed = f"{container}:{name}:{time.time_ns()}"
        sandbox_id = _generate_sandbox_id(seed)
        if not sandbox_id:
            log_error("Failed to generate sandbox identity (missing SHA-256 toolchain)")
            sys.exit(1)
        log_warn(f"Missing HMAC volume {hmac_volume_name}; provisioning a new git shadow secret")
        log_step(f"Sandbox ID: {sandbox_id}")

    allow_pr = _flag_enabled(metadata.get("allow_pr", False))
    os.environ["ALLOW_PR_OPERATIONS"] = "true" if allow_pr else ""

    return "true", sandbox_id


def _register_proxy(
    container: str,
    container_id: str,
    metadata: dict[str, object],
) -> None:
    """Register container with unified-proxy for credential isolation.

    Args:
        container: Container name prefix.
        container_id: Full container ID (e.g., container-dev-1).
        metadata: Sandbox metadata dictionary.

    Raises:
        SystemExit: If branch identity is missing or registration fails.
    """
    sandbox_branch = _string_value(metadata.get("branch", ""))
    if not sandbox_branch:
        log_error("Sandbox branch identity missing (created before branch isolation support). Recreate sandbox with 'cast new'.")
        sys.exit(1)

    os.environ["SANDBOX_GATEWAY_ENABLED"] = "true"

    proxy_container = f"{container}-unified-proxy-1"
    os.environ["PROXY_CONTAINER_NAME"] = proxy_container
    username = os.environ.get("USER") or getpass.getuser()
    fix_proxy_worktree_paths(proxy_container, username)

    repo_url = _string_value(metadata.get("repo_url", ""))
    repo_spec = repo_url
    if repo_spec:
        repo_spec = repo_spec.removeprefix("https://github.com/")
        repo_spec = repo_spec.removeprefix("http://github.com/")
        repo_spec = repo_spec.removeprefix("git@github.com:")
        if repo_spec.endswith(".git"):
            repo_spec = repo_spec[:-4]

    from_branch = _string_value(metadata.get("from_branch", ""))
    allow_pr = _flag_enabled(metadata.get("allow_pr", False))

    from foundry_sandbox.models import ProxyRegistration
    registration = ProxyRegistration(
        repo=repo_spec,
        allow_pr=allow_pr,
        sandbox_branch=sandbox_branch,
        from_branch=from_branch,
    )

    try:
        setup_proxy_registration(container_id, registration.model_dump())
    except (OSError, subprocess.SubprocessError, RuntimeError, json.JSONDecodeError) as e:
        log_error(f"Failed to register container with unified-proxy: {e}")
        sys.exit(1)


def _finalize_container(
    container_id: str,
    metadata: dict[str, object],
    enable_ssh: bool,
    isolate_credentials: str,
) -> None:
    """Copy configs, install pip requirements, and apply network restrictions.

    Args:
        container_id: Full container ID (e.g., container-dev-1).
        metadata: Sandbox metadata dictionary.
        enable_ssh: Whether SSH forwarding is enabled.
        isolate_credentials: "true" if credential isolation is active, else "".
    """
    working_dir = _string_value(metadata.get("working_dir", ""))
    repo_url = _string_value(metadata.get("repo_url", ""))
    from_branch = _string_value(metadata.get("from_branch", ""))
    sandbox_branch = _string_value(metadata.get("branch", ""))

    copy_configs_to_container(
        container_id,
        skip_plugins=False,
        enable_ssh=enable_ssh,
        working_dir=working_dir,
        isolate_credentials=bool(isolate_credentials),
        from_branch=from_branch,
        branch=sandbox_branch,
        repo_url=repo_url,
    )

    sparse_checkout = _flag_enabled(metadata.get("sparse_checkout", False))
    if sparse_checkout and working_dir:
        log_info(f"Sparse checkout active for: {working_dir}")

    pip_requirements = _string_value(metadata.get("pip_requirements", ""))
    if pip_requirements:
        install_pip_requirements(container_id, pip_requirements)

    network_mode = _string_value(metadata.get("network_mode", ""))
    if network_mode:
        _apply_network_restrictions(container_id, network_mode)


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


@click.command()
@click.argument("name")
@click.pass_context
def start(ctx: click.Context, name: str) -> None:
    """Start a stopped sandbox container."""
    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        log_error(name_error)
        sys.exit(1)

    # ------------------------------------------------------------------
    # 1. Derive paths and check worktree exists
    # ------------------------------------------------------------------
    paths = derive_sandbox_paths(name)
    worktree_path = paths.worktree_path
    container = paths.container_name
    claude_config_path = paths.claude_config_path
    override_file = paths.override_file

    if not worktree_path.is_dir():
        log_error(f"Sandbox '{name}' not found")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 2. Check image freshness
    # ------------------------------------------------------------------
    if check_image_freshness():
        if click.confirm("Rebuild image now?", default=True):
            from foundry_sandbox.commands.build import build as build_cmd
            ctx.invoke(build_cmd)

    # ------------------------------------------------------------------
    # 3. Load metadata and export enable flags
    # ------------------------------------------------------------------
    metadata = load_sandbox_metadata(name)
    if not metadata:
        metadata = {}

    # Build a scoped env dict for feature flags
    cmd_env: dict[str, str] = {}

    # Export enable flags into scoped dict
    enable_opencode, enable_zai = _export_feature_flags(metadata, cmd_env)

    # Clear ZHIPU_API_KEY if ZAI is not enabled
    if not enable_zai:
        cmd_env["ZHIPU_API_KEY"] = ""

    # Prevent host SANDBOX_ID from leaking into compose_up
    if "SANDBOX_ID" in os.environ:
        cmd_env["SANDBOX_ID"] = ""

    # Apply scoped env vars and restore original environment on exit.
    with environment_scope(cmd_env):
        uses_isolation = _uses_credential_isolation(container)

        # --------------------------------------------------------------
        # 5. Log credential warnings
        # --------------------------------------------------------------
        _log_credential_warnings(uses_isolation, enable_opencode, enable_zai)

        # --------------------------------------------------------------
        # 5b. Refresh bare repo so base branch stays current
        # --------------------------------------------------------------
        repo_url = _string_value(metadata.get("repo_url", ""))
        if repo_url:
            bare_path = repo_url_to_bare_path(repo_url)
            ensure_bare_repo(repo_url, bare_path)

        # --------------------------------------------------------------
        # 6. Setup override file and Claude home directory
        # --------------------------------------------------------------
        click.echo(f"Starting sandbox: {name}...")
        ensure_override_from_metadata(name, str(override_file))
        ensure_dir(override_file.parent)

        claude_home_path = path_claude_home(name)
        ensure_dir(claude_home_path)
        add_claude_home_to_override(str(override_file), str(claude_home_path))
        add_timezone_to_override(str(override_file))
        prepopulate_foundry_global(str(claude_home_path), skip_if_populated=True)

        # --------------------------------------------------------------
        # 7. Handle SSH agent forwarding
        # --------------------------------------------------------------
        enable_ssh = _setup_ssh_forwarding(metadata, str(override_file))

        # --------------------------------------------------------------
        # 8. Export GitHub token
        # --------------------------------------------------------------
        token = api_keys.export_gh_token()
        if token:
            os.environ["GITHUB_TOKEN"] = token
            os.environ["GH_TOKEN"] = token
            log_info("GitHub CLI token exported for container")

        # --------------------------------------------------------------
        # 9. Handle credential isolation
        # --------------------------------------------------------------
        isolate_credentials = ""
        sandbox_id = ""

        if uses_isolation:
            isolate_credentials, sandbox_id = _setup_credential_isolation(
                container, name, metadata,
            )

        # --------------------------------------------------------------
        # 10. Start containers via compose_up
        # --------------------------------------------------------------
        repos_dir = str(get_repos_dir())
        compose_up(
            worktree_path=str(worktree_path),
            claude_config_path=str(claude_config_path),
            container=container,
            override_file=str(override_file),
            isolate_credentials=(isolate_credentials == "true"),
            repos_dir=repos_dir,
            sandbox_id=sandbox_id,
        )

        container_id = f"{container}-dev-1"

        # --------------------------------------------------------------
        # 11. Register container with proxy (if credential isolation)
        # --------------------------------------------------------------
        if isolate_credentials == "true":
            _register_proxy(container, container_id, metadata)

        # --------------------------------------------------------------
        # 12. Finalize container: configs, pip, network
        # --------------------------------------------------------------
        _finalize_container(container_id, metadata, enable_ssh, isolate_credentials)
