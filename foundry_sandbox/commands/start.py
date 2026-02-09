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

import json
import os
import subprocess
import sys
from pathlib import Path

import click

from foundry_sandbox.constants import get_repos_dir
from foundry_sandbox.docker import (
    compose_up,
    hmac_secret_file_count,
    populate_stubs_volume,
    repair_hmac_secret_permissions,
)
from foundry_sandbox.network import (
    add_claude_home_to_override,
    add_ssh_agent_to_override,
    add_timezone_to_override,
    ensure_override_header,
)
from foundry_sandbox.paths import derive_sandbox_paths, ensure_dir, path_claude_home
from foundry_sandbox.proxy import setup_proxy_registration
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import log_error, log_info, log_step, log_warn

# Path to sandbox.sh for shell fallback
SANDBOX_SH = Path(__file__).resolve().parent.parent.parent / "sandbox.sh"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _shell_call(*args: str) -> subprocess.CompletedProcess[str]:
    """Call sandbox.sh with arguments.

    Args:
        *args: Arguments to pass to sandbox.sh.

    Returns:
        CompletedProcess result.
    """
    return subprocess.run(
        [str(SANDBOX_SH), *args],
        check=False,
    )


def _shell_call_capture(*args: str) -> str:
    """Call sandbox.sh with arguments and capture stdout.

    Args:
        *args: Arguments to pass to sandbox.sh.

    Returns:
        stdout output as string (stripped).
    """
    result = subprocess.run(
        [str(SANDBOX_SH), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


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
    """Check if a sandbox uses credential isolation.

    Args:
        container: Container name.

    Returns:
        True if unified-proxy container exists.
    """
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in result.stdout.splitlines():
            if line.startswith(f"{container}-unified-proxy-"):
                return True
    except OSError:
        pass
    return False


def _generate_sandbox_id(seed: str) -> str:
    """Generate a sandbox ID using shell fallback.

    Args:
        seed: Seed string for ID generation.

    Returns:
        Generated sandbox ID, or empty string on failure.
    """
    result = subprocess.run(
        ["bash", "-c", f"source {SANDBOX_SH} && generate_sandbox_id '{seed}'"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _apply_network_restrictions(container_id: str, network_mode: str) -> None:
    """Apply network restrictions to container.

    Args:
        container_id: Container ID.
        network_mode: Network mode (limited, host-only, none).
    """
    click.echo(f"Applying network mode: {network_mode}")

    if network_mode == "limited":
        subprocess.run(
            ["docker", "exec", container_id, "sudo", "/usr/local/bin/network-firewall.sh"],
            check=False,
        )
    else:
        subprocess.run(
            ["docker", "exec", container_id, "sudo", "/usr/local/bin/network-mode", network_mode],
            check=False,
        )


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


@click.command()
@click.argument("name")
def start(name: str) -> None:
    """Start a stopped sandbox container."""

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
    # 2. Check image freshness (shell fallback)
    # ------------------------------------------------------------------
    _shell_call("_bridge_check_image_freshness")

    # ------------------------------------------------------------------
    # 3. Load metadata and export enable flags
    # ------------------------------------------------------------------
    metadata = load_sandbox_metadata(name)
    if not metadata:
        metadata = {}

    # Export enable flags to environment
    enable_opencode = metadata.get("enable_opencode", "0")
    enable_zai = metadata.get("enable_zai", "0")
    os.environ["SANDBOX_ENABLE_OPENCODE"] = enable_opencode
    os.environ["SANDBOX_ENABLE_ZAI"] = enable_zai

    # Clear ZHIPU_API_KEY if ZAI is not enabled
    if enable_zai != "1":
        os.environ["ZHIPU_API_KEY"] = ""

    # ------------------------------------------------------------------
    # 4. Detect credential isolation mode
    # ------------------------------------------------------------------
    uses_credential_isolation = _uses_credential_isolation(container)

    # ------------------------------------------------------------------
    # 5. Log credential warnings
    # ------------------------------------------------------------------
    if uses_credential_isolation:
        # Codex CLI warning
        codex_auth = Path.home() / ".codex/auth.json"
        if not codex_auth.is_file():
            log_warn("Credential isolation: ~/.codex/auth.json not found; Codex CLI will not work.")
            log_warn("Run 'codex auth' to create it if you plan to use Codex.")

        # OpenCode CLI warning
        opencode_auth = Path.home() / ".local/share/opencode/auth.json"
        if not opencode_auth.is_file():
            if enable_opencode == "1":
                if _has_zai_key():
                    log_warn("OpenCode enabled but auth file not found; relying on ZHIPU_API_KEY fallback (credential isolation).")
                else:
                    log_warn("OpenCode enabled but auth file not found; OpenCode CLI will not work in credential isolation.")
            else:
                log_warn("Credential isolation: ~/.local/share/opencode/auth.json not found; OpenCode CLI will not work.")
                log_warn("Run 'opencode auth login' to create it if you plan to use OpenCode.")

        # Gemini CLI warning
        gemini_oauth = Path.home() / ".gemini/oauth_creds.json"
        gemini_api_key = os.environ.get("GEMINI_API_KEY", "")
        if not gemini_oauth.is_file() and not gemini_api_key:
            log_warn("Credential isolation: ~/.gemini/oauth_creds.json not found and GEMINI_API_KEY not set; Gemini CLI will not work.")
            log_warn("Run 'gemini auth' or set GEMINI_API_KEY if you plan to use Gemini.")

    # ZAI key warning (non-credential-isolation mode)
    if enable_zai == "1" and not _has_zai_key():
        log_warn("ZAI enabled but ZHIPU_API_KEY not set on host; claude-zai will not work.")

    # OpenCode key warning (non-credential-isolation mode)
    if enable_opencode == "1" and not _has_opencode_key() and not uses_credential_isolation:
        log_warn("OpenCode enabled but auth file not found; OpenCode setup will be skipped.")
        log_warn("Run 'opencode auth login' or re-run with --with-opencode after configuring ~/.local/share/opencode/auth.json.")

    # ------------------------------------------------------------------
    # 6. Setup override file from metadata (shell fallback)
    # ------------------------------------------------------------------
    click.echo(f"Starting sandbox: {name}...")
    _shell_call("_bridge_ensure_override_from_metadata", name, str(override_file))

    # Ensure override directory exists
    ensure_dir(override_file.parent)

    # ------------------------------------------------------------------
    # 7. Setup Claude home directory
    # ------------------------------------------------------------------
    claude_home_path = path_claude_home(name)
    ensure_dir(claude_home_path)
    add_claude_home_to_override(str(override_file), str(claude_home_path))
    add_timezone_to_override(str(override_file))

    # Pre-populate foundry skills and hooks (shell fallback)
    _shell_call("_bridge_prepopulate_foundry_global", str(claude_home_path), "1")

    # ------------------------------------------------------------------
    # 8. Handle SSH agent forwarding
    # ------------------------------------------------------------------
    enable_ssh = False
    sync_ssh = metadata.get("sync_ssh", "0")
    ssh_mode = metadata.get("ssh_mode", "")

    if sync_ssh == "1":
        if ssh_mode in ("init", "disabled"):
            log_warn(f"SSH mode '{ssh_mode}' disables forwarding; use --with-ssh to enable.")
            add_ssh_agent_to_override(str(override_file), "")
        else:
            # Try to resolve SSH agent socket (shell fallback)
            ssh_agent_sock = _shell_call_capture("_bridge_resolve_ssh_agent_sock")
            if ssh_agent_sock:
                add_ssh_agent_to_override(str(override_file), ssh_agent_sock)
                enable_ssh = True
            else:
                log_warn("SSH agent not detected; SSH forwarding disabled (agent-only mode).")
                add_ssh_agent_to_override(str(override_file), "")
    else:
        add_ssh_agent_to_override(str(override_file), "")

    # ------------------------------------------------------------------
    # 9. Export GitHub token (shell fallback)
    # ------------------------------------------------------------------
    result = subprocess.run(
        ["bash", "-c", f"source {SANDBOX_SH} && export_gh_token"],
        check=False,
    )
    if result.returncode == 0:
        log_info("GitHub CLI token exported for container")

    # ------------------------------------------------------------------
    # 10. Handle credential isolation: stubs volume, HMAC secrets
    # ------------------------------------------------------------------
    isolate_credentials = ""
    repos_dir = str(get_repos_dir())
    sandbox_id = ""

    if uses_credential_isolation:
        isolate_credentials = "true"
        populate_stubs_volume(container)
        os.environ["STUBS_VOLUME_NAME"] = f"{container}_stubs"
        os.environ["HMAC_VOLUME_NAME"] = f"{container}_hmac"

        # Check if HMAC volume exists and handle secret provisioning
        hmac_volume_name = f"{container}_hmac"
        volume_exists = subprocess.run(
            ["docker", "volume", "inspect", hmac_volume_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0

        if volume_exists:
            # Repair legacy permissions
            try:
                repair_hmac_secret_permissions(container)
            except Exception as e:
                log_error(f"Failed to repair HMAC secret permissions for {hmac_volume_name}: {e}")
                sys.exit(1)

            # Check secret count
            try:
                hmac_count = hmac_secret_file_count(container)
            except Exception as e:
                log_error(f"Failed to inspect HMAC secrets in {hmac_volume_name}: {e}")
                sys.exit(1)

            if hmac_count == 1:
                # Prevent accidental reprovisioning with an unrelated host SANDBOX_ID
                if "SANDBOX_ID" in os.environ:
                    del os.environ["SANDBOX_ID"]
            elif hmac_count == 0:
                # Existing volume with no secret: provision a new secret on start
                seed = f"{container}:{name}:{os.times().elapsed}"
                sandbox_id = _generate_sandbox_id(seed)
                if not sandbox_id:
                    log_error("Failed to generate sandbox identity (missing SHA-256 toolchain)")
                    sys.exit(1)
                os.environ["SANDBOX_ID"] = sandbox_id
                log_warn(f"HMAC volume {hmac_volume_name} had no secrets; provisioning a new git shadow secret")
                log_step(f"Sandbox ID: {sandbox_id}")
            else:
                log_error(f"HMAC volume {hmac_volume_name} has {hmac_count} secrets (expected 1)")
                sys.exit(1)
        else:
            # Backward compatibility: old sandboxes may predate git shadow secret volumes
            seed = f"{container}:{name}:{os.times().elapsed}"
            sandbox_id = _generate_sandbox_id(seed)
            if not sandbox_id:
                log_error("Failed to generate sandbox identity (missing SHA-256 toolchain)")
                sys.exit(1)
            os.environ["SANDBOX_ID"] = sandbox_id
            log_warn(f"Missing HMAC volume {hmac_volume_name}; provisioning a new git shadow secret")
            log_step(f"Sandbox ID: {sandbox_id}")

        # Export ALLOW_PR_OPERATIONS from metadata
        allow_pr = metadata.get("allow_pr", "0")
        if allow_pr == "1":
            os.environ["ALLOW_PR_OPERATIONS"] = "true"
        else:
            os.environ["ALLOW_PR_OPERATIONS"] = ""

    # ------------------------------------------------------------------
    # 11. Start containers via compose_up
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # 12. Register container with proxy (if credential isolation)
    # ------------------------------------------------------------------
    if isolate_credentials == "true":
        sandbox_branch = metadata.get("branch", "")
        if not sandbox_branch:
            log_error("Sandbox branch identity missing (created before branch isolation support). Recreate sandbox with 'cast new'.")
            sys.exit(1)

        os.environ["SANDBOX_GATEWAY_ENABLED"] = "true"

        # Fix proxy worktree paths (shell fallback)
        proxy_container = f"{container}-unified-proxy-1"
        username = os.environ.get("USER", "ubuntu")
        _shell_call("_bridge_fix_proxy_worktree_paths", proxy_container, username)

        # Prepare metadata JSON
        repo_url = metadata.get("repo_url", "")
        # Strip GitHub URL prefixes and .git suffix
        repo_spec = repo_url
        if repo_spec:
            repo_spec = repo_spec.removeprefix("https://github.com/")
            repo_spec = repo_spec.removeprefix("http://github.com/")
            repo_spec = repo_spec.removeprefix("git@github.com:")
            if repo_spec.endswith(".git"):
                repo_spec = repo_spec[:-4]

        from_branch = metadata.get("from_branch", "")

        # Build metadata JSON
        metadata_json = json.dumps({
            "repo": repo_spec,
            "allow_pr": (allow_pr == "1"),
            "sandbox_branch": sandbox_branch,
            "from_branch": from_branch,
        })

        # Setup proxy registration
        try:
            setup_proxy_registration(container_id, json.loads(metadata_json))
        except Exception as e:
            log_error(f"Failed to register container with unified-proxy: {e}")
            sys.exit(1)

    # ------------------------------------------------------------------
    # 13. Copy configs to container (shell fallback)
    # ------------------------------------------------------------------
    working_dir = metadata.get("working_dir", "")
    repo_url = metadata.get("repo_url", "")
    from_branch = metadata.get("from_branch", "")
    sandbox_branch = metadata.get("branch", "")

    _shell_call(
        "_bridge_copy_configs_to_container",
        container_id,
        "0",  # is_new
        "1" if enable_ssh else "0",
        working_dir,
        isolate_credentials,
        from_branch,
        sandbox_branch,
        repo_url,
    )

    # ------------------------------------------------------------------
    # 14. Log sparse checkout reminder if enabled
    # ------------------------------------------------------------------
    sparse_checkout = metadata.get("sparse_checkout", "0")
    if sparse_checkout == "1" and working_dir:
        log_info(f"Sparse checkout active for: {working_dir}")

    # ------------------------------------------------------------------
    # 15. Install pip requirements if configured (shell fallback)
    # ------------------------------------------------------------------
    pip_requirements = metadata.get("pip_requirements", "")
    if pip_requirements:
        _shell_call("_bridge_install_pip_requirements", container_id, pip_requirements)

    # ------------------------------------------------------------------
    # 16. Apply network restrictions
    # ------------------------------------------------------------------
    network_mode = metadata.get("network_mode", "")
    if network_mode:
        _apply_network_restrictions(container_id, network_mode)
