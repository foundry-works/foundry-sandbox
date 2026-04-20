"""Integration bridge between cast commands and foundry-git-safety.

Wraps all foundry-git-safety CLI interactions and manages HMAC secret
provisioning. Follows the same subprocess-based pattern as sbx.py.

No Click or Pydantic imports at module level.
"""

from __future__ import annotations

import json
import os
import secrets as _secrets
import subprocess
import sys
from pathlib import Path

# Default paths matching foundry-git-safety defaults
_DEFAULT_SECRETS_DIR = os.environ.get(
    "GIT_API_SECRETS_PATH", "/run/secrets/sandbox-hmac"
)
_DEFAULT_DATA_DIR = os.environ.get(
    "FOUNDRY_DATA_DIR", "/var/lib/foundry-git-safety"
)

_TIMEOUT = 10


# ============================================================================
# Server Lifecycle
# ============================================================================


def git_safety_server_start(
    *,
    port: int | None = None,
    foreground: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Start the git safety server via its CLI.

    Args:
        port: Override server port.
        foreground: Run in foreground instead of daemon mode.

    Returns:
        CompletedProcess result.
    """
    cmd = ["foundry-git-safety", "start"]
    if foreground:
        cmd.append("--foreground")
    if port is not None:
        cmd.extend(["--port", str(port)])
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=_TIMEOUT,
    )


def git_safety_server_stop() -> subprocess.CompletedProcess[str]:
    """Stop the git safety server via its CLI."""
    return subprocess.run(
        ["foundry-git-safety", "stop"],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT,
    )


def git_safety_server_is_running() -> bool:
    """Check if the git safety server is running and healthy."""
    try:
        result = subprocess.run(
            ["foundry-git-safety", "status"],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


# ============================================================================
# HMAC Secret Management
# ============================================================================


def generate_hmac_secret() -> str:
    """Generate a cryptographically random HMAC secret (64 hex chars)."""
    return _secrets.token_hex(32)


def write_hmac_secret_to_worktree(
    worktree_path: str | Path,
    secret: str,
) -> Path:
    """Write an HMAC secret file into the worktree's .foundry directory.

    The wrapper script discovers this file at {WORKSPACE_DIR}/.foundry/hmac-secret.

    Args:
        worktree_path: Host-side worktree directory.
        secret: HMAC secret value.

    Returns:
        Path to the written secret file.
    """
    foundry_dir = Path(worktree_path) / ".foundry"
    foundry_dir.mkdir(parents=True, exist_ok=True)
    secret_path = foundry_dir / "hmac-secret"
    secret_path.write_text(secret)
    secret_path.chmod(0o600)
    return secret_path


def write_hmac_secret_for_server(
    sandbox_id: str,
    secret: str,
    *,
    secrets_dir: str | None = None,
) -> Path:
    """Write an HMAC secret file for the git safety server's SecretStore.

    The server reads secrets from {secrets_dir}/{sandbox_id}.

    Args:
        sandbox_id: Sandbox identifier.
        secret: HMAC secret value.
        secrets_dir: Override for the server's secrets directory.

    Returns:
        Path to the written secret file.
    """
    base_dir = secrets_dir or _DEFAULT_SECRETS_DIR
    os.makedirs(base_dir, exist_ok=True)
    secret_path = Path(base_dir) / sandbox_id
    secret_path.write_text(secret)
    secret_path.chmod(0o600)
    return secret_path


# ============================================================================
# Sandbox Registration (file-based)
# ============================================================================


def register_sandbox_with_git_safety(
    sandbox_id: str,
    *,
    branch: str,
    repo_spec: str,
    from_branch: str = "",
    allow_pr: bool = False,
    data_dir: str | None = None,
) -> Path:
    """Register a sandbox with the git safety server via file-based metadata.

    Writes a JSON file that the server reads on each request to determine
    branch isolation policies for the sandbox.

    Args:
        sandbox_id: Sandbox identifier.
        branch: The sandbox's working branch.
        repo_spec: Repository spec (e.g. "owner/repo").
        from_branch: Base branch for PR operations.
        allow_pr: Whether PR operations are allowed.
        data_dir: Override for the server's data directory.

    Returns:
        Path to the written metadata file.
    """
    base_dir = data_dir or _DEFAULT_DATA_DIR
    sandboxes_dir = Path(base_dir) / "sandboxes"
    sandboxes_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "sandbox_branch": branch,
        "from_branch": from_branch,
        "repos": [repo_spec] if repo_spec else [],
        "allow_pr": allow_pr,
    }
    metadata_path = sandboxes_dir / f"{sandbox_id}.json"
    metadata_path.write_text(json.dumps(metadata, indent=2))
    metadata_path.chmod(0o644)
    return metadata_path


def unregister_sandbox_from_git_safety(
    sandbox_id: str,
    *,
    data_dir: str | None = None,
    secrets_dir: str | None = None,
) -> None:
    """Remove a sandbox's metadata and secret from the git safety server.

    Args:
        sandbox_id: Sandbox identifier.
        data_dir: Override for the server's data directory.
        secrets_dir: Override for the server's secrets directory.
    """
    # Remove metadata file
    base_dir = data_dir or _DEFAULT_DATA_DIR
    metadata_path = Path(base_dir) / "sandboxes" / f"{sandbox_id}.json"
    try:
        metadata_path.unlink()
    except FileNotFoundError:
        pass

    # Remove secret file
    sec_dir = secrets_dir or _DEFAULT_SECRETS_DIR
    secret_path = Path(sec_dir) / sandbox_id
    try:
        secret_path.unlink()
    except FileNotFoundError:
        pass


# ============================================================================
# Git Wrapper Injection
# ============================================================================

# Path to the wrapper script relative to the project root
_WRAPPER_SCRIPT = Path(__file__).parent.parent / "stubs" / "git-wrapper-sbx.sh"


def inject_git_wrapper(
    sandbox_name: str,
    *,
    sandbox_id: str,
    workspace_dir: str,
    git_api_host: str = "host.docker.internal",
    git_api_port: int = 8083,
) -> None:
    """Inject the git wrapper script into a running sandbox.

    Copies git-wrapper-sbx.sh to /usr/local/bin/git inside the sandbox
    and sets environment variables for the wrapper.

    Args:
        sandbox_name: Sandbox name as known to sbx.
        sandbox_id: Sandbox identifier for HMAC auth.
        workspace_dir: Workspace path inside the sandbox.
        git_api_host: Git API server hostname.
        git_api_port: Git API server port.
    """
    from foundry_sandbox.sbx import sbx_exec

    wrapper_src = _WRAPPER_SCRIPT
    if not wrapper_src.exists():
        raise FileNotFoundError(f"Git wrapper script not found: {wrapper_src}")

    # Read the wrapper script content
    wrapper_content = wrapper_src.read_text()

    # Use sbx_exec to write the wrapper to /usr/local/bin/git
    sbx_exec(
        sandbox_name,
        ["tee", "/usr/local/bin/git"],
        user="root",
        input=wrapper_content,
        quiet=True,
    )
    sbx_exec(
        sandbox_name,
        ["chmod", "755", "/usr/local/bin/git"],
        user="root",
        quiet=True,
    )

    # Write environment configuration to a profile script
    env_script = (
        f"export SANDBOX_ID={sandbox_id}\n"
        f"export WORKSPACE_DIR={workspace_dir}\n"
        f"export GIT_API_HOST={git_api_host}\n"
        f"export GIT_API_PORT={git_api_port}\n"
        f'export GIT_HMAC_SECRET_FILE="{workspace_dir}/.foundry/hmac-secret"\n'
    )
    sbx_exec(
        sandbox_name,
        ["tee", "/etc/profile.d/foundry-git-safety.sh"],
        user="root",
        input=env_script,
        quiet=True,
    )
    sbx_exec(
        sandbox_name,
        ["chmod", "644", "/etc/profile.d/foundry-git-safety.sh"],
        user="root",
        quiet=True,
    )


def verify_git_wrapper(sandbox_name: str) -> bool:
    """Verify the git wrapper is installed at /usr/local/bin/git.

    Args:
        sandbox_name: Sandbox name as known to sbx.

    Returns:
        True if the wrapper is installed.
    """
    from foundry_sandbox.sbx import sbx_exec

    try:
        result = sbx_exec(
            sandbox_name,
            ["which", "git"],
            quiet=True,
        )
        return result.returncode == 0 and "/usr/local/bin/git" in result.stdout
    except Exception:
        return False


def compute_wrapper_checksum() -> str:
    """Compute the SHA-256 checksum of the local wrapper script.

    Returns:
        Hex digest string.

    Raises:
        FileNotFoundError: If the wrapper script does not exist.
    """
    import hashlib

    if not _WRAPPER_SCRIPT.exists():
        raise FileNotFoundError(f"Git wrapper script not found: {_WRAPPER_SCRIPT}")
    return hashlib.sha256(_WRAPPER_SCRIPT.read_bytes()).hexdigest()


def read_wrapper_checksum_from_sandbox(sandbox_name: str) -> str | None:
    """Read the SHA-256 checksum of the wrapper installed in a sandbox.

    Args:
        sandbox_name: Sandbox name as known to sbx.

    Returns:
        Hex digest string, or None if the file is missing or unreadable.
    """
    from foundry_sandbox.sbx import sbx_exec

    try:
        result = sbx_exec(
            sandbox_name,
            ["sha256sum", "/usr/local/bin/git"],
            quiet=True,
        )
        if result.returncode != 0:
            return None
        parts = result.stdout.strip().split()
        return parts[0] if parts else None
    except Exception:
        return None


def verify_wrapper_integrity(
    sandbox_name: str,
    *,
    expected_checksum: str = "",
) -> tuple[bool, str]:
    """Verify the git wrapper's integrity via SHA-256 checksum.

    Args:
        sandbox_name: Sandbox name as known to sbx.
        expected_checksum: Expected hex digest. If empty, computed from
            the local wrapper script.

    Returns:
        Tuple of (is_ok, actual_checksum).
    """
    expected = expected_checksum or compute_wrapper_checksum()
    actual = read_wrapper_checksum_from_sandbox(sandbox_name) or ""
    return (actual == expected, actual)


# ============================================================================
# Template Management
# ============================================================================


FOUNDRY_TEMPLATE_TAG = "foundry-git-wrapper:latest"


def ensure_foundry_template() -> bool:
    """Ensure the foundry git-wrapper template exists, building it if needed.

    Checks if the template exists via ``sbx template ls``, and runs the
    build script if it does not.  Also triggers a rebuild when the stored
    digest is stale (i.e. ``sbx`` was upgraded).

    Returns:
        True if the template is available (pre-existing or freshly built).
    """
    from foundry_sandbox.sbx import sbx_template_ls

    templates = sbx_template_ls()
    if any(FOUNDRY_TEMPLATE_TAG in t for t in templates):
        # Template exists — check staleness
        build_script = _find_build_script()
        if build_script:
            subprocess.run(
                [str(build_script), "--check-staleness"],
                check=False,
                timeout=120,
            )
        return True

    build_script = _find_build_script()
    if not build_script:
        return False

    print(f"Template {FOUNDRY_TEMPLATE_TAG} not found. Building...")
    result = subprocess.run(
        [str(build_script)],
        check=False,
        timeout=300,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Template build failed:\n{result.stderr}", file=sys.stderr)
        return False
    if result.stdout.strip():
        print(result.stdout.strip())
    return True


def _find_build_script() -> Path | None:
    """Locate the template build script relative to this package."""
    script = Path(__file__).parent.parent / "scripts" / "build-foundry-template.sh"
    return script if script.exists() else None


# ============================================================================
# Diagnostics Bridge
# ============================================================================


def git_safety_server_health() -> dict[str, object] | None:
    """Query the git safety server's health endpoint.

    Returns:
        Dict with health info, or None if the server is unreachable.
    """
    try:
        import urllib.request

        req = urllib.request.Request("http://127.0.0.1:8083/health")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data: dict[str, object] = json.loads(resp.read())
            return data
    except Exception as exc:
        return {"reachable": False, "error": str(exc)}


def git_safety_readiness(port: int = 8083) -> dict[str, object] | None:
    """Query the git safety server's readiness endpoint.

    Returns:
        Dict with readiness info, or None if the server is unreachable.
    """
    try:
        import urllib.request

        req = urllib.request.Request(f"http://127.0.0.1:{port}/ready")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data: dict[str, object] = json.loads(resp.read())
            return data
    except Exception as exc:
        return {"ready": False, "error": str(exc)}
