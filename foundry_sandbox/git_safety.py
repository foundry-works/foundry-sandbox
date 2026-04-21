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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from foundry_sandbox.utils import log_warn

# Default paths for standalone host usage (user-writable).
# Container workloads override these via environment variables.
_FOUNDRY_BASE = os.path.expanduser("~/.foundry")
_DEFAULT_SECRETS_DIR = os.environ.get(
    "GIT_API_SECRETS_PATH", f"{_FOUNDRY_BASE}/secrets/sandbox-hmac"
)
_DEFAULT_DATA_DIR = os.environ.get(
    "FOUNDRY_DATA_DIR", f"{_FOUNDRY_BASE}/data/git-safety"
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


def write_hmac_secret_to_sandbox(
    sandbox_name: str,
    secret: str,
) -> Path:
    """Write an HMAC secret file for the wrapper inside the sandbox.

    The secret is written to two locations:
      /run/foundry/hmac-secret     — tmpfs, for live sessions
      /var/lib/foundry/hmac-secret — persistent disk, survives VM restarts

    The wrapper discovers the persistent copy when the tmpfs copy is absent
    (e.g. after a sandbox restart between sbx exec calls).

    Args:
        sandbox_name: Sandbox name (used only for logging context).
        secret: HMAC secret value.

    Returns:
        Path to the primary (tmpfs) secret file (container-absolute).
    """
    from foundry_sandbox.sbx import sbx_exec

    sbx_exec(
        sandbox_name,
        ["sh", "-c",
         f"mkdir -p /run/foundry /var/lib/foundry "
         f"&& printf '%s' '{secret}' > /run/foundry/hmac-secret "
         f"&& chmod 600 /run/foundry/hmac-secret "
         f"&& printf '%s' '{secret}' > /var/lib/foundry/hmac-secret "
         f"&& chmod 600 /var/lib/foundry/hmac-secret"],
        user="root",
        quiet=True,
    )
    return Path("/run/foundry/hmac-secret")


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
    repo_root: str | None = None,
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
        repo_root: Host-side path to the sandbox's git worktree.
        data_dir: Override for the server's data directory.

    Returns:
        Path to the written metadata file.
    """
    base_dir = data_dir or _DEFAULT_DATA_DIR
    sandboxes_dir = Path(base_dir) / "sandboxes"
    sandboxes_dir.mkdir(parents=True, exist_ok=True)

    metadata: dict[str, object] = {
        "sandbox_branch": branch,
        "from_branch": from_branch,
        "repos": [repo_spec] if repo_spec else [],
        "allow_pr": allow_pr,
    }
    if repo_root:
        metadata["repo_root"] = repo_root
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

def _wrapper_script_path() -> Path:
    """Resolve the git wrapper script from package resources.

    Uses importlib.resources so the asset is found in installed wheels
    as well as editable/source checkouts.

    Raises:
        FileNotFoundError: If the wrapper script is not bundled in the package.
    """
    from importlib.resources import files

    resource = files("foundry_sandbox.assets").joinpath("git-wrapper-sbx.sh")
    path = Path(str(resource))
    if not path.exists():
        raise FileNotFoundError(
            "Git wrapper script not found in package assets. "
            "Reinstall with: pip install --force-reinstall foundry-sandbox"
        )
    return path


def _proxy_sign_script_path() -> Path:
    """Resolve the proxy signing helper from package resources.

    Raises:
        FileNotFoundError: If the script is not bundled in the package.
    """
    from importlib.resources import files

    resource = files("foundry_sandbox.assets").joinpath("proxy-sign.sh")
    path = Path(str(resource))
    if not path.exists():
        raise FileNotFoundError(
            "Proxy signing script not found in package assets. "
            "Reinstall with: pip install --force-reinstall foundry-sandbox"
        )
    return path


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
    import base64

    wrapper_src = _wrapper_script_path()

    # Read the wrapper script content
    wrapper_content = wrapper_src.read_text()
    wrapper_b64 = base64.b64encode(wrapper_content.encode()).decode()

    # Use base64 to avoid stdin piping issues with sbx exec
    sbx_exec(
        sandbox_name,
        ["sh", "-c", f"echo '{wrapper_b64}' | base64 -d > /usr/local/bin/git && chmod 755 /usr/local/bin/git"],
        user="root",
        quiet=True,
    )

    # Install proxy-sign helper
    proxy_sign_src = _proxy_sign_script_path()
    proxy_sign_content = proxy_sign_src.read_text()
    proxy_b64 = base64.b64encode(proxy_sign_content.encode()).decode()

    sbx_exec(
        sandbox_name,
        ["sh", "-c", f"echo '{proxy_b64}' | base64 -d > /usr/local/bin/proxy-sign && chmod 755 /usr/local/bin/proxy-sign"],
        user="root",
        quiet=True,
    )

    # Write environment configuration to a profile script (login shells)
    env_script = (
        f"export SANDBOX_ID={sandbox_id}\n"
        f"export WORKSPACE_DIR={workspace_dir}\n"
        f"export GIT_API_HOST={git_api_host}\n"
        f"export GIT_API_PORT={git_api_port}\n"
        f'export GIT_HMAC_SECRET_FILE="/run/foundry/hmac-secret"\n'
    )
    env_b64 = base64.b64encode(env_script.encode()).decode()
    sbx_exec(
        sandbox_name,
        ["sh", "-c", f"echo '{env_b64}' | base64 -d > /etc/profile.d/foundry-git-safety.sh && chmod 644 /etc/profile.d/foundry-git-safety.sh"],
        user="root",
        quiet=True,
    )

    # Write a plain env file (no export) for the wrapper to source directly.
    # This persists across VM restarts and does not require a login shell.
    plain_env = (
        f"SANDBOX_ID={sandbox_id}\n"
        f"WORKSPACE_DIR={workspace_dir}\n"
        f"GIT_API_HOST={git_api_host}\n"
        f"GIT_API_PORT={git_api_port}\n"
    )
    env_plain_b64 = base64.b64encode(plain_env.encode()).decode()
    sbx_exec(
        sandbox_name,
        ["sh", "-c", f"mkdir -p /var/lib/foundry && echo '{env_plain_b64}' | base64 -d > /var/lib/foundry/git-safety.env && chmod 644 /var/lib/foundry/git-safety.env"],
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

    wrapper_path = _wrapper_script_path()
    return hashlib.sha256(wrapper_path.read_bytes()).hexdigest()


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

    Uses the Python sbx APIs (sbx_create, sbx_exec, sbx_template_save)
    instead of a shell script so this works from installed wheels.

    Returns:
        True if the template is available (pre-existing or freshly built).
    """
    from foundry_sandbox.sbx import (
        get_sbx_version,
        sbx_create,
        sbx_exec,
        sbx_rm,
        sbx_template_ls,
        sbx_template_save,
    )

    templates = sbx_template_ls()
    if any(FOUNDRY_TEMPLATE_TAG in t for t in templates):
        return True

    print(f"Template {FOUNDRY_TEMPLATE_TAG} not found. Building...")

    try:
        wrapper_path = _wrapper_script_path()
        wrapper_content = wrapper_path.read_text()
    except FileNotFoundError:
        print("Wrapper script not found in package assets.", file=sys.stderr)
        return False

    seed_name = f"foundry-template-seed-{os.getpid()}"

    try:
        sbx_create(seed_name, "shell", "/tmp")
        sbx_exec(
            seed_name, ["tee", "/usr/local/bin/git"],
            user="root", input=wrapper_content, quiet=True,
        )
        sbx_exec(
            seed_name, ["chmod", "755", "/usr/local/bin/git"],
            user="root", quiet=True,
        )

        verify_result = sbx_exec(seed_name, ["which", "git"], quiet=True)
        if verify_result.returncode != 0 or "/usr/local/bin/git" not in verify_result.stdout:
            print("Error: wrapper verification failed during template build", file=sys.stderr)
            return False

        sbx_template_save(seed_name, FOUNDRY_TEMPLATE_TAG)

        digest_file = Path.home() / ".foundry" / "template-image-digest"
        digest_file.parent.mkdir(parents=True, exist_ok=True)
        version = get_sbx_version() or "unknown"
        digest_file.write_text(version)

        print(f"  Template {FOUNDRY_TEMPLATE_TAG} built successfully.")
        return True

    except Exception as exc:
        print(f"Template build failed: {exc}", file=sys.stderr)
        return False
    finally:
        try:
            sbx_rm(seed_name)
        except Exception:
            pass


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


# ============================================================================
# Tamper Event Emission
# ============================================================================


_tamper_event_fallback_count: int = 0


def emit_wrapper_tamper_event(
    *,
    sandbox: str,
    expected_sha256: str,
    actual_sha256: str,
    action: str,
) -> None:
    """Record a wrapper tamper event via the git-safety server.

    POSTs to the server's ``/tamper-event`` endpoint, which always
    increments a Prometheus counter and writes to the decision log on a
    best-effort basis.  Falls back to a local counter + direct decision
    log write when the server is unreachable.

    Args:
        sandbox: Sandbox name.
        expected_sha256: Expected wrapper checksum.
        actual_sha256: Checksum found in the sandbox.
        action: "reinjected" or "reinject_failed".
    """
    global _tamper_event_fallback_count

    payload = json.dumps({
        "sandbox": sandbox,
        "expected_sha256": expected_sha256,
        "actual_sha256": actual_sha256,
        "action": action,
    }).encode()

    # Try the server endpoint first.
    try:
        import urllib.request

        req = urllib.request.Request(
            "http://127.0.0.1:8083/tamper-event",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status in (200, 202):
                return
    except Exception:
        pass

    # Server unreachable — local fallback.
    _tamper_event_fallback_count += 1
    log_warn(
        f"Tamper-event server unreachable; recording locally for "
        f"sandbox={sandbox} action={action} "
        f"(fallback_count={_tamper_event_fallback_count})"
    )

    try:
        from foundry_git_safety.decision_log import write_decision  # type: ignore[import-untyped]

        write_decision(
            sandbox=sandbox,
            rule="wrapper_integrity",
            verb="wrapper_tamper",
            outcome=action,
            expected_sha256=expected_sha256,
            actual_sha256=actual_sha256,
        )
    except Exception as exc:
        log_warn(f"Tamper-event decision log fallback also failed: {exc}")


def get_tamper_event_fallback_count() -> int:
    """Return count of tamper events recorded via local fallback."""
    return _tamper_event_fallback_count


# ============================================================================
# Sandbox Connectivity Verification
# ============================================================================


def _verify_sandbox_connectivity(
    sandbox_name: str,
    *,
    api_host: str = "host.docker.internal",
    api_port: int = 8083,
    proxy: str = "http://gateway.docker.internal:3128",
) -> None:
    """Verify the sandbox can reach the git-safety server through the proxy.

    Runs ``curl`` inside the sandbox to hit ``/health`` on the git-safety
    server via the SBX HTTP proxy.  Raises on failure so the provisioning
    caller knows the path is broken before claiming git safety is enabled.
    """
    from foundry_sandbox.sbx import sbx_exec

    url = f"http://{api_host}:{api_port}/health"
    result = sbx_exec(
        sandbox_name,
        [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--max-time", "5", "--connect-timeout", "3",
            "--proxy", proxy,
            url,
        ],
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"curl exited {result.returncode} — sandbox cannot reach "
            f"git-safety server at {url} via proxy {proxy}"
        )
    code = result.stdout.strip()
    if not code.startswith("2"):
        raise RuntimeError(
            f"git-safety /health returned HTTP {code} from sandbox "
            f"(expected 2xx)"
        )


# ============================================================================
# Centralized Git-Safety Provisioning
# ============================================================================


@dataclass
class ProvisioningResult:
    """Structured result from git-safety provisioning or repair."""

    success: bool
    wrapper_checksum: str = ""
    error: str = ""


def provision_git_safety(
    sandbox_name: str,
    *,
    sandbox_id: str | None = None,
    workspace_dir: str = "/workspace",
    branch: str = "",
    repo_spec: str = "",
    from_branch: str = "",
    allow_pr: bool = False,
    repo_root: str | None = None,
) -> ProvisioningResult:
    """Full git-safety provisioning for an sbx sandbox.

    Performs HMAC secret generation, guest + server secret writes,
    git-safety registration, wrapper injection, and checksum computation.

    This is the ONLY function authorized to write ``git_safety_enabled=True``
    to sandbox metadata.  Callers must not set that field directly.
    """
    from foundry_sandbox.state import patch_sandbox_metadata

    sid = sandbox_id or sandbox_name

    try:
        hmac_secret = generate_hmac_secret()
    except Exception as exc:
        return ProvisioningResult(success=False, error=f"HMAC generation failed: {exc}")

    try:
        write_hmac_secret_to_sandbox(sandbox_name, hmac_secret)
    except Exception as exc:
        return ProvisioningResult(success=False, error=f"Guest HMAC write failed: {exc}")

    try:
        write_hmac_secret_for_server(sid, hmac_secret)
    except Exception as exc:
        return ProvisioningResult(success=False, error=f"Server HMAC write failed: {exc}")

    if branch and repo_spec:
        try:
            register_sandbox_with_git_safety(
                sid,
                branch=branch,
                repo_spec=repo_spec,
                from_branch=from_branch,
                allow_pr=allow_pr,
                repo_root=repo_root,
            )
        except Exception as exc:
            return ProvisioningResult(
                success=False, error=f"Git-safety registration failed: {exc}",
            )

    try:
        inject_git_wrapper(sandbox_name, sandbox_id=sid, workspace_dir=workspace_dir)
    except Exception as exc:
        return ProvisioningResult(
            success=False, error=f"Wrapper injection failed: {exc}",
        )

    try:
        wrapper_checksum = compute_wrapper_checksum()
    except FileNotFoundError as exc:
        return ProvisioningResult(
            success=False,
            error=f"Checksum computation failed: {exc}. "
            "Reinstall foundry-sandbox.",
        )

    try:
        _verify_sandbox_connectivity(sandbox_name)
    except Exception as exc:
        return ProvisioningResult(
            success=False,
            error=f"Sandbox connectivity to git-safety server failed: {exc}",
        )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    patch_sandbox_metadata(
        sandbox_name,
        git_safety_enabled=True,
        wrapper_checksum=wrapper_checksum,
        wrapper_last_verified=now,
    )

    return ProvisioningResult(success=True, wrapper_checksum=wrapper_checksum)


def repair_git_safety(
    sandbox_name: str,
    *,
    sandbox_id: str | None = None,
    workspace_dir: str = "/workspace",
    expected_checksum: str = "",
    rotate_hmac: bool = False,
) -> ProvisioningResult:
    """Repair git-safety wrapper in a running sandbox.

    Re-injects the wrapper and updates the stored checksum.  Optionally
    rotates the HMAC secret (used by the watchdog).

    Does **not** set ``git_safety_enabled=True`` — that is reserved for
    :func:`provision_git_safety`.
    """
    from foundry_sandbox.state import patch_sandbox_metadata

    sid = sandbox_id or sandbox_name

    if rotate_hmac:
        try:
            new_secret = generate_hmac_secret()
            write_hmac_secret_to_sandbox(sandbox_name, new_secret)
            write_hmac_secret_for_server(sid, new_secret)
        except Exception as exc:
            return ProvisioningResult(
                success=False, error=f"HMAC rotation failed: {exc}",
            )

    try:
        inject_git_wrapper(sandbox_name, sandbox_id=sid, workspace_dir=workspace_dir)
    except Exception as exc:
        return ProvisioningResult(
            success=False, error=f"Wrapper re-injection failed: {exc}",
        )

    try:
        wrapper_checksum = expected_checksum or compute_wrapper_checksum()
    except FileNotFoundError:
        wrapper_checksum = expected_checksum

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    patch_sandbox_metadata(
        sandbox_name,
        wrapper_checksum=wrapper_checksum,
        wrapper_last_verified=now,
    )

    return ProvisioningResult(success=True, wrapper_checksum=wrapper_checksum)


# ============================================================================
# Template Staleness Detection
# ============================================================================


def get_template_image_digest() -> str | None:
    """Read the stored template-image-digest (the sbx version used to build)."""
    digest_file = Path.home() / ".foundry" / "template-image-digest"
    try:
        return digest_file.read_text().strip() or None
    except (FileNotFoundError, OSError):
        return None


def is_template_stale() -> bool:
    """Return True if the current sbx version differs from the stored digest.

    Indicates sandboxes built from the old template should be re-provisioned.
    Returns False when the digest file is missing (no template was ever built
    or the file was cleaned up).
    """
    from foundry_sandbox.sbx import get_sbx_version

    stored = get_template_image_digest()
    if stored is None:
        return False
    current = get_sbx_version() or ""
    return stored != current
