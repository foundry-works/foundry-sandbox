"""Docker operations for foundry-sandbox.

Replaces lib/docker.sh (237 lines). Wraps docker and docker-compose CLI calls
via subprocess. Matches current timeout/error behavior and stderr messaging.

No Click or Pydantic imports at module level (bridge-callable constraint).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from foundry_sandbox.models import CredentialPlaceholders

from foundry_sandbox.constants import (
    get_sandbox_verbose,
    TIMEOUT_DOCKER_COMPOSE,
    TIMEOUT_DOCKER_EXEC,
    TIMEOUT_DOCKER_NETWORK,
    TIMEOUT_DOCKER_QUERY,
    TIMEOUT_DOCKER_VOLUME,
    TIMEOUT_GIT_QUERY,
)
from foundry_sandbox.utils import log_debug, log_warn


# ============================================================================
# Internal Helpers
# ============================================================================


def _run_cmd(
    args: list[str],
    *,
    quiet: bool = False,
    check: bool = True,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command, optionally suppressing output.

    Mirrors the shell run_cmd / run_cmd_quiet helpers from lib/runtime.sh:
      - run_cmd: prints "+ <cmd>" when SANDBOX_VERBOSE=1, runs command
      - run_cmd_quiet: same verbose trace, but redirects stdout+stderr to /dev/null

    Args:
        args: Command and arguments.
        quiet: If True, suppress stdout and stderr (like run_cmd_quiet).
        check: If True, raise CalledProcessError on non-zero exit.
        timeout: Optional timeout in seconds.

    Returns:
        CompletedProcess result.

    Raises:
        subprocess.CalledProcessError: If check=True and command fails.
        subprocess.TimeoutExpired: If timeout is exceeded.
    """
    if get_sandbox_verbose():
        print(f"+ {' '.join(args)}", file=sys.stderr)

    kwargs: dict[str, Any] = {"check": check}
    if timeout is not None:
        kwargs["timeout"] = timeout
    if quiet:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    else:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE

    return subprocess.run(args, **kwargs)


def _script_dir() -> Path:
    """Return the repository root directory (equivalent to $SCRIPT_DIR in shell).

    The shell code uses SCRIPT_DIR which points to the repo root where
    docker-compose.yml lives.
    """
    # Walk up from foundry_sandbox/ to the repo root
    return Path(__file__).resolve().parent.parent


# ============================================================================
# Credential Placeholders
# ============================================================================


def _credential_placeholder() -> str:
    """Generate a random per-sandbox credential placeholder.

    Uses a random nonce prefixed with a recognizable tag so the proxy can
    identify placeholders without relying on a static shared secret.
    """
    return f"CRED_PROXY_{secrets.token_hex(16)}"


def setup_credential_placeholders() -> CredentialPlaceholders:
    """Detect host auth configuration and return a CredentialPlaceholders model.

    Determines which placeholder credentials to use based on what's configured
    on the host. Each placeholder is a unique random nonce to prevent
    cross-sandbox forgery.

    Returns:
        CredentialPlaceholders model. Use .to_env_dict() for env var dict.
    """
    from foundry_sandbox.models import CredentialPlaceholders

    # Claude: Use OAuth placeholder if CLAUDE_CODE_OAUTH_TOKEN is set on host
    if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        anthropic_key = ""
        claude_oauth = _credential_placeholder()
    else:
        anthropic_key = _credential_placeholder()
        claude_oauth = ""

    # Gemini: Check selectedType in settings file
    gemini_settings = Path.home() / ".gemini" / "settings.json"
    gemini_is_oauth = False
    try:
        with open(gemini_settings) as f:
            data = json.load(f)
        if data.get("selectedType") == "oauth-personal":
            gemini_is_oauth = True
    except (OSError, json.JSONDecodeError) as exc:
        log_debug(f"Could not read Gemini settings: {exc}")
    gemini_key = "" if gemini_is_oauth else _credential_placeholder()

    # OpenCode/Zhipu: Only set placeholder if OpenCode is explicitly enabled
    if os.environ.get("SANDBOX_ENABLE_OPENCODE", "0") == "1":
        zhipu_key = _credential_placeholder()
    else:
        zhipu_key = ""

    # Tavily: Set flag if API key is available on host
    enable_tavily = "1" if os.environ.get("TAVILY_API_KEY") else "0"

    return CredentialPlaceholders(
        sandbox_anthropic_api_key=anthropic_key,
        sandbox_claude_oauth=claude_oauth,
        sandbox_gemini_api_key=gemini_key,
        sandbox_zhipu_api_key=zhipu_key,
        sandbox_enable_tavily=enable_tavily,
    )


# ============================================================================
# Subnet Generation
# ============================================================================


def _get_existing_docker_subnets() -> set[str]:
    """Return the set of subnets currently used by Docker networks."""
    subnets: set[str] = set()
    try:
        result = subprocess.run(
            ["docker", "network", "ls", "-q"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        if result.returncode != 0:
            return subnets
        for net_id in result.stdout.strip().splitlines():
            if not net_id:
                continue
            try:
                inspect = subprocess.run(
                    ["docker", "network", "inspect", net_id,
                     "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}"],
                    capture_output=True, text=True, check=False, timeout=5,
                )
                for s in inspect.stdout.strip().split():
                    if s:
                        subnets.add(s)
            except (OSError, subprocess.TimeoutExpired):
                pass
    except (OSError, subprocess.TimeoutExpired) as exc:
        log_debug(f"Could not list Docker networks for collision check: {exc}")
    return subnets


def generate_sandbox_subnet(project_name: str) -> tuple[str, str]:
    """Generate a unique /24 subnet for the credential-isolation network.

    Uses SHA-256 of the project name to derive subnet bytes in the
    10.x.x.0/24 range with values clamped to 1-254.  Checks for
    collisions with existing Docker networks and retries with a salt
    if needed.

    Args:
        project_name: Docker compose project name.

    Returns:
        Tuple of (subnet, proxy_ip) e.g. ("10.42.17.0/24", "10.42.17.2").
    """
    existing = _get_existing_docker_subnets()

    for salt in range(16):
        seed = project_name if salt == 0 else f"{project_name}\x00{salt}"
        digest = hashlib.sha256(seed.encode()).digest()
        # Use first two raw bytes — full 8-bit range each (vs 4 hex chars)
        byte1 = digest[0]
        byte2 = digest[1]

        # Clamp to valid range 1-254 (avoid 0=network and 255=broadcast)
        byte1 = max(1, min(254, byte1))
        byte2 = max(1, min(254, byte2))

        subnet = f"10.{byte1}.{byte2}.0/24"
        if subnet not in existing:
            proxy_ip = f"10.{byte1}.{byte2}.2"
            return subnet, proxy_ip
        log_debug(f"Subnet {subnet} collides with existing network (salt={salt}), retrying")

    # Exhausted retries — raise instead of silently using a colliding subnet
    raise RuntimeError(
        f"Could not find an unused /24 subnet for project '{project_name}' "
        f"after {16} attempts. Consider removing unused Docker networks."
    )


# ============================================================================
# Compose Command Building
# ============================================================================


def get_compose_command(
    override_file: str = "",
    isolate_credentials: bool = False,
) -> list[str]:
    """Build docker compose command with optional credential isolation.

    Args:
        override_file: Path to docker-compose override file (optional).
        isolate_credentials: Whether to include credential isolation compose file.

    Returns:
        List of command arguments for docker compose.
    """
    script_dir = str(_script_dir())
    cmd = [
        "docker", "compose",
        "-f", f"{script_dir}/docker-compose.yml",
    ]
    if isolate_credentials:
        cmd.extend(["-f", f"{script_dir}/docker-compose.credential-isolation.yml"])
    if override_file and Path(override_file).is_file():
        cmd.extend(["-f", override_file])
    return cmd


# ============================================================================
# Compose Up / Down
# ============================================================================


def compose_up(
    worktree_path: str,
    claude_config_path: str,
    container: str,
    override_file: str = "",
    isolate_credentials: bool = False,
    repos_dir: str = "",
    sandbox_id: str = "",
) -> None:
    """Start containers via docker compose up.

    Sets up required environment variables and runs compose up -d.

    Args:
        worktree_path: Path to git worktree.
        claude_config_path: Path to Claude config directory.
        container: Container/project name.
        override_file: Optional docker-compose override file.
        isolate_credentials: Whether to enable credential isolation.
        repos_dir: Repository directory (for compose volume substitution).
        sandbox_id: Sandbox ID (for HMAC secret provisioning).
    """
    env = os.environ.copy()
    env["WORKSPACE_PATH"] = worktree_path
    env["CLAUDE_CONFIG_PATH"] = claude_config_path
    env["CONTAINER_NAME"] = container

    if isolate_credentials:
        # Detect host auth config and set appropriate placeholder env vars
        cred_env = setup_credential_placeholders()
        env.update(cred_env.to_env_dict())

        # Generate a random session management key for this sandbox
        env["GATEWAY_SESSION_MGMT_KEY"] = secrets.token_bytes(32).hex()

        # Populate stubs volume (avoids Docker Desktop bind mount staleness)
        populate_stubs_volume(container)
        env["STUBS_VOLUME_NAME"] = f"{container}_stubs"

        # Export REPOS_DIR for docker-compose volume substitution
        env["REPOS_DIR"] = repos_dir or os.environ.get("REPOS_DIR", "")

        # Export git identity for unified-proxy
        env["GIT_USER_NAME"] = os.environ.get("GIT_USER_NAME", "")
        if not env["GIT_USER_NAME"]:
            try:
                result = subprocess.run(
                    ["git", "config", "--global", "user.name"],
                    capture_output=True, text=True, check=False,
                    timeout=TIMEOUT_GIT_QUERY,
                )
                env["GIT_USER_NAME"] = result.stdout.strip()
            except OSError as exc:
                log_debug(f"Could not read git user.name: {exc}")

        env["GIT_USER_EMAIL"] = os.environ.get("GIT_USER_EMAIL", "")
        if not env["GIT_USER_EMAIL"]:
            try:
                result = subprocess.run(
                    ["git", "config", "--global", "user.email"],
                    capture_output=True, text=True, check=False,
                    timeout=TIMEOUT_GIT_QUERY,
                )
                env["GIT_USER_EMAIL"] = result.stdout.strip()
            except OSError as exc:
                log_debug(f"Could not read git user.email: {exc}")

        # Git shadow mode: provision HMAC secret for git API authentication
        if sandbox_id:
            provision_hmac_secret(container, sandbox_id)
            env["HMAC_VOLUME_NAME"] = f"{container}_hmac"

        # Generate unique subnet for credential-isolation network
        subnet, proxy_ip = generate_sandbox_subnet(container)
        env["SANDBOX_SUBNET"] = subnet
        env["SANDBOX_PROXY_IP"] = proxy_ip

    compose_cmd = get_compose_command(override_file, isolate_credentials)
    cmd = compose_cmd + ["-p", container, "up", "-d"]

    if get_sandbox_verbose():
        print(f"+ {' '.join(cmd)}", file=sys.stderr)

    compose_result = subprocess.run(
        cmd, env=env, check=False,
        capture_output=True,
        timeout=TIMEOUT_DOCKER_COMPOSE,
    )
    if compose_result.returncode != 0:
        stderr_text = compose_result.stderr.decode() if isinstance(compose_result.stderr, bytes) else (compose_result.stderr or "")
        raise subprocess.CalledProcessError(
            compose_result.returncode, cmd, output=compose_result.stdout, stderr=stderr_text,
        )


def compose_down(
    worktree_path: str,
    claude_config_path: str,
    container: str,
    override_file: str = "",
    remove_volumes: bool = False,
    isolate_credentials: bool = False,
) -> None:
    """Stop containers via docker compose down.

    Args:
        worktree_path: Path to git worktree.
        claude_config_path: Path to Claude config directory.
        container: Container/project name.
        override_file: Optional docker-compose override file.
        remove_volumes: Whether to remove volumes (-v flag).
        isolate_credentials: Whether credential isolation is enabled.
    """
    env = os.environ.copy()
    env["WORKSPACE_PATH"] = worktree_path
    env["CLAUDE_CONFIG_PATH"] = claude_config_path
    env["CONTAINER_NAME"] = container

    # Auto-detect credential isolation if not explicitly set
    if not isolate_credentials:
        try:
            result = subprocess.run(
                ["docker", "ps", "-a", "--format", "{{.Names}}"],
                capture_output=True, text=True, check=False,
                timeout=TIMEOUT_DOCKER_QUERY,
            )
            for line in result.stdout.splitlines():
                if line.startswith(f"{container}-unified-proxy-"):
                    isolate_credentials = True
                    break
        except OSError as exc:
            log_debug(f"Could not detect credential isolation via docker ps: {exc}")

    if isolate_credentials:
        # Set placeholder values for compose file variable substitution.
        # These are only needed to suppress "variable is not set" warnings;
        # compose down does not create networks so the values are unused.
        env.setdefault("SANDBOX_SUBNET", "10.0.0.0/24")
        env.setdefault("SANDBOX_PROXY_IP", "10.0.0.2")

    compose_cmd = get_compose_command(override_file, isolate_credentials)
    cmd = compose_cmd + ["-p", container, "down"]
    if remove_volumes:
        cmd.append("-v")

    if get_sandbox_verbose():
        print(f"+ {' '.join(cmd)}", file=sys.stderr)

    subprocess.run(cmd, env=env, check=True, timeout=TIMEOUT_DOCKER_COMPOSE)


# ============================================================================
# Container Status & Interaction
# ============================================================================


def container_is_running(container: str) -> bool:
    """Check if a container is running.

    Args:
        container: Container project name.

    Returns:
        True if the dev container is running.
    """
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name=^{container}-dev",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, check=False,
            timeout=TIMEOUT_DOCKER_QUERY,
        )
        return bool(result.stdout.strip())
    except OSError as exc:
        log_debug(f"Could not check if container is running: {exc}")
        return False


def get_unified_proxy_host_port(container: str) -> str:
    """Get the unified-proxy host port for a container.

    Args:
        container: Container project name.

    Returns:
        Host port string, or empty string if not found.
    """
    proxy_container = f"{container}-unified-proxy-1"
    try:
        result = subprocess.run(
            ["docker", "port", proxy_container, "8080"],
            capture_output=True, text=True, check=False,
            timeout=TIMEOUT_DOCKER_QUERY,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return ""
        # Output is like "0.0.0.0:12345" or ":::12345", take first line
        first_line = result.stdout.strip().splitlines()[0]
        # Extract port after last colon
        return first_line.rsplit(":", 1)[-1]
    except OSError as exc:
        log_debug(f"Could not get proxy host port: {exc}")
        return ""


def setup_unified_proxy_url(container: str) -> str:
    """Set up GATEWAY_URL after containers start.

    Args:
        container: Container project name.

    Returns:
        Gateway URL string (e.g. "http://127.0.0.1:12345"), or empty on failure.
    """
    port = get_unified_proxy_host_port(container)
    if not port:
        return ""
    return f"http://127.0.0.1:{port}"


def exec_in_container(container_id: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Execute a command inside a container.

    Args:
        container_id: Docker container ID or name.
        *args: Command and arguments to run.

    Returns:
        CompletedProcess result.
    """
    return _run_cmd(["docker", "exec", container_id, *args], timeout=TIMEOUT_DOCKER_EXEC)


def copy_to_container(src: str, container_id: str, dst: str) -> None:
    """Copy a file to a container.

    Args:
        src: Source path on host.
        container_id: Docker container ID or name.
        dst: Destination path inside container.
    """
    _run_cmd(["docker", "cp", src, f"{container_id}:{dst}"], timeout=TIMEOUT_DOCKER_EXEC)


# ============================================================================
# Volume Management
# ============================================================================


def populate_stubs_volume(container: str) -> None:
    """Populate the stubs volume for credential isolation.

    Uses a temporary alpine container to copy stub files into the volume.
    This avoids Docker Desktop's VirtioFS/gRPC-FUSE file sync staleness issues.

    Args:
        container: Container project name.
    """
    volume_name = f"{container}_stubs"
    script_dir = str(_script_dir())

    # Create volume (ignore if exists)
    subprocess.run(
        ["docker", "volume", "create", volume_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
        timeout=TIMEOUT_DOCKER_VOLUME,
    )

    subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{script_dir}/unified-proxy:/src:ro",
            "-v", f"{volume_name}:/stubs",
            "alpine:latest",
            "sh", "-c",
            "cp /src/stub-*.json /src/stub-*.yml /stubs/ 2>/dev/null "
            "|| cp /src/stub-*.json /stubs/",
        ],
        check=True,
        timeout=TIMEOUT_DOCKER_VOLUME,
    )


def remove_stubs_volume(container: str) -> None:
    """Remove the stubs volume for a sandbox.

    Args:
        container: Container project name.
    """
    subprocess.run(
        ["docker", "volume", "rm", f"{container}_stubs"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
        timeout=TIMEOUT_DOCKER_VOLUME,
    )


def provision_hmac_secret(container: str, sandbox_id: str) -> None:
    """Provision per-sandbox HMAC secret for git API authentication.

    Creates a Docker volume containing the shared secret file.
    File mode 0444 is intentional: both runtime users (sandbox user and
    mitmproxy user) must read this file, and UID/GID differ across images.

    Args:
        container: Container project name.
        sandbox_id: Sandbox identifier for the secret filename.
    """
    volume_name = f"{container}_hmac"

    # Generate 32-byte (256-bit) random secret (base64 encoded)
    hmac_secret_b64 = base64.b64encode(secrets.token_bytes(32)).decode()

    # Create volume (ignore if exists)
    subprocess.run(
        ["docker", "volume", "create", volume_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
        timeout=TIMEOUT_DOCKER_VOLUME,
    )

    # Write secret to volume using temporary container.
    # Secret is piped via stdin to avoid leaking in process args or Docker logs.
    subprocess.run(
        [
            "docker", "run", "--rm", "-i",
            "-v", f"{volume_name}:/secrets",
            "alpine:latest",
            "sh", "-c",
            'cat > "/secrets/$1" && chmod 0444 "/secrets/$1"',
            "_", sandbox_id,
        ],
        input=hmac_secret_b64.encode(),
        check=True,
        timeout=TIMEOUT_DOCKER_VOLUME,
    )


def hmac_secret_file_count(container: str) -> int:
    """Return the number of HMAC secret files in a sandbox volume.

    Args:
        container: Container project name.

    Returns:
        Number of secret files, or 0 on error.
    """
    volume_name = f"{container}_hmac"
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{volume_name}:/secrets",
                "alpine:latest",
                "sh", "-c",
                "find /secrets -mindepth 1 -maxdepth 1 -type f | wc -l",
            ],
            capture_output=True, text=True, check=False,
            timeout=TIMEOUT_DOCKER_VOLUME,
        )
        return int(result.stdout.strip())
    except (OSError, ValueError) as exc:
        log_debug(f"Could not count HMAC secret files: {exc}")
        return 0


def repair_hmac_secret_permissions(container: str) -> None:
    """Ensure HMAC secret files are readable by both sandbox and proxy users.

    Args:
        container: Container project name.
    """
    volume_name = f"{container}_hmac"
    subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{volume_name}:/secrets",
            "alpine:latest",
            "sh", "-c",
            "find /secrets -mindepth 1 -maxdepth 1 -type f -exec chmod 0444 {} +",
        ],
        stdout=subprocess.DEVNULL, check=True,
        timeout=TIMEOUT_DOCKER_VOLUME,
    )


def remove_hmac_volume(container: str) -> None:
    """Remove the HMAC secrets volume for a sandbox.

    Args:
        container: Container project name.
    """
    subprocess.run(
        ["docker", "volume", "rm", f"{container}_hmac"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
        timeout=TIMEOUT_DOCKER_VOLUME,
    )


# ============================================================================
# Container / Network Helpers (moved from commands/_helpers.py)
# ============================================================================


def uses_credential_isolation(container: str) -> bool:
    """Check if a sandbox uses credential isolation.

    Args:
        container: Container name prefix.

    Returns:
        True if unified-proxy container exists.
    """
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_DOCKER_QUERY,
        )
        if result.returncode == 0:
            pattern = f"{container}-unified-proxy-"
            for line in result.stdout.splitlines():
                if line.strip().startswith(pattern):
                    return True
    except OSError:
        pass
    return False


def apply_network_restrictions(container_id: str, network_mode: str) -> None:
    """Apply network restrictions to a container.

    Args:
        container_id: Docker container ID.
        network_mode: Network mode (``limited``, ``host-only``, ``none``).
    """
    if network_mode == "limited":
        subprocess.run(
            ["docker", "exec", container_id, "sudo", "/usr/local/bin/network-firewall.sh"],
            check=False,
            timeout=TIMEOUT_DOCKER_EXEC,
        )
    else:
        subprocess.run(
            ["docker", "exec", container_id, "sudo", "/usr/local/bin/network-mode", network_mode],
            check=False,
            timeout=TIMEOUT_DOCKER_EXEC,
        )


def proxy_cleanup(container: str, container_id: str) -> None:
    """Best-effort proxy registration cleanup.

    Saves/restores CONTAINER_NAME env var to avoid leaking state.

    Args:
        container: Container name prefix (e.g. ``sandbox-foo``).
        container_id: Full dev container ID (e.g. ``sandbox-foo-dev-1``).
    """
    from foundry_sandbox.proxy import cleanup_proxy_registration

    prev_container_name = os.environ.get("CONTAINER_NAME")
    os.environ["CONTAINER_NAME"] = container
    try:
        cleanup_proxy_registration(container_id)
    except (OSError, subprocess.SubprocessError):
        pass
    finally:
        if prev_container_name is None:
            os.environ.pop("CONTAINER_NAME", None)
        else:
            os.environ["CONTAINER_NAME"] = prev_container_name


def remove_sandbox_networks(container: str) -> None:
    """Remove credential-isolation and proxy-egress networks for a sandbox.

    Best-effort: silently ignores failures.

    Args:
        container: Container/project name prefix (e.g. ``sandbox-foo``).
    """
    for suffix in ("credential-isolation", "proxy-egress"):
        network_name = f"{container}_{suffix}"
        try:
            inspect_result = subprocess.run(
                ["docker", "network", "inspect", network_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=TIMEOUT_DOCKER_NETWORK,
            )
            if inspect_result.returncode == 0:
                subprocess.run(
                    ["docker", "network", "rm", network_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=TIMEOUT_DOCKER_NETWORK,
                )
        except (OSError, subprocess.SubprocessError):
            pass


_NETWORK_PATTERN = re.compile(r"^sandbox-.*_(credential-isolation|proxy-egress)$")


def cleanup_orphaned_networks(
    *,
    skip_confirm: bool = True,
    confirm_fn: Callable[[str], bool] | None = None,
    check_running: bool = False,
) -> list[str]:
    """Remove orphaned sandbox Docker networks.

    Args:
        skip_confirm: If ``True`` remove without prompting.
        confirm_fn: Called with the network name; return ``True`` to proceed.
            Ignored when *skip_confirm* is ``True``.
        check_running: If ``True``, skip networks whose sandbox still has
            running containers.

    Returns:
        List of network names that were successfully removed.
    """
    removed: list[str] = []
    try:
        result = subprocess.run(
            ["docker", "network", "ls", "--format", "{{.Name}}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_DOCKER_QUERY,
        )
        if result.returncode != 0:
            return removed

        for line in result.stdout.splitlines():
            network_name = line.strip()
            if not network_name or not _NETWORK_PATTERN.match(network_name):
                continue

            # Optionally check for running containers
            if check_running:
                sandbox_prefix = network_name
                if sandbox_prefix.endswith("_credential-isolation"):
                    sandbox_prefix = sandbox_prefix[: -len("_credential-isolation")]
                elif sandbox_prefix.endswith("_proxy-egress"):
                    sandbox_prefix = sandbox_prefix[: -len("_proxy-egress")]
                try:
                    ps_result = subprocess.run(
                        ["docker", "ps", "-q", "--filter", f"name=^{sandbox_prefix}-"],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=TIMEOUT_DOCKER_QUERY,
                    )
                    if ps_result.stdout.strip():
                        continue  # Still has running containers
                except (OSError, subprocess.SubprocessError):
                    continue  # Fail-safe: skip if we can't check

            # Prompt
            if not skip_confirm:
                if confirm_fn and not confirm_fn(network_name):
                    continue

            # Disconnect dangling endpoints
            try:
                inspect_result = subprocess.run(
                    [
                        "docker", "network", "inspect",
                        "--format", "{{range .Containers}}{{.Name}} {{end}}",
                        network_name,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=TIMEOUT_DOCKER_NETWORK,
                )
                if inspect_result.returncode == 0:
                    for endpoint in inspect_result.stdout.strip().split():
                        if endpoint:
                            subprocess.run(
                                ["docker", "network", "disconnect", "-f", network_name, endpoint],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                check=False,
                                timeout=TIMEOUT_DOCKER_NETWORK,
                            )
            except (OSError, subprocess.SubprocessError):
                pass

            # Remove stopped containers referencing this sandbox
            if check_running:
                sandbox_name_for_rm = network_name
                if sandbox_name_for_rm.endswith("_credential-isolation"):
                    sandbox_name_for_rm = sandbox_name_for_rm[: -len("_credential-isolation")]
                elif sandbox_name_for_rm.endswith("_proxy-egress"):
                    sandbox_name_for_rm = sandbox_name_for_rm[: -len("_proxy-egress")]
                try:
                    stopped_result = subprocess.run(
                        [
                            "docker", "ps", "-aq",
                            "--filter", "status=exited",
                            "--filter", f"name=^{sandbox_name_for_rm}-",
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=TIMEOUT_DOCKER_QUERY,
                    )
                    for stopped_id in stopped_result.stdout.splitlines():
                        stopped_id = stopped_id.strip()
                        if stopped_id:
                            subprocess.run(
                                ["docker", "rm", stopped_id],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                check=False,
                                timeout=TIMEOUT_DOCKER_QUERY,
                            )
                except (OSError, subprocess.SubprocessError):
                    pass

            # Remove the network
            try:
                rm_result = subprocess.run(
                    ["docker", "network", "rm", network_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=TIMEOUT_DOCKER_NETWORK,
                )
                if rm_result.returncode == 0:
                    removed.append(network_name)
                else:
                    log_warn(f"Failed to remove network: {network_name}")
            except (OSError, subprocess.SubprocessError):
                log_warn(f"Failed to remove network: {network_name}")

    except (OSError, subprocess.SubprocessError):
        pass  # Docker may not be available

    return removed
