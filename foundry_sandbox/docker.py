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
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

import yaml

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

    # Zhipu: Set placeholder if OpenCode or ZAI is enabled (both use ZHIPU_API_KEY)
    if os.environ.get("SANDBOX_ENABLE_OPENCODE", "0") == "1" or os.environ.get("SANDBOX_ENABLE_ZAI", "0") == "1":
        zhipu_key = _credential_placeholder()
    else:
        zhipu_key = ""

    # OpenAI: route SDK traffic through the gateway for fast credential injection.
    # Codex CLI uses a shell wrapper that unsets OPENAI_BASE_URL so subscription
    # mode still routes through chatgpt.com → TLS interception on port 443.
    openai_base_url = "http://unified-proxy:9849"

    # User-defined services: generate placeholders for any with env var set on host
    from foundry_sandbox.user_services import load_user_services

    user_placeholders: dict[str, str] = {}
    for svc in load_user_services():
        if os.environ.get(svc.env_var):
            user_placeholders[svc.env_var] = _credential_placeholder()
            log_debug(f"User service '{svc.name}': placeholder generated for {svc.env_var}")

    return CredentialPlaceholders(
        sandbox_anthropic_api_key=anthropic_key,
        sandbox_claude_oauth=claude_oauth,
        sandbox_gemini_api_key=gemini_key,
        sandbox_zhipu_api_key=zhipu_key,
        sandbox_openai_base_url=openai_base_url,
        user_service_placeholders=user_placeholders,
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
# Compose Extras Collection
# ============================================================================


def _collect_compose_extras(
    extra_paths: list[str] | None = None,
    strict: bool = True,
) -> list[str]:
    """Collect compose extras from auto-discovery, env var, and caller paths.

    Sources are collected in precedence order (later overrides earlier in
    docker-compose merge semantics):

    1. Auto-discovered: ``config/docker-compose.*.yml`` (sorted by name)
    2. ``FOUNDRY_COMPOSE_EXTRAS`` env var (colon-separated paths)
    3. *extra_paths* parameter (additional paths from caller)

    All paths are resolved to absolute before validation and deduplication.
    Deduplication preserves the earliest occurrence when the same file is
    referenced via different relative/absolute paths.

    This function does **not** include the temp overrides for
    allowlist/user-services — those are added separately by their existing
    ``_prepare_*`` functions.

    Args:
        extra_paths: Optional list of additional compose override file paths.
        strict: If True (default), raise FileNotFoundError for missing paths.
            If False, skip missing paths with a warning (suitable for teardown).

    Returns:
        Deduplicated list of validated absolute paths.

    Raises:
        FileNotFoundError: If *strict* is True and any path does not exist
            or is not a regular file.
    """
    # (original_path, source_label) — source_label used in error messages
    raw_paths: list[tuple[str, str]] = []

    # 1. Auto-discovery: config/docker-compose.*.yml
    config_dir = _script_dir() / "config"
    if config_dir.is_dir():
        discovered = sorted(config_dir.glob("docker-compose.*.yml"))
        for p in discovered:
            raw_paths.append((str(p), "auto-discovered"))

    # 2. FOUNDRY_COMPOSE_EXTRAS env var (colon-separated)
    env_extras = os.environ.get("FOUNDRY_COMPOSE_EXTRAS", "")
    if env_extras:
        for segment in env_extras.split(":"):
            segment = segment.strip()
            if segment:
                raw_paths.append((segment, "FOUNDRY_COMPOSE_EXTRAS"))

    # 3. Caller-provided extra paths
    if extra_paths:
        for cli_path in extra_paths:
            raw_paths.append((cli_path, "extra_paths"))

    # Resolve, validate, deduplicate
    seen: set[Path] = set()
    result: list[str] = []
    for original, source in raw_paths:
        resolved = Path(original).resolve()
        if not resolved.exists() or not resolved.is_file():
            if strict:
                raise FileNotFoundError(
                    f"Compose extras path does not exist or is not a regular file: "
                    f"{original} (source: {source})"
                )
            log_warn(f"Compose extras path not found, skipping: {original} (source: {source})")
            continue
        if resolved not in seen:
            seen.add(resolved)
            result.append(str(resolved))

    if result:
        log_debug(f"Compose extras collected: {result}")

    return result


def resolve_metadata_compose_extras(metadata: dict[str, object]) -> list[str]:
    """Resolve compose extras from metadata (relative paths) to absolute paths.

    Paths stored in metadata are relative to the project root.  This function
    resolves them back to absolute paths, skipping any that no longer exist
    (with a warning).

    Args:
        metadata: Sandbox metadata dictionary.

    Returns:
        List of absolute paths to existing compose extra files.
    """
    raw = metadata.get("compose_extras", [])
    if not isinstance(raw, list):
        return []
    project_root = _script_dir()
    result: list[str] = []
    for rel_path in raw:
        if not isinstance(rel_path, str) or not rel_path:
            continue
        resolved = (project_root / rel_path).resolve()
        if resolved.is_file():
            result.append(str(resolved))
        else:
            log_warn(f"Compose extra from metadata not found, skipping: {rel_path}")
    return result


def relativize_compose_extras(paths: list[str]) -> list[str]:
    """Convert absolute compose extra paths to project-root-relative strings.

    Falls back to the absolute path for any path that is outside the project
    root.

    Args:
        paths: List of (possibly absolute) file paths.

    Returns:
        List of relative path strings (or absolute if outside project root).
    """
    project_root = _script_dir()
    result: list[str] = []
    for p in paths:
        try:
            result.append(str(Path(p).resolve().relative_to(project_root)))
        except ValueError:
            result.append(str(Path(p).resolve()))
    return result


# ============================================================================
# Compose Command Building
# ============================================================================


def get_compose_command(
    override_file: str = "",
    isolate_credentials: bool = False,
    compose_extras: list[str] | None = None,
) -> list[str]:
    """Build docker compose command with optional credential isolation.

    Args:
        override_file: Path to docker-compose override file (optional).
        isolate_credentials: Whether to include credential isolation compose file.
        compose_extras: Optional list of paths to additional compose override files.
            Each path must exist and be a regular file.

    Returns:
        List of command arguments for docker compose.

    Raises:
        FileNotFoundError: If any compose_extras path does not exist or is not
            a regular file.
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
    if compose_extras:
        for extra_path in compose_extras:
            p = Path(extra_path)
            if not p.exists() or not p.is_file():
                raise FileNotFoundError(
                    f"Compose extras path does not exist or is not a regular file: {extra_path}"
                )
            cmd.extend(["-f", extra_path])
    return cmd


# ============================================================================
# Compose Up / Down
# ============================================================================


def _wait_for_proxy_health(container_name: str, timeout: int = 55) -> bool:
    """Poll a proxy container's health status until healthy or timeout."""
    import time as _time

    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", container_name],
                capture_output=True, text=True, check=False, timeout=5,
            )
            status = result.stdout.strip()
            if status == "healthy":
                return True
            if status == "exited" or (
                result.returncode != 0 and "No such" in result.stderr
            ):
                return False
            # Also check if the container process exited
            state_result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
                capture_output=True, text=True, check=False, timeout=5,
            )
            if state_result.stdout.strip() == "false":
                return False
        except (OSError, subprocess.TimeoutExpired) as exc:
            log_debug(f"Proxy health check attempt failed: {exc}")
        _time.sleep(2)
    return False


def _capture_container_logs(container_name: str) -> str:
    """Capture logs from a container for diagnostic purposes."""
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", "100", container_name],
            capture_output=True, text=True, check=False, timeout=10,
        )
        return (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        return "(failed to capture container logs)"


def _build_compose_env(
    worktree_path: str,
    claude_config_path: str,
    container: str,
    isolate_credentials: bool,
    repos_dir: str,
    sandbox_id: str,
    anthropic_base_url: str,
) -> dict[str, str]:
    """Build the environment dict for docker compose up.

    Handles credential placeholders, git identity, HMAC provisioning,
    and subnet generation for credential-isolation mode.

    Returns:
        Environment dictionary ready for subprocess.run().
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

    # Anthropic base URL: CLI arg takes precedence over host env
    base_url = anthropic_base_url or os.environ.get("ANTHROPIC_BASE_URL", "")
    if base_url:
        env["ANTHROPIC_BASE_URL"] = base_url

    if isolate_credentials:
        # Git shadow mode: provision HMAC secret for git API authentication
        if sandbox_id:
            provision_hmac_secret(container, sandbox_id)
            env["HMAC_VOLUME_NAME"] = f"{container}_hmac"

        # Generate unique subnet for credential-isolation network
        subnet, proxy_ip = generate_sandbox_subnet(container)
        env["SANDBOX_SUBNET"] = subnet
        env["SANDBOX_PROXY_IP"] = proxy_ip

    return env


def _prepare_allowlist_override(
    isolate_credentials: bool,
    compose_extras: list[str] | None,
) -> tuple[str | None, list[str] | None]:
    """Create a temp compose override for PROXY_ALLOWLIST_EXTRA_PATH if needed.

    Returns:
        Tuple of (temp_file_path or None, updated compose_extras or original).
        The caller must delete temp_file_path when done.
    """
    if not isolate_credentials:
        return None, compose_extras

    host_extra = os.environ.get("PROXY_ALLOWLIST_EXTRA_PATH", "")
    if not host_extra:
        return None, compose_extras

    host_extra = os.path.realpath(host_extra)
    if not os.path.isfile(host_extra):
        raise FileNotFoundError(
            f"PROXY_ALLOWLIST_EXTRA_PATH is not a regular file: {host_extra}"
        )
    # Belt-and-suspenders: reject paths with control characters that could
    # corrupt YAML output even when using a safe serializer.
    for ch in ("\n", "\r", "\x00"):
        if ch in host_extra:
            raise ValueError(
                f"PROXY_ALLOWLIST_EXTRA_PATH contains invalid character: {host_extra!r}"
            )
    container_mount = "/etc/unified-proxy/allowlist-extra.yml"
    override_dict = {
        "services": {
            "unified-proxy": {
                "volumes": [f"{host_extra}:{container_mount}:ro"],
                "environment": [f"PROXY_ALLOWLIST_EXTRA_PATH={container_mount}"],
            }
        }
    }
    override_content = yaml.dump(override_dict, default_flow_style=False)
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", prefix="allowlist-extra-",
        delete=False,
    )
    tmp_path = f.name
    f.write(override_content)
    f.close()
    os.chmod(tmp_path, 0o600)
    compose_extras = list(compose_extras or []) + [tmp_path]
    return tmp_path, compose_extras


def _prepare_user_services_override(
    isolate_credentials: bool,
    compose_extras: list[str] | None,
) -> tuple[str | None, list[str] | None]:
    """Create a temp compose override that mounts user-services.yaml and threads env vars.

    Returns:
        Tuple of (temp_file_path or None, updated compose_extras or original).
        The caller must delete temp_file_path when done.
    """
    if not isolate_credentials:
        return None, compose_extras

    from foundry_sandbox.user_services import load_user_services, find_user_services_path

    # Resolve path first, then pass to load_user_services() to avoid a
    # redundant filesystem check (load_user_services would call
    # find_user_services_path() internally if no path is given).
    raw_config_path = find_user_services_path()
    if raw_config_path is None:
        return None, compose_extras

    services = load_user_services(path=raw_config_path)
    if not services:
        return None, compose_extras

    config_path = os.path.realpath(raw_config_path)
    container_mount = "/etc/unified-proxy/user-services.yaml"

    # Build compose override: mount config + pass env vars
    proxy_volumes = [f"{config_path}:{container_mount}:ro"]
    proxy_env: list[str] = []
    dev_env: list[str] = []

    for svc in services:
        # Pass real env var to proxy (compose inherits from host)
        proxy_env.append(svc.env_var)
        # Pass placeholder to dev container (only if host env var is set,
        # so unconfigured services don't get empty-string env vars)
        if os.environ.get(svc.env_var):
            dev_env.append(f"{svc.env_var}=${{SANDBOX_{svc.env_var}}}")

    override_dict: dict[str, object] = {
        "services": {
            "unified-proxy": {
                "volumes": proxy_volumes,
                "environment": proxy_env,
            },
            "dev": {
                "environment": dev_env,
            },
        }
    }

    override_content = yaml.dump(override_dict, default_flow_style=False)
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", prefix="user-services-",
        delete=False,
    )
    tmp_path = f.name
    f.write(override_content)
    f.close()
    os.chmod(tmp_path, 0o600)
    compose_extras = list(compose_extras or []) + [tmp_path]
    return tmp_path, compose_extras


def _start_proxy_first(
    compose_cmd: list[str],
    container: str,
    env: dict[str, str],
) -> None:
    """Two-phase proxy startup with health check and log capture.

    Starts the unified-proxy service independently and waits for it to
    become healthy before the remaining services are brought up.  On
    failure, proxy logs are captured for diagnosis.
    """
    proxy_cmd = compose_cmd + ["-p", container, "up", "-d", "--no-deps", "unified-proxy"]
    if get_sandbox_verbose():
        print(f"+ {' '.join(proxy_cmd)}", file=sys.stderr)
    proxy_result = subprocess.run(
        proxy_cmd, env=env, check=False,
        capture_output=True, timeout=TIMEOUT_DOCKER_COMPOSE,
    )
    if proxy_result.returncode != 0:
        stderr_text = proxy_result.stderr.decode() if isinstance(proxy_result.stderr, bytes) else (proxy_result.stderr or "")
        raise subprocess.CalledProcessError(
            proxy_result.returncode, proxy_cmd, output=proxy_result.stdout, stderr=stderr_text,
        )

    # Wait for proxy health (matches compose healthcheck: start_period=30s + retries=5 * interval=5s)
    proxy_container = f"{container}-unified-proxy-1"
    proxy_healthy = _wait_for_proxy_health(proxy_container, timeout=55)
    if not proxy_healthy:
        # Capture proxy logs for diagnosis before cleanup
        logs = _capture_container_logs(proxy_container)
        # Stop the proxy so compose down can clean up
        subprocess.run(
            ["docker", "rm", "-f", proxy_container],
            capture_output=True, check=False, timeout=TIMEOUT_DOCKER_QUERY,
        )
        raise subprocess.CalledProcessError(
            1, proxy_cmd,
            stderr=f"unified-proxy failed health check.\n--- Proxy Logs ---\n{logs}",
        )


def compose_up(
    worktree_path: str,
    claude_config_path: str,
    container: str,
    override_file: str = "",
    isolate_credentials: bool = False,
    repos_dir: str = "",
    sandbox_id: str = "",
    anthropic_base_url: str = "",
    compose_extras: list[str] | None = None,
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
        anthropic_base_url: Optional Anthropic API base URL override.
        compose_extras: Optional list of additional compose override file paths.
    """
    env = _build_compose_env(
        worktree_path, claude_config_path, container,
        isolate_credentials, repos_dir, sandbox_id, anthropic_base_url,
    )

    # Collect sidecar extras (auto-discovery + env var + caller paths).
    # The _prepare_* functions below will append their temp overrides after.
    compose_extras = _collect_compose_extras(extra_paths=compose_extras) or None

    _compose_overrides: list[str] = []
    try:
        allowlist_tmp, compose_extras = _prepare_allowlist_override(
            isolate_credentials, compose_extras,
        )
        if allowlist_tmp:
            _compose_overrides.append(allowlist_tmp)

        user_svc_tmp, compose_extras = _prepare_user_services_override(
            isolate_credentials, compose_extras,
        )
        if user_svc_tmp:
            _compose_overrides.append(user_svc_tmp)

        compose_cmd = get_compose_command(override_file, isolate_credentials, compose_extras)

        if isolate_credentials:
            _start_proxy_first(compose_cmd, container, env)

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
    finally:
        for tmp_path in _compose_overrides:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def compose_down(
    worktree_path: str,
    claude_config_path: str,
    container: str,
    override_file: str = "",
    remove_volumes: bool = False,
    isolate_credentials: bool = False,
    compose_extras: list[str] | None = None,
) -> None:
    """Stop containers via docker compose down.

    Args:
        worktree_path: Path to git worktree.
        claude_config_path: Path to Claude config directory.
        container: Container/project name.
        override_file: Optional docker-compose override file.
        remove_volumes: Whether to remove volumes (-v flag).
        isolate_credentials: Whether credential isolation is enabled.
        compose_extras: Optional list of additional compose override file paths.
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

    # Collect sidecar extras (auto-discovery + env var + caller paths).
    # Use strict=False: during teardown, files may already be gone.
    compose_extras = _collect_compose_extras(extra_paths=compose_extras, strict=False) or None

    compose_cmd = get_compose_command(override_file, isolate_credentials, compose_extras)
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


def exec_in_container_streaming(
    container_id: str, *args: str, timeout: int = 3600
) -> int:
    """Execute a command inside a container with real-time output streaming.

    Unlike exec_in_container(), stdout and stderr are inherited (not captured),
    so output streams to the caller's terminal in real time.

    Args:
        container_id: Docker container ID or name.
        *args: Command and arguments to run.
        timeout: Maximum seconds to wait (default 3600). Returns 124 on timeout.

    Returns:
        Process exit code, or 124 on timeout (coreutils convention).
    """
    cmd = ["docker", "exec", container_id, *args]
    if get_sandbox_verbose():
        print(f"+ {' '.join(cmd)}", file=sys.stderr)

    proc = subprocess.Popen(cmd)
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Graceful shutdown: SIGTERM → wait 5s → SIGKILL → reap
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        return 124


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
    except (OSError, subprocess.SubprocessError) as e:
        log_warn(f"Proxy cleanup failed for {container}: {e}")
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
