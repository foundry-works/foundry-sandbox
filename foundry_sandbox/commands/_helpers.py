"""Shared helper functions for sandbox commands.

Consolidates duplicated utilities from destroy.py, prune.py, legacy_bridge.py,
start.py, attach.py, and new.py.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from foundry_sandbox.constants import (
    SANDBOX_NAME_MAX_LENGTH,
    TIMEOUT_DOCKER_EXEC,
    TIMEOUT_DOCKER_NETWORK,
    TIMEOUT_DOCKER_QUERY,
    get_claude_configs_dir,
    get_repos_dir,
    get_worktrees_dir,
)
from foundry_sandbox.utils import log_debug, log_warn, sanitize_ref_component
from foundry_sandbox.validate import validate_existing_sandbox_name


def repo_url_to_bare_path(repo_url: str) -> str:
    """Convert a repository URL to its bare-clone path under REPOS_DIR.

    Handles https://, http://, git@, and local filesystem paths.

    Args:
        repo_url: Repository URL or local path.

    Returns:
        Absolute path string to the bare repository.
    """
    repos_dir = str(get_repos_dir())

    if not repo_url:
        return f"{repos_dir}/unknown.git"

    # Local filesystem path
    if repo_url.startswith(("~/", "/", "./", "../")):
        expanded = repo_url
        if expanded.startswith("~/"):
            expanded = str(Path.home()) + expanded[1:]
        p = Path(expanded)
        if p.exists():
            try:
                expanded = str(p.resolve())
            except OSError:
                pass
        stripped = expanded.lstrip("/")
        return f"{repos_dir}/local/{stripped}.git"

    # HTTPS, HTTP, or git@ URL
    path = repo_url
    path = path.removeprefix("https://")
    path = path.removeprefix("http://")
    path = path.removeprefix("git@")
    path = path.replace(":", "/", 1) if ":" in path else path
    if path.endswith(".git"):
        path = path[:-4]
    return f"{repos_dir}/{path}.git"


# Re-export from canonical location for backwards compatibility
from foundry_sandbox.utils import flag_enabled  # noqa: F401


def tmux_session_name(name: str) -> str:
    """Return the tmux session name for a sandbox.

    Currently just returns the sandbox name as-is.

    Args:
        name: Sandbox name.

    Returns:
        Tmux session name.
    """
    return name


def shell_call(*args: str) -> subprocess.CompletedProcess[str]:
    """Call legacy bridge with arguments (stdout/stderr passed through).

    Args:
        *args: Arguments to pass to the legacy bridge.

    Returns:
        CompletedProcess result.
    """
    from foundry_sandbox.legacy_bridge import run_legacy_command
    return run_legacy_command(*args, capture_output=False)


def shell_call_capture(*args: str) -> str:
    """Call legacy bridge with arguments and capture stdout.

    Args:
        *args: Arguments to pass to the legacy bridge.

    Returns:
        stdout output as string (stripped), or empty string on failure.
    """
    from foundry_sandbox.legacy_bridge import run_legacy_command
    result = run_legacy_command(*args, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def auto_detect_sandbox() -> str | None:
    """Auto-detect sandbox name from current working directory.

    If the cwd is under the worktrees directory, extracts the first path
    component as the sandbox name.

    Returns:
        Sandbox name if detected, None otherwise.
    """
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        return None

    worktrees_dir = get_worktrees_dir()

    try:
        relative = cwd.relative_to(worktrees_dir)
        parts = relative.parts
        if parts:
            name = parts[0]
            valid, _ = validate_existing_sandbox_name(name)
            if valid and (worktrees_dir / name).is_dir():
                return name
    except ValueError:
        pass

    return None


# ---------------------------------------------------------------------------
# Pure functions (moved from legacy_bridge.py)
# ---------------------------------------------------------------------------


def sandbox_name(bare_path: str, branch: str) -> str:
    """Generate a sandbox name from bare repo path and branch.

    Args:
        bare_path: Path to bare repository.
        branch: Branch name.

    Returns:
        Sanitised sandbox name.
    """
    repo = Path(bare_path).name
    if repo.endswith(".git"):
        repo = repo[:-4]
    repo = sanitize_ref_component(repo) or "repo"
    branch_part = sanitize_ref_component(branch) or "branch"
    name = f"{repo}-{branch_part}".lower()
    if len(name) > SANDBOX_NAME_MAX_LENGTH:
        digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:8]
        name = f"{name[:SANDBOX_NAME_MAX_LENGTH - 9]}-{digest}"
    return name


def find_next_sandbox_name(base_name: str) -> str:
    """Find next available sandbox name by appending a numeric suffix.

    Args:
        base_name: Desired sandbox name.

    Returns:
        *base_name* if available, otherwise *base_name*-N.
    """
    worktrees = get_worktrees_dir()
    configs = get_claude_configs_dir()

    def _taken(candidate: str) -> bool:
        return (worktrees / candidate).exists() or (configs / candidate).exists()

    if not _taken(base_name):
        return base_name

    for i in range(2, 10_000):
        candidate = f"{base_name}-{i}"
        if not _taken(candidate):
            return candidate
    return f"{base_name}-{os.getpid()}"


def resolve_ssh_agent_sock() -> str:
    """Find SSH agent socket from environment.

    Returns:
        Socket path if it exists, empty string otherwise.
    """
    sock = os.environ.get("SSH_AUTH_SOCK", "")
    if not sock:
        return ""
    return sock if Path(sock).exists() else ""


def generate_sandbox_id(seed: str) -> str:
    """Generate a sandbox ID from a seed string using SHA-256.

    Args:
        seed: Seed string.

    Returns:
        32-character hex digest.
    """
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Shared UI helpers (deduplicated from attach.py, refresh_creds.py)
# ---------------------------------------------------------------------------


def fzf_select_sandbox() -> str | None:
    """Interactively select a sandbox using fzf.

    Returns:
        Selected sandbox name, or None if canceled/unavailable.
    """
    worktrees_dir = get_worktrees_dir()

    if not worktrees_dir.is_dir():
        return None

    if shutil.which("fzf") is None:
        return None

    try:
        sandboxes = sorted(
            entry.name for entry in worktrees_dir.iterdir()
            if entry.is_dir()
        )

        if not sandboxes:
            return None

        result = subprocess.run(
            ["fzf", "--prompt=Select sandbox: ", "--height=10", "--reverse"],
            input="\n".join(sandboxes),
            text=True,
            capture_output=True,
            check=False,
        )

        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        log_debug("fzf selection failed, falling back")

    return None


def list_sandbox_names() -> list[str]:
    """List all sandbox names by scanning WORKTREES_DIR.

    Returns:
        Sorted list of sandbox directory names.
    """
    worktrees_dir = get_worktrees_dir()
    if not worktrees_dir.is_dir():
        return []

    try:
        return sorted(entry.name for entry in worktrees_dir.iterdir() if entry.is_dir())
    except OSError:
        return []


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


def strip_github_url(repo_url: str) -> str:
    """Strip GitHub URL prefixes and .git suffix to get owner/repo spec.

    Args:
        repo_url: Full repository URL.

    Returns:
        Short ``owner/repo`` form.
    """
    spec = repo_url
    spec = spec.removeprefix("https://github.com/")
    spec = spec.removeprefix("http://github.com/")
    spec = spec.removeprefix("git@github.com:")
    if spec.endswith(".git"):
        spec = spec[:-4]
    return spec


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


# ---------------------------------------------------------------------------
# Orphaned network cleanup (shared by destroy_all.py and prune.py)
# ---------------------------------------------------------------------------

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
                sandbox_name = network_name
                if sandbox_name.endswith("_credential-isolation"):
                    sandbox_name = sandbox_name[: -len("_credential-isolation")]
                elif sandbox_name.endswith("_proxy-egress"):
                    sandbox_name = sandbox_name[: -len("_proxy-egress")]
                try:
                    ps_result = subprocess.run(
                        ["docker", "ps", "-q", "--filter", f"name=^{sandbox_name}-"],
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
