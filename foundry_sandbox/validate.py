"""Input validation for foundry-sandbox.

Replaces lib/validate.sh (252 lines). Pure validation logic for sandbox names,
URLs, mount paths, SSH modes, environment requirements, git remote credential
detection, and Docker network capacity checking.

No Click or Pydantic imports at module level (bridge-callable constraint).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from foundry_sandbox._bridge import bridge_main
from foundry_sandbox.constants import (
    get_repos_dir,
    get_worktrees_dir,
    get_claude_configs_dir,
)
from foundry_sandbox.paths import ensure_dir
from foundry_sandbox.utils import log_error, log_warn


# ============================================================================
# Dangerous Paths (credential directories)
# ============================================================================

def _dangerous_paths() -> list[Path]:
    """Return list of dangerous credential paths that should not be mounted.

    Computed at call time (not module load) so $HOME is respected.
    """
    home = Path.home()
    return [
        home / ".ssh",
        home / ".aws",
        home / ".config" / "gcloud",
        home / ".config" / "gh",
        home / ".azure",
        home / ".netrc",
        home / ".kube",
        home / ".gnupg",
        home / ".docker",
        home / ".npmrc",
        home / ".pypirc",
        Path("/var/run/docker.sock"),
        Path("/run/docker.sock"),
    ]


# ============================================================================
# Path Validation
# ============================================================================


def _resolve_path(path: str | Path, must_exist: bool = False) -> Path:
    """Resolve a path to its canonical form.

    Cross-platform equivalent of _realpath_canonical from validate.sh.

    Args:
        path: Path to resolve.
        must_exist: If True, resolve symlinks strictly (path must exist).

    Returns:
        Resolved Path object.
    """
    p = Path(path)
    if must_exist:
        try:
            return p.resolve(strict=True)
        except OSError:
            return p.resolve(strict=False)
    return p.resolve(strict=False)


def validate_mount_path(mount_path: str) -> tuple[bool, str]:
    """Validate that a mount path does not expose credential directories.

    Checks the canonical path against known dangerous paths to prevent
    mounting credential directories into sandboxes.

    Args:
        mount_path: Host path to validate.

    Returns:
        Tuple of (is_valid, error_message). error_message is empty if valid.
    """
    # Resolve the canonical path, preferring existing paths for security
    # (prevents TOCTOU race conditions with symlink swaps)
    canonical = _resolve_path(mount_path, must_exist=True)

    for dangerous in _dangerous_paths():
        dangerous_canonical = _resolve_path(str(dangerous), must_exist=True)

        # Check exact match
        if canonical == dangerous_canonical:
            return False, (
                f"Mount path '{mount_path}' is a dangerous credential path: "
                f"{dangerous}"
            )

        # Check if mount is parent of dangerous (would expose credentials)
        try:
            dangerous_canonical.relative_to(canonical)
            return False, (
                f"Mount path '{mount_path}' would expose credential directory: "
                f"{dangerous}"
            )
        except ValueError:
            pass

        # Check if mount is child of dangerous (inside credentials)
        try:
            canonical.relative_to(dangerous_canonical)
            return False, (
                f"Mount path '{mount_path}' is inside credential directory: "
                f"{dangerous}"
            )
        except ValueError:
            pass

    return True, ""


# ============================================================================
# Name and URL Validation
# ============================================================================


def validate_sandbox_name(name: str) -> tuple[bool, str]:
    """Validate a sandbox name.

    Args:
        name: Sandbox name to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not name:
        return False, "Sandbox name required"
    return True, ""


def validate_git_url(url: str) -> tuple[bool, str]:
    """Validate a git repository URL.

    Accepts http(s) URLs, git@ SSH URLs, and org/repo shorthand.

    Args:
        url: Repository URL to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not url:
        return False, "Repository URL required"
    if not (url.startswith("http") or url.startswith("git@") or "/" in url):
        return False, f"Invalid repository URL: {url}"
    return True, ""


def validate_ssh_mode(mode: str) -> tuple[bool, str]:
    """Validate an SSH mode value.

    Args:
        mode: SSH mode to validate (init, always, disabled).

    Returns:
        Tuple of (is_valid, error_message).
    """
    valid_modes = {"init", "always", "disabled"}
    if mode not in valid_modes:
        return False, f"Invalid SSH mode: {mode} (use: always, disabled)"
    return True, ""


# ============================================================================
# Environment Validation
# ============================================================================


def require_command(cmd: str) -> tuple[bool, str]:
    """Check that a command is available on the system.

    Args:
        cmd: Command name to check.

    Returns:
        Tuple of (is_available, error_message).
    """
    if shutil.which(cmd) is None:
        return False, f"Missing required command: {cmd}"
    return True, ""


def check_docker_running() -> tuple[bool, str]:
    """Check that Docker is running and accessible.

    Returns:
        Tuple of (is_running, error_message).
    """
    try:
        result = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode != 0:
            return False, "Docker is not running or not accessible"
        return True, ""
    except OSError:
        return False, "Docker is not running or not accessible"


def validate_environment() -> tuple[bool, str]:
    """Validate the required environment (git, docker, directories).

    Ensures required commands are available and creates necessary directories.

    Returns:
        Tuple of (is_valid, error_message).
    """
    for cmd in ("git", "docker"):
        ok, msg = require_command(cmd)
        if not ok:
            return False, msg

    ensure_dir(get_repos_dir())
    ensure_dir(get_worktrees_dir())
    ensure_dir(get_claude_configs_dir())
    return True, ""


# ============================================================================
# Docker Network Capacity
# ============================================================================


def check_docker_network_capacity(
    isolate_credentials: bool = True,
) -> tuple[bool, str]:
    """Check Docker network pool availability.

    Only relevant when credential isolation is enabled (creates networks).
    Creates a test network to verify capacity, then cleans up.

    Args:
        isolate_credentials: Whether credential isolation is enabled.

    Returns:
        Tuple of (has_capacity, error_message).
    """
    if not isolate_credentials:
        return True, ""

    # Count existing sandbox networks
    sandbox_network_count = 0
    try:
        result = subprocess.run(
            ["docker", "network", "ls", "--format", "{{.Name}}"],
            capture_output=True, text=True, check=False,
        )
        for line in result.stdout.splitlines():
            if line.startswith("sandbox-"):
                sandbox_network_count += 1
    except OSError:
        pass

    # Try to create a test network to verify capacity
    test_name = f"sandbox-network-capacity-test-{os.getpid()}"
    try:
        result = subprocess.run(
            ["docker", "network", "create", test_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode != 0:
            msg = (
                "Docker network address pool exhausted\n"
                "\n"
                "Docker cannot create new networks. This typically happens when:\n"
                "  - Many sandboxes have been created without cleanup\n"
                "  - Orphaned networks remain from destroyed sandboxes\n"
                "\n"
                f"Current sandbox networks: {sandbox_network_count}\n"
                "\n"
                "Remediation steps:\n"
                "  1. Clean up orphaned sandbox networks:\n"
                "     cast prune --networks\n"
                "\n"
                "  2. If that doesn't help, remove ALL unused Docker networks:\n"
                "     docker network prune\n"
                "\n"
                "  3. If problems persist, restart Docker Desktop"
            )
            return False, msg
    except OSError:
        return False, "Docker is not running or not accessible"

    # Clean up test network
    subprocess.run(
        ["docker", "network", "rm", test_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
    )

    # Warn if many sandbox networks exist
    if sandbox_network_count > 20:
        # Count orphaned networks (no running containers)
        orphaned_count = 0
        try:
            result = subprocess.run(
                ["docker", "network", "ls", "--format", "{{.Name}}"],
                capture_output=True, text=True, check=False,
            )
            for net in result.stdout.splitlines():
                if not net.startswith("sandbox-"):
                    continue
                sandbox_name = net.removesuffix("_credential-isolation")
                sandbox_name = sandbox_name.removesuffix("_proxy-egress")
                check = subprocess.run(
                    ["docker", "ps", "-q", "--filter", f"name=^{sandbox_name}-"],
                    capture_output=True, text=True, check=False,
                )
                if not check.stdout.strip():
                    orphaned_count += 1
        except OSError:
            pass

        if orphaned_count > 0:
            log_warn(
                f"Found {orphaned_count} orphaned sandbox networks "
                f"(of {sandbox_network_count} total)"
            )
            log_warn("Run 'cast prune --networks' to clean up")
        else:
            log_warn(f"Found {sandbox_network_count} active sandbox networks")
            log_warn("Consider destroying unused sandboxes with 'cast destroy <name>'")

    return True, ""


# ============================================================================
# Git Remote Credential Detection
# ============================================================================

# Pattern: ://user:password@host (credentials embedded in URL)
_CREDENTIAL_PATTERN = re.compile(r"://[^/:@]+:[^/:@]+@[^/]+")


def validate_git_remotes(git_dir: str = ".git") -> tuple[bool, str]:
    """Detect embedded credentials in git remote URLs.

    Scans the git config for URLs containing user:password@ patterns.

    Args:
        git_dir: Path to the .git directory.

    Returns:
        Tuple of (is_clean, error_message).
    """
    config_file = Path(git_dir) / "config"
    if not config_file.is_file():
        return True, ""

    try:
        content = config_file.read_text()
    except OSError:
        return True, ""

    offending_lines = []
    for line in content.splitlines():
        if _CREDENTIAL_PATTERN.search(line):
            offending_lines.append(line.strip())

    if not offending_lines:
        return True, ""

    # Redact passwords in error message
    redacted = []
    for line in offending_lines[:3]:
        redacted.append(
            re.sub(r"(://[^:]+:)[^@]+(@)", r"\1***\2", line)
        )

    msg = (
        f"Embedded credentials detected in git config: {config_file}\n"
        "Remote URLs must not contain credentials (user:pass@)\n"
        "Offending lines:\n"
    )
    for r in redacted:
        msg += f"  {r}\n"
    msg += "Remove credentials from git remote URLs before enabling credential isolation"

    return False, msg


# ============================================================================
# Bridge Commands
# ============================================================================


def _cmd_validate_sandbox_name(name: str) -> dict[str, Any]:
    """Bridge command: Validate sandbox name."""
    ok, msg = validate_sandbox_name(name)
    return {"valid": ok, "error": msg}


def _cmd_validate_git_url(url: str) -> dict[str, Any]:
    """Bridge command: Validate git URL."""
    ok, msg = validate_git_url(url)
    return {"valid": ok, "error": msg}


def _cmd_validate_ssh_mode(mode: str) -> dict[str, Any]:
    """Bridge command: Validate SSH mode."""
    ok, msg = validate_ssh_mode(mode)
    return {"valid": ok, "error": msg}


def _cmd_validate_mount_path(path: str) -> dict[str, Any]:
    """Bridge command: Validate mount path."""
    ok, msg = validate_mount_path(path)
    return {"valid": ok, "error": msg}


def _cmd_check_docker_running() -> dict[str, Any]:
    """Bridge command: Check Docker is running."""
    ok, msg = check_docker_running()
    return {"running": ok, "error": msg}


def _cmd_validate_environment() -> dict[str, Any]:
    """Bridge command: Validate environment."""
    ok, msg = validate_environment()
    return {"valid": ok, "error": msg}


def _cmd_check_network_capacity(isolate_credentials: str = "true") -> dict[str, Any]:
    """Bridge command: Check Docker network capacity."""
    ok, msg = check_docker_network_capacity(
        isolate_credentials=isolate_credentials == "true"
    )
    return {"capacity": ok, "error": msg}


def _cmd_validate_git_remotes(git_dir: str = ".git") -> dict[str, Any]:
    """Bridge command: Validate git remotes for embedded credentials."""
    ok, msg = validate_git_remotes(git_dir)
    return {"clean": ok, "error": msg}


def _cmd_require_command(cmd: str) -> dict[str, Any]:
    """Bridge command: Check required command."""
    ok, msg = require_command(cmd)
    return {"available": ok, "error": msg}


if __name__ == "__main__":
    bridge_main({
        "validate-name": _cmd_validate_sandbox_name,
        "validate-url": _cmd_validate_git_url,
        "validate-ssh-mode": _cmd_validate_ssh_mode,
        "validate-mount": _cmd_validate_mount_path,
        "check-docker": _cmd_check_docker_running,
        "validate-env": _cmd_validate_environment,
        "check-network-capacity": _cmd_check_network_capacity,
        "validate-git-remotes": _cmd_validate_git_remotes,
        "require-command": _cmd_require_command,
    })
