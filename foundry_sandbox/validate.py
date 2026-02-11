"""Input validation for foundry-sandbox.

Replaces lib/validate.sh (252 lines). Pure validation logic for sandbox names,
URLs, mount paths, SSH modes, environment requirements, git remote credential
detection, and Docker network capacity checking.

Convention:
- Functions validating user input return (is_valid: bool, error_msg: str).
  An empty error_msg indicates success.
- Functions validating internal state raise ValueError/TypeError on failure.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from foundry_sandbox.constants import (
    TIMEOUT_DOCKER_NETWORK,
    TIMEOUT_DOCKER_QUERY,
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

    When validation succeeds, the returned error_message contains the resolved
    canonical path so callers can use it directly (avoiding TOCTOU races from
    re-resolving the path later).

    Args:
        mount_path: Host path to validate.

    Returns:
        Tuple of (is_valid, canonical_or_error). On success, second element is
        the resolved canonical path string. On failure, it is an error message.
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

    return True, str(canonical)


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
    if len(name) > 128:
        return False, "Sandbox name too long (max 128 characters)"
    if name in {".", ".."}:
        return False, "Sandbox name cannot be '.' or '..'"
    if "/" in name or "\\" in name:
        return False, "Sandbox name cannot contain path separators"
    if any(ch.isspace() for ch in name):
        return False, "Sandbox name cannot contain whitespace"
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", name):
        return False, (
            "Invalid sandbox name (allowed: letters, numbers, '.', '_', '-')"
        )
    return True, ""


def validate_existing_sandbox_name(name: str) -> tuple[bool, str]:
    """Validate sandbox names for lifecycle commands on existing sandboxes.

    This is intentionally more permissive than validate_sandbox_name() to avoid
    locking out older sandboxes that predate stricter naming rules.
    """
    if not name:
        return False, "Sandbox name required"
    if len(name) > 255:
        return False, "Sandbox name too long (max 255 characters)"
    if name in {".", ".."}:
        return False, "Sandbox name cannot be '.' or '..'"
    if "/" in name or "\\" in name:
        return False, "Sandbox name cannot contain path separators"
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        return False, "Sandbox name cannot contain control characters"
    return True, ""


# Pattern for org/repo shorthand (e.g., "owner/repo" or "owner/repo.git")
_ORG_REPO_PATTERN = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(?:\.git)?$")


# Pattern for valid SSH hostnames (alphanumeric, dots, hyphens)
_SSH_HOST_PATTERN = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")

# Sensitive filesystem prefixes that should not be cloned
_SENSITIVE_PREFIXES = ("/etc", "/proc", "/sys", "/dev", "/var/run", "/root", "/boot", "/var/lib/docker")


def validate_git_url(url: str) -> tuple[bool, str]:
    """Validate a git repository URL.

    Accepts http(s) URLs, git@ SSH URLs, org/repo shorthand, and local
    filesystem paths (absolute or relative).
    Rejects URLs with path traversal, embedded credentials, sensitive
    system paths, and malformed values.

    Args:
        url: Repository URL or local path to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not url:
        return False, "Repository URL required"

    # Reject path traversal sequences
    if ".." in url:
        return False, f"Invalid repository URL (path traversal): {url}"

    # HTTPS/HTTP URLs: use proper URL parsing
    if url.startswith(("https://", "http://")):
        parsed = urlparse(url)
        if not parsed.hostname:
            return False, f"Invalid repository URL (missing host): {url}"
        if not parsed.path or parsed.path == "/":
            return False, f"Invalid repository URL (missing path): {url}"
        if parsed.username or parsed.password:
            return False, f"Invalid repository URL (embedded credentials not allowed): {url}"
        if ";" in parsed.netloc or " " in parsed.netloc:
            return False, f"Invalid repository URL (suspicious characters in host): {url}"
        return True, ""

    # Git SSH URLs: git@host:owner/repo.git
    if url.startswith("git@"):
        rest = url[4:]
        colon_idx = rest.find(":")
        if colon_idx < 1:
            return False, f"Invalid git SSH URL (missing host): {url}"
        host = rest[:colon_idx]
        path = rest[colon_idx + 1:]
        if not path or path.startswith("/"):
            return False, f"Invalid git SSH URL (missing or absolute path): {url}"
        if not _SSH_HOST_PATTERN.match(host):
            return False, f"Invalid git SSH URL (invalid host): {url}"
        return True, ""

    # Local filesystem paths (absolute or relative)
    if url.startswith(("/", "./", "~/")) or url == ".":
        resolved = os.path.realpath(os.path.expanduser(url))
        for prefix in _SENSITIVE_PREFIXES:
            if resolved == prefix or resolved.startswith(prefix + "/"):
                return False, f"Invalid repository path (sensitive location): {url}"
        return True, ""

    # Org/repo shorthand: "owner/repo" (GitHub shorthand)
    if _ORG_REPO_PATTERN.match(url):
        return True, ""

    return False, f"Invalid repository URL: {url}"


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
            timeout=TIMEOUT_DOCKER_QUERY,
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
            timeout=TIMEOUT_DOCKER_QUERY,
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
            timeout=TIMEOUT_DOCKER_NETWORK,
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
        timeout=TIMEOUT_DOCKER_NETWORK,
    )

    # Warn if many sandbox networks exist
    if sandbox_network_count > 20:
        # Count orphaned networks (no running containers)
        orphaned_count = 0
        try:
            result = subprocess.run(
                ["docker", "network", "ls", "--format", "{{.Name}}"],
                capture_output=True, text=True, check=False,
                timeout=TIMEOUT_DOCKER_QUERY,
            )
            for net in result.stdout.splitlines():
                if not net.startswith("sandbox-"):
                    continue
                sandbox_name = net.removesuffix("_credential-isolation")
                sandbox_name = sandbox_name.removesuffix("_proxy-egress")
                check = subprocess.run(
                    ["docker", "ps", "-q", "--filter", f"name=^{sandbox_name}-"],
                    capture_output=True, text=True, check=False,
                    timeout=TIMEOUT_DOCKER_QUERY,
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
