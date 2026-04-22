"""Input validation for foundry-sandbox.

Pure validation logic for sandbox names, URLs, SSH modes, environment
requirements, and git remote credential detection.

Convention:
- Functions validating user input return (is_valid: bool, error_msg: str).
  An empty error_msg indicates success.
- Functions validating internal state raise ValueError/TypeError on failure.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

from foundry_sandbox.constants import (
    get_repos_dir,
    get_claude_configs_dir,
)
from foundry_sandbox.paths import ensure_dir


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
        expanded = os.path.expanduser(url)
        resolved = os.path.realpath(expanded)
        # Check both original and resolved paths — on macOS /etc -> /private/etc
        for check_path in (expanded, resolved):
            for prefix in _SENSITIVE_PREFIXES:
                if check_path == prefix or check_path.startswith(prefix + "/"):
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


def validate_environment() -> tuple[bool, str]:
    """Validate the required environment (git, directories).

    Ensures required commands are available and creates necessary directories.

    Returns:
        Tuple of (is_valid, error_message).
    """
    ok, msg = require_command("git")
    if not ok:
        return False, msg

    ensure_dir(get_repos_dir())
    ensure_dir(get_claude_configs_dir())
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
