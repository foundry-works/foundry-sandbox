"""Input validation for foundry-sandbox.

Pure validation logic for sandbox names and git URLs.

Convention:
- Functions validating user input return (is_valid: bool, error_msg: str).
  An empty error_msg indicates success.
- Functions validating internal state raise ValueError/TypeError on failure.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse

from foundry_sandbox.constants import SANDBOX_NAME_MAX_LENGTH


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
    if len(name) > SANDBOX_NAME_MAX_LENGTH:
        return False, (
            f"Sandbox name too long (max {SANDBOX_NAME_MAX_LENGTH} characters)"
        )
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
