"""Repository resolution helpers for the ``new`` command.

Extracted from new.py to reduce module size. Contains functions for
resolving repo input, listing local branches, and generating branch names.
"""

from __future__ import annotations

import os
import subprocess
from datetime import datetime

from foundry_sandbox.constants import TIMEOUT_GIT_QUERY, TIMEOUT_LOCAL_CMD
from foundry_sandbox.utils import log_debug, sanitize_ref_component


def _resolve_repo_input(repo_input: str) -> tuple[str, str, str, str]:
    """Resolve repo input to URL, root path, display name, and current branch.

    Args:
        repo_input: User input (URL, '.', local path, or owner/repo).

    Returns:
        Tuple of (repo_url, repo_root, repo_display, current_branch).
        repo_root is empty for remote URLs.
    """
    # Local path inputs
    if repo_input in (".", "/", "./", "../", "~/") or repo_input.startswith(("/", "./", "../", "~/")):
        expanded = os.path.expanduser(repo_input)
        result = subprocess.run(
            ["git", "-C", expanded, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )
        if result.returncode != 0:
            return ("", "", "", "")

        repo_root = result.stdout.strip()
        origin_result = subprocess.run(
            ["git", "-C", repo_root, "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )

        if origin_result.returncode == 0 and origin_result.stdout.strip():
            repo_url = origin_result.stdout.strip()
            repo_display = repo_url
        else:
            repo_url = repo_root
            repo_display = repo_root

        branch_result = subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )
        current_branch = branch_result.stdout.strip() if branch_result.returncode == 0 else ""

        return (repo_url, repo_root, repo_display, current_branch)

    # URL or shorthand
    if repo_input.startswith(("http://", "https://", "git@")) or "://" in repo_input:
        repo_url = repo_input
    else:
        repo_url = f"https://github.com/{repo_input}"

    return (repo_url, "", repo_url, "")


def _get_local_branches(repo_root: str) -> list[str]:
    """Get list of local branches in a repo."""
    result = subprocess.run(
        ["git", "-C", repo_root, "for-each-ref", "--format=%(refname:short)", "refs/heads"],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.strip().split("\n") if line]


def _generate_branch_name(repo_url: str, from_branch: str) -> str:
    """Generate a branch name for a new sandbox."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    repo_name = os.path.basename(repo_url.removesuffix(".git"))

    user_segment = os.environ.get("USER", "")
    if not user_segment:
        try:
            user_segment = subprocess.run(
                ["id", "-un"],
                capture_output=True,
                text=True,
                check=False,
                timeout=TIMEOUT_LOCAL_CMD,
            ).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            log_debug("Failed to get username from id command")

    if not user_segment:
        user_segment = "user"

    user_segment = sanitize_ref_component(user_segment)
    safe_repo_name = sanitize_ref_component(repo_name)

    if not safe_repo_name:
        safe_repo_name = "repo"

    branch = f"{user_segment}/{safe_repo_name}-{timestamp}"

    # Validate branch name
    check_result = subprocess.run(
        ["git", "check-ref-format", "--branch", branch],
        capture_output=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )

    if check_result.returncode != 0:
        fallback_branch = f"{safe_repo_name}-{timestamp}"
        check_fallback = subprocess.run(
            ["git", "check-ref-format", "--branch", fallback_branch],
            capture_output=True,
            check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )
        if check_fallback.returncode == 0:
            branch = fallback_branch
        else:
            branch = f"sandbox-{timestamp}"

    return branch
