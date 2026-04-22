"""Git operations for repository management.

Handles:
  - Retry wrapper with exponential backoff for git commands
  - Stale lockfile cleanup
  - Working directory checkout with uncommitted change detection
  - Sandbox branch cleanup for new-layout sandboxes

Security-critical: ref validation and protected-branch guards preserve
deny-by-default behavior.
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from typing import Callable

from foundry_sandbox.constants import TIMEOUT_GIT_QUERY, TIMEOUT_GIT_TRANSFER
from foundry_sandbox.paths import ensure_dir
from foundry_sandbox.utils import log_info, log_warn

# Git lockfile names that can become stale in a bare repo.
_GIT_LOCK_NAMES = ("config.lock", "HEAD.lock")

# Lockfiles older than this (seconds) are considered stale.
_STALE_LOCK_AGE = 120


# ============================================================================
# Core Git Operations
# ============================================================================


def git_with_retry(
    args: list[str],
    *,
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    capture_output: bool = True,
    timeout: int = 120,
    _sleep: Callable[[float], None] = time.sleep,
) -> subprocess.CompletedProcess[str]:
    """Run a git command with exponential backoff retry.

    Mirrors shell ``git_with_retry()`` from lib/git.sh. Retries up to
    *max_attempts* times with doubling delay between attempts.

    Args:
        args: Git sub-command and arguments (e.g. ``["clone", "--bare", url, path]``).
        max_attempts: Maximum number of attempts (default 3).
        initial_delay: Seconds to wait before first retry (doubles each retry).
        capture_output: Whether to capture stdout/stderr.
        timeout: Per-attempt timeout in seconds.
        _sleep: Injectable sleep function (for testing).

    Returns:
        The completed process from the successful attempt.

    Raises:
        RuntimeError: If all attempts fail, with the last stderr output.
    """
    delay = initial_delay
    last_result: subprocess.CompletedProcess[str] | None = None
    last_error: str = "unknown error"

    for attempt in range(1, max_attempts + 1):
        try:
            result = subprocess.run(
                ["git", *args],
                capture_output=capture_output,
                text=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            last_error = f"timed out after {timeout}s"
            if attempt < max_attempts:
                log_warn(
                    f"Git command timed out (attempt {attempt}/{max_attempts}). "
                    f"Retrying in {delay:.0f}s..."
                )
                _sleep(delay)
                delay *= 2
            continue

        if result.returncode == 0:
            return result

        last_result = result

        if attempt < max_attempts:
            log_warn(
                f"Git command failed (attempt {attempt}/{max_attempts}). "
                f"Retrying in {delay:.0f}s..."
            )
            _sleep(delay)
            delay *= 2

    # All attempts exhausted
    if last_result is not None:
        last_error = last_result.stderr.strip() if last_result.stderr else last_error
    msg = f"Git command failed after {max_attempts} attempts: git {' '.join(args)}"
    if last_error:
        msg += f"\n{last_error}"
    raise RuntimeError(msg)


def remove_stale_git_locks(repo_path: str | Path) -> None:
    """Remove stale git lockfiles from a repository directory.

    Git uses ``<file>.lock`` with ``O_CREAT|O_EXCL`` for atomic config writes.
    If a process is interrupted mid-write (e.g. a sandbox container is killed),
    the lockfile persists and blocks all subsequent git operations against the
    repo — including other sandboxes sharing the same bare repo.

    This function removes lockfiles older than ``_STALE_LOCK_AGE`` seconds.
    """
    rp = Path(repo_path)
    if not rp.is_dir():
        return

    now = time.time()
    for name in _GIT_LOCK_NAMES:
        lock = rp / name
        try:
            age = now - lock.stat().st_mtime
        except FileNotFoundError:
            continue
        if age >= _STALE_LOCK_AGE:
            try:
                lock.unlink()
                log_warn(f"Removed stale git lockfile: {lock} (age {age:.0f}s)")
            except OSError:
                pass


def ensure_repo_checkout(
    repo_url: str,
    checkout_path: str | Path,
    branch: str = "main",
) -> None:
    """Clone or update a working directory checkout.

    Behavior:
      - If *checkout_path* does not exist, clones the repo on *branch*.
      - If it exists but is not a git repo, raises ValueError.
      - If there are uncommitted changes, skips pull with a warning.
      - Otherwise, fetches, checks out *branch*, and fast-forward pulls.

    Args:
        repo_url: Remote repository URL.
        checkout_path: Local path for the working checkout.
        branch: Branch to check out (default ``"main"``).

    Raises:
        ValueError: If required arguments are empty or path exists but is not a repo.
        RuntimeError: If git operations fail.
    """
    if not repo_url or not checkout_path:
        raise ValueError("repo_url and checkout_path are required")

    if branch.startswith("-"):
        raise ValueError(f"branch must not start with '-': {branch!r}")

    cp = Path(checkout_path)
    ensure_dir(cp.parent)

    git_dir = cp / ".git"

    if not git_dir.is_dir():
        # Path exists but is not a git repo
        if cp.exists():
            raise ValueError(f"Path exists but is not a git repo: {cp}")

        # Fresh clone
        log_info(f"Cloning {repo_url} to {cp}...")
        git_with_retry(["clone", "--branch", branch, repo_url, str(cp)])
        return

    # Existing repo — check for uncommitted changes
    diff_staged = subprocess.run(
        ["git", "-C", str(cp), "diff", "--quiet"],
        capture_output=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )
    diff_cached = subprocess.run(
        ["git", "-C", str(cp), "diff", "--cached", "--quiet"],
        capture_output=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )

    if diff_staged.returncode != 0 or diff_cached.returncode != 0:
        log_warn(f"Uncommitted changes in {cp}; skipping pull.")
        return

    # Clean working tree — update
    log_info(f"Updating {repo_url} in {cp}...")
    git_with_retry(["-C", str(cp), "fetch", "origin", "--prune"])

    # Try checking out the branch
    checkout_result = subprocess.run(
        ["git", "-C", str(cp), "checkout", branch],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_TRANSFER,
    )
    if checkout_result.returncode != 0:
        # Branch doesn't exist locally — create from origin
        create_result = subprocess.run(
            ["git", "-C", str(cp), "checkout", "-b", branch, f"origin/{branch}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_GIT_TRANSFER,
        )
        if create_result.returncode != 0:
            raise RuntimeError(
                f"Failed to checkout branch {branch}: {create_result.stderr.strip()}"
            )

    # Fast-forward pull
    pull_result = subprocess.run(
        ["git", "-C", str(cp), "pull", "--ff-only", "origin", branch],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_TRANSFER,
    )
    if pull_result.returncode != 0:
        log_warn(f"Could not fast-forward {cp}")


def _assert_safe_ref(name: str, label: str = "ref") -> None:
    """Reject ref names that look like git flags.

    Raises:
        ValueError: If *name* starts with ``-``.
    """
    if name and name.startswith("-"):
        raise ValueError(f"{label} must not start with '-': {name!r}")


def cleanup_sandbox_branch_repo(branch: str, repo_root: str | Path) -> None:
    """Delete a sandbox branch from a regular repo checkout.

    Skips deletion if:
      - Branch or repo_root is empty
      - Branch is protected (main, master, develop, production, release/*, hotfix/*)
      - Another worktree is using the branch

    Args:
        branch: Branch name to delete.
        repo_root: Path to the repository root (non-bare checkout).
    """
    if not branch or not repo_root:
        return

    _assert_safe_ref(branch, "branch")

    protected_patterns = [
        r"^main$",
        r"^master$",
        r"^develop$",
        r"^production$",
        r"^release/",
        r"^hotfix/",
    ]
    for pattern in protected_patterns:
        if re.match(pattern, branch):
            return

    repo_p = Path(repo_root)
    if not repo_p.is_dir():
        return

    # Check if another worktree is using this branch
    worktree_list = subprocess.run(
        ["git", "-C", str(repo_p), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )

    if worktree_list.returncode == 0:
        if f"branch refs/heads/{branch}" in worktree_list.stdout:
            log_info(f"Branch '{branch}' still in use by another worktree, skipping cleanup")
            return

    result = subprocess.run(
        ["git", "-C", str(repo_p), "branch", "-D", "--", branch],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )
    if result.returncode == 0:
        log_info(f"Cleaned up sandbox branch: {branch}")
