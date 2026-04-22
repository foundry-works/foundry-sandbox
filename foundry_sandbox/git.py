"""Git operations for repository management.

Replaces lib/git.sh (76 lines). Handles:
  - Retry wrapper with exponential backoff for git commands
  - Bare repository clone and update
  - Working directory checkout with uncommitted change detection
  - Branch existence checking

Security-critical: ref validation preserves deny-by-default behavior.
"""

from __future__ import annotations

import re
import subprocess
import time
import warnings
from pathlib import Path
from typing import Callable

from foundry_sandbox.constants import TIMEOUT_GIT_QUERY, TIMEOUT_GIT_TRANSFER
from foundry_sandbox.paths import ensure_dir
from foundry_sandbox.utils import log_info, log_step, log_warn

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


def _ensure_fetch_refspec(bare_path: Path) -> None:
    """Add a standard fetch refspec to a bare repo if missing.

    .. deprecated::
        Removed in next release. Bare repo functions are no longer used.

    ``git clone --bare`` does not configure ``remote.origin.fetch``, so
    subsequent ``git fetch origin`` never updates ``refs/remotes/origin/*``.
    This causes worktrees to see a stale ``origin/main`` tracking ref.

    Silently returns if the path is not a valid git repository.
    """
    warnings.warn(
        "_ensure_fetch_refspec() is deprecated and will be removed in the next release; "
        "bare repo functions are no longer used.",
        DeprecationWarning,
        stacklevel=2,
    )
    result = subprocess.run(
        ["git", "-C", str(bare_path), "config", "--get", "remote.origin.fetch"],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )
    if result.returncode not in (0, 1):
        # returncode 1 = key not found (expected for bare clones);
        # anything else means the repo is broken or not a git dir.
        return

    expected = "+refs/heads/*:refs/remotes/origin/*"
    if expected not in (result.stdout or ""):
        subprocess.run(
            ["git", "-C", str(bare_path), "config", "remote.origin.fetch", expected],
            capture_output=True,
            check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )


def ensure_bare_repo(repo_url: str, bare_path: str | Path) -> None:
    """Clone or update a bare repository.

    .. deprecated::
        Removed in next release. Bare repo functions are no longer used.

    If *bare_path* does not exist, clones *repo_url* as a bare repo.
    After ensuring the fetch refspec is configured, fetches all remote
    refs so ``refs/remotes/origin/*`` stays current for worktrees.

    Individual branch refs (``refs/heads/*``) may still be updated by
    :func:`fetch_bare_branch` when a worktree is created, since ``git
    fetch`` refuses to update a ref that is checked out in a worktree.

    Args:
        repo_url: Remote repository URL.
        bare_path: Local path for the bare clone.
    """
    bp = Path(bare_path)

    warnings.warn(
        "ensure_bare_repo() is deprecated and will be removed in the next release; "
        "bare repo functions are no longer used.",
        DeprecationWarning,
        stacklevel=2,
    )

    fresh_clone = not bp.is_dir()
    if fresh_clone:
        log_step("Cloning repository...")
        bp.parent.mkdir(parents=True, exist_ok=True)
        git_with_retry(["clone", "--bare", repo_url, str(bp)])

    # Ensure fetch refspec is configured.  ``git clone --bare`` omits it,
    # so ``git fetch`` never updates ``refs/remotes/origin/*``.  Without
    # this, worktrees see a stale ``origin/main`` and think they are ahead.
    if bp.is_dir():
        _ensure_fetch_refspec(bp)

    if not fresh_clone:
        log_step("Fetching latest from origin...")
        remove_stale_git_locks(bp)
        git_with_retry(["-C", str(bp), "fetch", "origin", "--prune"])


_VALID_BRANCH_RE = re.compile(
    r"^[a-zA-Z0-9]"          # Must start with alnum
    r"(?!.*\.\.)"             # No ".." anywhere (path traversal)
    r"(?!.*//)"               # No consecutive slashes
    r"(?!.*\.lock$)"          # Must not end with .lock
    r"(?!.*\.$)"              # Must not end with "."
    r"(?!.*/\.)"              # No component starting with "."
    r"[a-zA-Z0-9._/-]*$"     # Body: alnum, dot, underscore, slash, hyphen
)


def fetch_bare_branch(bare_path: str | Path, branch: str) -> str:
    """Fetch a single branch into a bare repo, updating refs/heads/<branch>.

    .. deprecated::
        Removed in next release. Bare repo functions are no longer used.

    ``git clone --bare`` omits the fetch refspec and ``git fetch`` refuses
    to update a ref that is checked out in any worktree.  This function
    works around both issues by fetching to ``FETCH_HEAD`` and then using
    ``update-ref`` to move the local branch pointer.

    Note: the fetch → rev-parse → update-ref sequence is not atomic. A
    concurrent fetch could change FETCH_HEAD between steps. In practice
    bare repos are per-user so contention is unlikely.

    Args:
        bare_path: Path to the bare repository.
        branch: Remote branch name to fetch and update.

    Returns:
        The commit SHA that refs/heads/<branch> was set to.

    Raises:
        ValueError: If *branch* contains invalid ref characters or path traversal.
    """
    if not _VALID_BRANCH_RE.match(branch):
        raise ValueError(f"Invalid branch name: {branch!r}")

    warnings.warn(
        "fetch_bare_branch() is deprecated and will be removed in the next release; "
        "bare repo functions are no longer used.",
        DeprecationWarning,
        stacklevel=2,
    )
    bp = str(bare_path)

    # Fetch the branch — this always writes FETCH_HEAD regardless of
    # whether refs/heads/<branch> is "checked out" somewhere.
    git_with_retry(["-C", bp, "fetch", "origin", branch])

    # Read the fetched commit SHA.
    result = subprocess.run(
        ["git", "-C", bp, "rev-parse", "FETCH_HEAD"],
        capture_output=True,
        text=True,
        check=True,
        timeout=TIMEOUT_GIT_QUERY,
    )
    sha = result.stdout.strip()

    # Force-update the local branch ref (bypasses checked-out guard).
    subprocess.run(
        ["git", "-C", bp, "update-ref", f"refs/heads/{branch}", sha],
        capture_output=True,
        check=True,
        timeout=TIMEOUT_GIT_QUERY,
    )

    # Also update the remote tracking ref so worktrees see an accurate
    # ``origin/<branch>`` and don't report phantom ahead/behind counts.
    subprocess.run(
        ["git", "-C", bp, "update-ref", f"refs/remotes/origin/{branch}", sha],
        capture_output=True,
        check=True,
        timeout=TIMEOUT_GIT_QUERY,
    )

    return sha


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


def branch_exists(repo_path: str | Path, branch: str) -> bool:
    """Check if a branch exists in a repository.

    Args:
        repo_path: Path to the repository (bare or working).
        branch: Branch name to check.

    Returns:
        True if the branch exists, False otherwise.
    """
    result = subprocess.run(
        ["git", "-C", str(repo_path), "show-ref", "--verify", "--quiet",
         f"refs/heads/{branch}"],
        capture_output=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )
    return result.returncode == 0
