"""Git operations for repository management.

Replaces lib/git.sh (76 lines). Handles:
  - Retry wrapper with exponential backoff for git commands
  - Bare repository clone and update
  - Working directory checkout with uncommitted change detection
  - Branch existence checking

Security-critical: ref validation preserves deny-by-default behavior.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from foundry_sandbox._bridge import bridge_main
from foundry_sandbox.constants import TIMEOUT_GIT_QUERY, TIMEOUT_GIT_TRANSFER
from foundry_sandbox.paths import ensure_dir
from foundry_sandbox.utils import log_info, log_step, log_warn


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


def ensure_bare_repo(repo_url: str, bare_path: str | Path) -> None:
    """Clone or update a bare repository.

    If *bare_path* does not exist, clones *repo_url* as a bare repo.
    Otherwise, fetches all refs with pruning.

    Args:
        repo_url: Remote repository URL.
        bare_path: Local path for the bare clone.
    """
    bp = Path(bare_path)

    if not bp.is_dir():
        log_step("Cloning repository...")
        bp.parent.mkdir(parents=True, exist_ok=True)
        git_with_retry(["clone", "--bare", repo_url, str(bp)])
    else:
        log_step("Fetching latest from origin...")
        git_with_retry(["-C", str(bp), "fetch", "--all", "--prune"])


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


# ============================================================================
# Bridge Commands
# ============================================================================


def _cmd_git_with_retry(*args: str) -> dict[str, Any]:
    """Bridge command: Run git with retry.

    Args are passed directly as git sub-command and arguments.
    Returns dict with returncode, stdout, stderr.
    """
    result = git_with_retry(list(args))
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _cmd_ensure_bare_repo(repo_url: str, bare_path: str) -> None:
    """Bridge command: Ensure a bare repository exists and is up to date."""
    ensure_bare_repo(repo_url, bare_path)


def _cmd_ensure_repo_checkout(repo_url: str, checkout_path: str, branch: str = "main") -> None:
    """Bridge command: Ensure a working checkout exists and is up to date."""
    ensure_repo_checkout(repo_url, checkout_path, branch)


def _cmd_branch_exists(repo_path: str, branch: str) -> bool:
    """Bridge command: Check if a branch exists."""
    return branch_exists(repo_path, branch)


# ============================================================================
# Bridge Dispatcher
# ============================================================================


if __name__ == "__main__":
    bridge_main({
        "git-with-retry": _cmd_git_with_retry,
        "ensure-bare-repo": _cmd_ensure_bare_repo,
        "ensure-repo-checkout": _cmd_ensure_repo_checkout,
        "branch-exists": _cmd_branch_exists,
    })
