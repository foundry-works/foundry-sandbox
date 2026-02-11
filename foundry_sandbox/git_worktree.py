"""Git worktree management for sandboxes.

Replaces lib/git_worktree.sh (177 lines). Handles:
  - Worktree path translation and lifecycle
  - Sparse-checkout cone pattern management
  - Branch cleanup for ephemeral sandboxes
  - Uncommitted change detection

Security-critical: Protected branch patterns enforced in cleanup_sandbox_branch.
"""

from __future__ import annotations

import re
import subprocess
import shutil
from pathlib import Path
from typing import Any

from foundry_sandbox.constants import TIMEOUT_GIT_QUERY, TIMEOUT_GIT_TRANSFER
from foundry_sandbox.git import git_with_retry
from foundry_sandbox.utils import log_info, log_step, log_warn


# ============================================================================
# Ref Safety
# ============================================================================


def _assert_safe_ref(name: str, label: str = "ref") -> None:
    """Reject ref names that look like git flags.

    Raises:
        ValueError: If *name* starts with ``-``.
    """
    if name and name.startswith("-"):
        raise ValueError(f"{label} must not start with '-': {name!r}")


# ============================================================================
# Core Worktree Operations
# ============================================================================


def configure_sparse_checkout(
    bare_path: str | Path,
    worktree_path: str | Path,
    working_dir: str,
) -> None:
    """Configure sparse checkout for a worktree using cone mode.

    Enables per-worktree sparse checkout config and sets cone patterns
    to include only root files, .github/, and the specified working_dir.

    Args:
        bare_path: Path to the bare repository.
        worktree_path: Path to the worktree.
        working_dir: Directory path to include in sparse checkout.

    Raises:
        RuntimeError: If gitdir cannot be read or checkout fails.
    """
    bare_p = Path(bare_path)
    wt_p = Path(worktree_path)

    # Read gitdir from the worktree's .git file
    git_file = wt_p / ".git"
    if not git_file.exists():
        raise RuntimeError(f"Worktree .git file not found: {git_file}")

    gitdir_line = git_file.read_text().strip()
    if not gitdir_line.startswith("gitdir: "):
        raise RuntimeError(f"Invalid .git file format: {git_file}")

    gitdir = gitdir_line.replace("gitdir: ", "", 1)
    gitdir_path = Path(gitdir)
    if not gitdir_path.is_absolute():
        gitdir_path = (wt_p / gitdir).resolve()

    # Enable per-worktree config at bare repo level
    subprocess.run(
        ["git", "-C", str(bare_p), "config", "extensions.worktreeConfig", "true"],
        capture_output=True,
        text=True,
        check=True,
        timeout=TIMEOUT_GIT_QUERY,
    )

    # Bump repositoryformatversion to 1 if needed
    version_result = subprocess.run(
        ["git", "-C", str(bare_p), "config", "--get", "core.repositoryformatversion"],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )
    version = int(version_result.stdout.strip() or "0")
    if version < 1:
        subprocess.run(
            ["git", "-C", str(bare_p), "config", "core.repositoryformatversion", "1"],
            capture_output=True,
            text=True,
            check=True,
            timeout=TIMEOUT_GIT_QUERY,
        )

    # Enable sparse checkout in worktree config
    worktree_config = gitdir_path / "config.worktree"
    subprocess.run(
        ["git", "config", "--file", str(worktree_config), "core.sparseCheckout", "true"],
        capture_output=True,
        text=True,
        check=True,
        timeout=TIMEOUT_GIT_QUERY,
    )
    subprocess.run(
        ["git", "config", "--file", str(worktree_config), "core.sparseCheckoutCone", "true"],
        capture_output=True,
        text=True,
        check=True,
        timeout=TIMEOUT_GIT_QUERY,
    )

    # Build sparse-checkout patterns for cone mode
    patterns = [
        "/*",          # Include root files
        "!/*/"         # Exclude all root directories
    ]
    patterns.append("/.github/")  # Always include .github

    # Add each parent directory with sibling exclusions
    path_parts = [p for p in working_dir.split("/") if p]
    path_so_far = ""
    for part in path_parts:
        path_so_far += f"/{part}"
        patterns.append(f"{path_so_far}/")
        patterns.append(f"!{path_so_far}/*/")

    # Remove the last sibling exclusion (we want contents of target dir)
    if patterns and patterns[-1].startswith("!"):
        patterns = patterns[:-1]

    # Write sparse-checkout file
    sparse_checkout_file = gitdir_path / "info" / "sparse-checkout"
    sparse_checkout_file.parent.mkdir(parents=True, exist_ok=True)
    sparse_checkout_file.write_text("\n".join(patterns) + "\n")

    log_warn(f"Sparse checkout enabled. Only files in '{working_dir}' and root configs are available.")
    log_warn("Use 'git sparse-checkout add <path>' inside the container to add more paths.")

    # Checkout using explicit git-dir and work-tree
    result = subprocess.run(
        ["git", f"--git-dir={gitdir}", f"--work-tree={wt_p}", "checkout"],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_TRANSFER,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Sparse checkout failed: {result.stderr.strip()}")


def worktree_has_changes(worktree_path: str | Path) -> bool:
    """Check if a worktree has uncommitted changes.

    Args:
        worktree_path: Path to the worktree.

    Returns:
        True if there are staged or unstaged changes, False if clean.
    """
    wt_p = Path(worktree_path)

    # Check unstaged changes
    diff_result = subprocess.run(
        ["git", "-C", str(wt_p), "diff", "--quiet"],
        capture_output=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )

    # Check staged changes
    cached_result = subprocess.run(
        ["git", "-C", str(wt_p), "diff", "--cached", "--quiet"],
        capture_output=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )

    # If either command returns non-zero, there are changes
    return diff_result.returncode != 0 or cached_result.returncode != 0


def create_worktree(
    bare_path: str | Path,
    worktree_path: str | Path,
    branch: str,
    from_branch: str | None = None,
    sparse_checkout: bool = False,
    working_dir: str | None = None,
) -> None:
    """Create or update a git worktree.

    If the worktree doesn't exist, creates it from the specified branch.
    If from_branch is provided, fetches it and creates a new branch.
    If the worktree exists, pulls latest changes (skipping if dirty).

    Args:
        bare_path: Path to the bare repository.
        worktree_path: Path where the worktree should be created.
        branch: Target branch name.
        from_branch: Base branch to create from (optional).
        sparse_checkout: Whether to enable sparse checkout.
        working_dir: Working directory for sparse checkout.

    Raises:
        RuntimeError: If git operations fail.
    """
    _assert_safe_ref(branch, "branch")
    if from_branch:
        _assert_safe_ref(from_branch, "from_branch")

    bare_p = Path(bare_path)
    wt_p = Path(worktree_path)

    # Prune stale worktree registrations
    subprocess.run(
        ["git", "-C", str(bare_p), "worktree", "prune"],
        capture_output=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )

    if not wt_p.exists():
        # Create new worktree
        if from_branch:
            # Fetch the base branch
            try:
                git_with_retry(["-C", str(bare_p), "fetch", "origin", "--", f"{from_branch}:{from_branch}"])
            except RuntimeError as e:
                log_info(f"Fetch failed (may already exist locally): {e}")

            # Check if target branch already exists
            branch_exists = subprocess.run(
                ["git", "-C", str(bare_p), "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
                capture_output=True,
                check=False,
                timeout=TIMEOUT_GIT_QUERY,
            ).returncode == 0

            if branch_exists:
                log_step(f"Using existing branch: {branch}")
                if sparse_checkout and working_dir:
                    subprocess.run(
                        ["git", "-C", str(bare_p), "worktree", "add", "--no-checkout", "--", str(wt_p), branch],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=TIMEOUT_GIT_TRANSFER,
                    )
                    configure_sparse_checkout(bare_p, wt_p, working_dir)
                else:
                    subprocess.run(
                        ["git", "-C", str(bare_p), "worktree", "add", "--", str(wt_p), branch],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=TIMEOUT_GIT_TRANSFER,
                    )
            else:
                log_step(f"Creating branch: {branch} (from {from_branch})")
                if sparse_checkout and working_dir:
                    subprocess.run(
                        ["git", "-C", str(bare_p), "worktree", "add", "--no-checkout", "-b", branch, "--", str(wt_p), from_branch],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=TIMEOUT_GIT_TRANSFER,
                    )
                    configure_sparse_checkout(bare_p, wt_p, working_dir)
                else:
                    subprocess.run(
                        ["git", "-C", str(bare_p), "worktree", "add", "-b", branch, "--", str(wt_p), from_branch],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=TIMEOUT_GIT_TRANSFER,
                    )
        else:
            # No from_branch — try to create worktree directly
            log_step(f"Creating worktree for branch: {branch}")

            if sparse_checkout and working_dir:
                # Try creating worktree without checkout
                result = subprocess.run(
                    ["git", "-C", str(bare_p), "worktree", "add", "--no-checkout", "--", str(wt_p), branch],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=TIMEOUT_GIT_TRANSFER,
                )
                if result.returncode != 0:
                    # Branch not found locally, try fetching
                    log_step("Branch not found locally, fetching...")
                    try:
                        git_with_retry(["-C", str(bare_p), "fetch", "origin", "--", f"{branch}:{branch}"])
                    except RuntimeError:
                        # Try alternative fetch format
                        git_with_retry(["-C", str(bare_p), "fetch", "origin", f"refs/heads/{branch}:refs/heads/{branch}"])

                    subprocess.run(
                        ["git", "-C", str(bare_p), "worktree", "add", "--no-checkout", "--", str(wt_p), branch],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=TIMEOUT_GIT_TRANSFER,
                    )

                configure_sparse_checkout(bare_p, wt_p, working_dir)
            else:
                # Normal checkout
                result = subprocess.run(
                    ["git", "-C", str(bare_p), "worktree", "add", "--", str(wt_p), branch],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=TIMEOUT_GIT_TRANSFER,
                )
                if result.returncode != 0:
                    # Branch not found locally, try fetching
                    log_step("Branch not found locally, fetching...")
                    try:
                        git_with_retry(["-C", str(bare_p), "fetch", "origin", "--", f"{branch}:{branch}"])
                    except RuntimeError:
                        # Try alternative fetch format
                        git_with_retry(["-C", str(bare_p), "fetch", "origin", f"refs/heads/{branch}:refs/heads/{branch}"])

                    subprocess.run(
                        ["git", "-C", str(bare_p), "worktree", "add", "--", str(wt_p), branch],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=TIMEOUT_GIT_TRANSFER,
                    )
    else:
        # Worktree exists — pull latest changes
        log_info(f"Worktree already exists at {wt_p}")
        log_info("Pulling latest changes...")

        if worktree_has_changes(wt_p):
            log_warn("Uncommitted changes detected. Skipping pull.")
        else:
            try:
                git_with_retry(["-C", str(wt_p), "pull", "--ff-only"])
            except RuntimeError as e:
                log_warn(f"Could not fast-forward: {e}. You may need to pull manually.")


def cleanup_sandbox_branch(branch: str, bare_path: str | Path) -> None:
    """Delete a sandbox branch if it's not in use and not protected.

    Skips deletion if:
      - Branch or bare_path is empty
      - Branch is protected (main, master, develop, production, release/*, hotfix/*)
      - Another worktree is using the branch

    Args:
        branch: Branch name to delete.
        bare_path: Path to the bare repository.
    """
    if not branch or not bare_path:
        return

    _assert_safe_ref(branch, "branch")

    # Skip protected branches
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

    bare_p = Path(bare_path)
    if not bare_p.is_dir():
        return

    # Check if another worktree is using this branch
    worktree_list = subprocess.run(
        ["git", "-C", str(bare_p), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )

    if worktree_list.returncode == 0:
        if f"branch refs/heads/{branch}" in worktree_list.stdout:
            log_info(f"Branch '{branch}' still in use by another worktree, skipping cleanup")
            return

    # Delete the branch
    result = subprocess.run(
        ["git", "-C", str(bare_p), "branch", "-D", "--", branch],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )
    if result.returncode == 0:
        log_info(f"Cleaned up sandbox branch: {branch}")


def remove_worktree(worktree_path: str | Path) -> None:
    """Remove a git worktree.

    Attempts to use git worktree remove --force, falls back to rm -rf.

    Args:
        worktree_path: Path to the worktree to remove.
    """
    wt_p = Path(worktree_path)
    if not wt_p.exists():
        return

    # Try to get git-dir to derive bare_path
    git_dir_result = subprocess.run(
        ["git", "-C", str(wt_p), "rev-parse", "--git-dir"],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )

    if git_dir_result.returncode == 0 and git_dir_result.stdout.strip():
        git_dir = Path(git_dir_result.stdout.strip())
        # bare_path is two levels up from git_dir (worktrees/<name>)
        bare_p = git_dir.parent.parent

        # Try git worktree remove --force
        remove_result = subprocess.run(
            ["git", "-C", str(bare_p), "worktree", "remove", str(wt_p), "--force"],
            capture_output=True,
            check=False,
            timeout=TIMEOUT_GIT_TRANSFER,
        )
        if remove_result.returncode == 0:
            return

    # Fall back to rm -rf
    shutil.rmtree(wt_p, ignore_errors=True)
