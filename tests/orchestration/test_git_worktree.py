"""Tests for git worktree lifecycle in sandbox.sh.

Verifies that sandbox creation properly manages git worktrees:
- Worktree is created at the expected path
- Worktree is on the correct branch
- Worktree is removed when the sandbox is destroyed
- Multiple sandboxes from the same repo share a bare repo
"""

import os
import subprocess
import uuid

import pytest

pytestmark = [
    pytest.mark.orchestration,
    pytest.mark.slow,
    pytest.mark.usefixtures("requires_docker"),
]

WORKTREES_DIR = os.path.expanduser("~/.sandboxes/worktrees")
REPOS_DIR = os.path.expanduser("~/.sandboxes/repos")


def test_worktree_created(cli, sandbox_name, local_repo):
    """Sandbox creation produces a worktree at ~/.sandboxes/worktrees/<name>."""
    cli("new", str(local_repo), "--skip-key-check")

    worktree_path = os.path.join(WORKTREES_DIR, sandbox_name)
    assert os.path.isdir(worktree_path), (
        f"Worktree directory does not exist: {worktree_path}"
    )

    # A valid git checkout has a .git file (worktree) or .git directory
    git_path = os.path.join(worktree_path, ".git")
    assert os.path.exists(git_path), (
        f"Worktree has no .git file or directory: {git_path}"
    )


def test_worktree_on_correct_branch(cli, sandbox_name, local_repo):
    """Sandbox created with an explicit branch checks out that branch."""
    cli("new", str(local_repo), "test-branch", "main", "--skip-key-check")

    worktree_path = os.path.join(WORKTREES_DIR, sandbox_name)
    result = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=worktree_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"git branch --show-current failed: {result.stderr}"
    assert result.stdout.strip() == "test-branch", (
        f"Expected branch 'test-branch', got '{result.stdout.strip()}'"
    )


def test_worktree_removed_on_destroy(cli, sandbox_name, local_repo):
    """Destroying a sandbox removes its worktree directory."""
    cli("new", str(local_repo), "--skip-key-check")

    worktree_path = os.path.join(WORKTREES_DIR, sandbox_name)
    assert os.path.isdir(worktree_path), "Worktree should exist after creation"

    cli("destroy", sandbox_name, "--force")

    assert not os.path.exists(worktree_path), (
        f"Worktree should not exist after destroy: {worktree_path}"
    )


def test_bare_repo_shared(cli, local_repo):
    """Two sandboxes from the same repo share a single bare repo in ~/.sandboxes/repos/."""
    name_a = f"test-{uuid.uuid4().hex[:8]}"
    name_b = f"test-{uuid.uuid4().hex[:8]}"

    try:
        cli("new", str(local_repo), f"{name_a}-branch", "main", "--skip-key-check")
        cli("new", str(local_repo), f"{name_b}-branch", "main", "--skip-key-check")

        # Collect bare repo directories that contain objects for this repo.
        # Local repos are stored under ~/.sandboxes/repos/local/...
        bare_repos = set()
        for root, dirs, _files in os.walk(REPOS_DIR):
            if "objects" in dirs and "refs" in dirs:
                bare_repos.add(root)

        # Both sandboxes should resolve to the same bare repo, so there
        # should be exactly one bare repo matching the local test repo.
        assert len(bare_repos) >= 1, "Expected at least one bare repo"

        # Verify both worktrees reference the same bare repo by reading their
        # .git files and extracting the gitdir path.
        worktree_a = os.path.join(WORKTREES_DIR, f"{name_a}-branch")
        worktree_b = os.path.join(WORKTREES_DIR, f"{name_b}-branch")

        def bare_repo_for_worktree(worktree_path):
            git_file = os.path.join(worktree_path, ".git")
            if os.path.isfile(git_file):
                with open(git_file) as f:
                    content = f.read().strip()
                # Format: "gitdir: /path/to/bare/worktrees/<name>"
                gitdir = content.replace("gitdir: ", "")
                if not os.path.isabs(gitdir):
                    gitdir = os.path.normpath(
                        os.path.join(worktree_path, gitdir)
                    )
                # The gitdir points into bare_repo/worktrees/<name>;
                # walk up two levels to get the bare repo root.
                return os.path.dirname(os.path.dirname(gitdir))
            return None

        bare_a = bare_repo_for_worktree(worktree_a)
        bare_b = bare_repo_for_worktree(worktree_b)

        assert bare_a is not None, "Could not resolve bare repo for sandbox A"
        assert bare_b is not None, "Could not resolve bare repo for sandbox B"
        assert bare_a == bare_b, (
            f"Sandboxes should share the same bare repo but got: {bare_a} vs {bare_b}"
        )
    finally:
        cli("destroy", name_a, "--force")
        cli("destroy", name_b, "--force")
