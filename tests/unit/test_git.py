"""Unit tests for foundry_sandbox/git.py and foundry_sandbox/git_worktree.py.

Tests cover:
- foundry_sandbox.git: retry logic, bare repo management, checkout management,
  branch existence checking
- foundry_sandbox.git_worktree: sparse checkout configuration, change detection,
  worktree creation, branch cleanup, worktree removal
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, Mock, call, patch

import pytest

from foundry_sandbox import git, git_worktree


# ============================================================================
# git.py Tests
# ============================================================================


class TestGitWithRetry:
    """Tests for git_with_retry()."""

    @patch("foundry_sandbox.git.subprocess.run")
    def test_success_on_first_attempt(self, mock_run):
        """Successful git command should return immediately."""
        mock_run.return_value = Mock(returncode=0, stdout="ok", stderr="")

        result = git.git_with_retry(["status"])

        assert result.returncode == 0
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == ["git", "status"]

    @patch("foundry_sandbox.git.subprocess.run")
    def test_retry_then_succeed(self, mock_run):
        """Command that fails then succeeds should retry."""
        mock_run.side_effect = [
            Mock(returncode=1, stdout="", stderr="error"),
            Mock(returncode=0, stdout="ok", stderr=""),
        ]
        sleep_calls = []

        result = git.git_with_retry(
            ["fetch"], max_attempts=3, _sleep=lambda d: sleep_calls.append(d)
        )

        assert result.returncode == 0
        assert mock_run.call_count == 2
        assert len(sleep_calls) == 1
        assert sleep_calls[0] == 1.0  # Initial delay

    @patch("foundry_sandbox.git.subprocess.run")
    def test_all_retries_exhausted_raises(self, mock_run):
        """Exhausting all retries should raise RuntimeError."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="fatal: bad ref")

        with pytest.raises(RuntimeError, match="failed after 3 attempts"):
            git.git_with_retry(
                ["push"], max_attempts=3, _sleep=lambda d: None
            )

        assert mock_run.call_count == 3

    @patch("foundry_sandbox.git.subprocess.run")
    def test_error_message_includes_stderr(self, mock_run):
        """RuntimeError message should include stderr from last attempt."""
        mock_run.return_value = Mock(
            returncode=128, stdout="", stderr="fatal: not a git repo"
        )

        with pytest.raises(RuntimeError, match="not a git repo"):
            git.git_with_retry(
                ["log"], max_attempts=2, _sleep=lambda d: None
            )

    @patch("foundry_sandbox.git.subprocess.run")
    def test_exponential_backoff(self, mock_run):
        """Sleep delays should double between retries."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="err")
        sleep_calls = []

        with pytest.raises(RuntimeError):
            git.git_with_retry(
                ["clone", "url"],
                max_attempts=4,
                initial_delay=1.0,
                _sleep=lambda d: sleep_calls.append(d),
            )

        # 3 sleeps between 4 attempts: 1.0, 2.0, 4.0
        assert sleep_calls == [1.0, 2.0, 4.0]


class TestEnsureBareRepo:
    """Tests for ensure_bare_repo()."""

    @patch("foundry_sandbox.git.git_with_retry")
    def test_new_clone(self, mock_retry, tmp_path):
        """Non-existent bare_path should trigger a clone."""
        bare_path = tmp_path / "repo.git"

        git.ensure_bare_repo("https://github.com/user/repo.git", bare_path)

        mock_retry.assert_called_once()
        args = mock_retry.call_args[0][0]
        assert "clone" in args
        assert "--bare" in args
        assert "https://github.com/user/repo.git" in args

    @patch("foundry_sandbox.git.git_with_retry")
    def test_existing_repo_fetches(self, mock_retry, tmp_path):
        """Existing bare_path should trigger a fetch."""
        bare_path = tmp_path / "repo.git"
        bare_path.mkdir()

        git.ensure_bare_repo("https://github.com/user/repo.git", bare_path)

        mock_retry.assert_called_once()
        args = mock_retry.call_args[0][0]
        assert "fetch" in args
        assert "--all" in args
        assert "--prune" in args


class TestEnsureRepoCheckout:
    """Tests for ensure_repo_checkout()."""

    def test_empty_args_raises(self):
        """Empty repo_url or checkout_path should raise ValueError."""
        with pytest.raises(ValueError, match="required"):
            git.ensure_repo_checkout("", "/some/path")

        with pytest.raises(ValueError, match="required"):
            git.ensure_repo_checkout("https://example.com/repo.git", "")

    @patch("foundry_sandbox.git.git_with_retry")
    @patch("foundry_sandbox.git.ensure_dir")
    def test_fresh_clone(self, mock_ensure_dir, mock_retry, tmp_path):
        """Non-existent checkout_path should trigger a clone."""
        checkout = tmp_path / "checkout"

        git.ensure_repo_checkout("https://example.com/repo.git", checkout)

        mock_retry.assert_called_once()
        args = mock_retry.call_args[0][0]
        assert "clone" in args
        assert "--branch" in args
        assert "main" in args

    @patch("foundry_sandbox.git.git_with_retry")
    @patch("foundry_sandbox.git.ensure_dir")
    def test_existing_non_repo_raises(self, mock_ensure_dir, mock_retry, tmp_path):
        """Existing path that isn't a git repo should raise ValueError."""
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        # .git directory does NOT exist

        with pytest.raises(ValueError, match="not a git repo"):
            git.ensure_repo_checkout("https://example.com/repo.git", checkout)

    @patch("foundry_sandbox.git.subprocess.run")
    @patch("foundry_sandbox.git.git_with_retry")
    @patch("foundry_sandbox.git.ensure_dir")
    def test_dirty_tree_skips_pull(self, mock_ensure_dir, mock_retry, mock_run, tmp_path):
        """Existing repo with uncommitted changes should skip pull."""
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        (checkout / ".git").mkdir()

        # diff --quiet returns non-zero (dirty)
        mock_run.return_value = Mock(returncode=1)

        git.ensure_repo_checkout("https://example.com/repo.git", checkout)

        # git_with_retry should NOT be called (no fetch/pull)
        mock_retry.assert_not_called()

    @patch("foundry_sandbox.git.subprocess.run")
    @patch("foundry_sandbox.git.git_with_retry")
    @patch("foundry_sandbox.git.ensure_dir")
    def test_clean_tree_fetches_and_pulls(self, mock_ensure_dir, mock_retry, mock_run, tmp_path):
        """Existing repo with clean tree should fetch and pull."""
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        (checkout / ".git").mkdir()

        # diff --quiet returns 0 (clean) for both calls, then checkout succeeds
        mock_run.side_effect = [
            Mock(returncode=0),  # diff --quiet
            Mock(returncode=0),  # diff --cached --quiet
            Mock(returncode=0, stdout="", stderr=""),  # checkout
            Mock(returncode=0, stdout="", stderr=""),  # pull
        ]

        git.ensure_repo_checkout("https://example.com/repo.git", checkout, "main")

        # Should have called git_with_retry for fetch and possibly pull
        assert mock_retry.call_count >= 1


class TestBranchExists:
    """Tests for branch_exists()."""

    @patch("foundry_sandbox.git.subprocess.run")
    def test_existing_branch(self, mock_run):
        """Existing branch should return True."""
        mock_run.return_value = Mock(returncode=0)

        assert git.branch_exists("/path/to/repo", "main") is True

        args = mock_run.call_args[0][0]
        assert "show-ref" in args
        assert "--verify" in args
        assert "refs/heads/main" in args

    @patch("foundry_sandbox.git.subprocess.run")
    def test_nonexistent_branch(self, mock_run):
        """Non-existent branch should return False."""
        mock_run.return_value = Mock(returncode=1)

        assert git.branch_exists("/path/to/repo", "nonexistent") is False


# ============================================================================
# git_worktree.py Tests
# ============================================================================


class TestConfigureSparseCheckout:
    """Tests for configure_sparse_checkout()."""

    def test_missing_git_file_raises(self, tmp_path):
        """Missing .git file in worktree should raise RuntimeError."""
        bare = tmp_path / "bare.git"
        bare.mkdir()
        wt = tmp_path / "worktree"
        wt.mkdir()

        with pytest.raises(RuntimeError, match="not found"):
            git_worktree.configure_sparse_checkout(bare, wt, "src")

    def test_invalid_git_file_format_raises(self, tmp_path):
        """Invalid .git file format should raise RuntimeError."""
        bare = tmp_path / "bare.git"
        bare.mkdir()
        wt = tmp_path / "worktree"
        wt.mkdir()
        (wt / ".git").write_text("not a gitdir line")

        with pytest.raises(RuntimeError, match="Invalid .git file format"):
            git_worktree.configure_sparse_checkout(bare, wt, "src")

    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_sparse_checkout_patterns(self, mock_run, tmp_path):
        """Sparse-checkout file should contain correct cone patterns."""
        bare = tmp_path / "bare.git"
        bare.mkdir()
        wt = tmp_path / "worktree"
        wt.mkdir()

        # Create gitdir structure
        gitdir = bare / "worktrees" / "wt"
        gitdir.mkdir(parents=True)
        (wt / ".git").write_text(f"gitdir: {gitdir}")

        # Mock all subprocess calls to succeed
        mock_run.return_value = Mock(returncode=0, stdout="0", stderr="")

        git_worktree.configure_sparse_checkout(bare, wt, "src/app")

        # Verify sparse-checkout file was written
        sparse_file = gitdir / "info" / "sparse-checkout"
        assert sparse_file.exists()

        content = sparse_file.read_text()
        lines = content.strip().split("\n")

        # Should include root files pattern
        assert "/*" in lines
        # Should include .github
        assert "/.github/" in lines
        # Should include src/ and src/app/ path segments
        assert "/src/" in lines
        assert "/src/app/" in lines
        # Should exclude src siblings but NOT app siblings (last exclusion removed)
        assert "!/src/*/" in lines
        # The last exclusion (!/src/app/*/) should be removed
        assert "!/src/app/*/" not in lines


class TestWorktreeHasChanges:
    """Tests for worktree_has_changes()."""

    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_clean_worktree(self, mock_run):
        """Clean worktree should return False."""
        mock_run.return_value = Mock(returncode=0)

        assert git_worktree.worktree_has_changes("/path/to/wt") is False

    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_unstaged_changes(self, mock_run):
        """Unstaged changes should return True."""
        mock_run.side_effect = [
            Mock(returncode=1),  # diff --quiet (has changes)
            Mock(returncode=0),  # diff --cached --quiet (no staged)
        ]

        assert git_worktree.worktree_has_changes("/path/to/wt") is True

    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_staged_changes(self, mock_run):
        """Staged changes should return True."""
        mock_run.side_effect = [
            Mock(returncode=0),  # diff --quiet (no unstaged)
            Mock(returncode=1),  # diff --cached --quiet (has staged)
        ]

        assert git_worktree.worktree_has_changes("/path/to/wt") is True


class TestCreateWorktree:
    """Tests for create_worktree()."""

    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_new_worktree_no_from_branch(self, mock_run, tmp_path):
        """New worktree without from_branch should use worktree add."""
        bare = tmp_path / "bare.git"
        bare.mkdir()
        wt = tmp_path / "worktree"

        # prune succeeds, worktree add succeeds
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        git_worktree.create_worktree(bare, wt, "feature-branch")

        # Should have called worktree prune and worktree add
        calls = mock_run.call_args_list
        assert any("prune" in str(c) for c in calls)
        assert any("worktree" in str(c) and "add" in str(c) for c in calls)

    @patch("foundry_sandbox.git_worktree.configure_sparse_checkout")
    @patch("foundry_sandbox.git_worktree.git_with_retry")
    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_new_worktree_with_from_branch_and_sparse(self, mock_run, mock_retry, mock_sparse, tmp_path):
        """New worktree with from_branch and sparse should use --no-checkout."""
        bare = tmp_path / "bare.git"
        bare.mkdir()
        wt = tmp_path / "worktree"

        # prune, show-ref (not found), worktree add all succeed
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # prune
            Mock(returncode=1, stdout="", stderr=""),  # show-ref (branch not found)
            Mock(returncode=0, stdout="", stderr=""),  # worktree add --no-checkout
        ]

        git_worktree.create_worktree(
            bare, wt, "sandbox-branch", from_branch="main",
            sparse_checkout=True, working_dir="src"
        )

        # Should call configure_sparse_checkout
        mock_sparse.assert_called_once_with(bare, wt, "src")

        # worktree add should use --no-checkout
        add_call = [c for c in mock_run.call_args_list if "add" in str(c)]
        assert len(add_call) >= 1
        assert "--no-checkout" in str(add_call[-1])

    @patch("foundry_sandbox.git_worktree.worktree_has_changes")
    @patch("foundry_sandbox.git_worktree.git_with_retry")
    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_existing_worktree_dirty_skips_pull(self, mock_run, mock_retry, mock_changes, tmp_path):
        """Existing worktree with changes should skip pull."""
        bare = tmp_path / "bare.git"
        bare.mkdir()
        wt = tmp_path / "worktree"
        wt.mkdir()  # Already exists

        # prune succeeds
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        mock_changes.return_value = True

        git_worktree.create_worktree(bare, wt, "feature-branch")

        # git_with_retry should NOT be called (no pull)
        mock_retry.assert_not_called()


class TestCleanupSandboxBranch:
    """Tests for cleanup_sandbox_branch()."""

    def test_empty_branch_noop(self, tmp_path):
        """Empty branch should do nothing."""
        git_worktree.cleanup_sandbox_branch("", tmp_path)

    def test_empty_bare_path_noop(self):
        """Empty bare_path should do nothing."""
        git_worktree.cleanup_sandbox_branch("feature", "")

    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_protected_branches_skipped(self, mock_run, tmp_path):
        """Protected branches should not be deleted."""
        bare = tmp_path / "bare.git"
        bare.mkdir()

        for branch in ["main", "master", "develop", "production", "release/1.0", "hotfix/fix"]:
            git_worktree.cleanup_sandbox_branch(branch, bare)

        # subprocess.run should never be called for protected branches
        mock_run.assert_not_called()

    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_branch_in_use_skipped(self, mock_run, tmp_path):
        """Branch in use by another worktree should not be deleted."""
        bare = tmp_path / "bare.git"
        bare.mkdir()

        # worktree list shows the branch in use
        mock_run.return_value = Mock(
            returncode=0,
            stdout="worktree /path/to/wt\nHEAD abc123\nbranch refs/heads/sandbox-123\n",
            stderr="",
        )

        git_worktree.cleanup_sandbox_branch("sandbox-123", bare)

        # Should only call worktree list, NOT branch -D
        assert mock_run.call_count == 1
        assert "worktree" in str(mock_run.call_args)

    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_unprotected_branch_deleted(self, mock_run, tmp_path):
        """Unprotected branch not in use should be deleted."""
        bare = tmp_path / "bare.git"
        bare.mkdir()

        mock_run.side_effect = [
            Mock(returncode=0, stdout="worktree /bare\nHEAD abc\n", stderr=""),  # worktree list
            Mock(returncode=0, stdout="", stderr=""),  # branch -D
        ]

        git_worktree.cleanup_sandbox_branch("sandbox-456", bare)

        assert mock_run.call_count == 2
        delete_call = mock_run.call_args_list[1]
        assert "branch" in str(delete_call)
        assert "-D" in str(delete_call)


class TestRemoveWorktree:
    """Tests for remove_worktree()."""

    def test_nonexistent_path_noop(self, tmp_path):
        """Non-existent worktree path should do nothing."""
        wt = tmp_path / "nonexistent"

        # Should not raise
        git_worktree.remove_worktree(wt)

    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_git_remove_succeeds(self, mock_run, tmp_path):
        """Successful git worktree remove should not fall back."""
        wt = tmp_path / "worktree"
        wt.mkdir()

        mock_run.side_effect = [
            Mock(returncode=0, stdout=str(tmp_path / "bare.git" / "worktrees" / "wt"), stderr=""),  # rev-parse
            Mock(returncode=0, stdout="", stderr=""),  # worktree remove
        ]

        git_worktree.remove_worktree(wt)

        assert mock_run.call_count == 2

    @patch("foundry_sandbox.git_worktree.shutil.rmtree")
    @patch("foundry_sandbox.git_worktree.subprocess.run")
    def test_fallback_to_rmtree(self, mock_run, mock_rmtree, tmp_path):
        """Failed git worktree remove should fall back to shutil.rmtree."""
        wt = tmp_path / "worktree"
        wt.mkdir()

        mock_run.side_effect = [
            Mock(returncode=0, stdout=str(tmp_path / "bare.git" / "worktrees" / "wt"), stderr=""),  # rev-parse
            Mock(returncode=1, stdout="", stderr="error"),  # worktree remove fails
        ]

        git_worktree.remove_worktree(wt)

        mock_rmtree.assert_called_once_with(wt, ignore_errors=True)
