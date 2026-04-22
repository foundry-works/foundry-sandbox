"""Unit tests for foundry_sandbox/git.py.

Tests cover:
- Retry logic with exponential backoff
- Stale git lockfile cleanup
- Working directory checkout management
- Branch existence checking
- Sandbox branch cleanup (new-layout)
- Ref injection prevention
"""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from foundry_sandbox import git


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


class TestRemoveStaleGitLocks:
    """Tests for remove_stale_git_locks()."""

    def test_no_lockfiles_is_noop(self, tmp_path):
        """No lockfiles present should do nothing."""
        git.remove_stale_git_locks(tmp_path)  # should not raise

    def test_nonexistent_dir_is_noop(self, tmp_path):
        """Non-existent directory should do nothing."""
        git.remove_stale_git_locks(tmp_path / "nonexistent")

    def test_stale_config_lock_removed(self, tmp_path):
        """config.lock older than threshold should be removed."""
        lock = tmp_path / "config.lock"
        lock.write_text("")
        import os
        # Set mtime to 5 minutes ago
        old_time = __import__("time").time() - 300
        os.utime(lock, (old_time, old_time))

        git.remove_stale_git_locks(tmp_path)

        assert not lock.exists()

    def test_stale_head_lock_removed(self, tmp_path):
        """HEAD.lock older than threshold should be removed."""
        lock = tmp_path / "HEAD.lock"
        lock.write_text("")
        import os
        old_time = __import__("time").time() - 300
        os.utime(lock, (old_time, old_time))

        git.remove_stale_git_locks(tmp_path)

        assert not lock.exists()

    def test_fresh_lock_preserved(self, tmp_path):
        """config.lock younger than threshold should not be removed."""
        lock = tmp_path / "config.lock"
        lock.write_text("")
        # mtime is now — well under the 120s threshold

        git.remove_stale_git_locks(tmp_path)

        assert lock.exists()


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


class TestCleanupSandboxBranchRepo:
    """Tests for cleanup_sandbox_branch_repo()."""

    def test_empty_branch_noop(self, tmp_path):
        """Empty branch should do nothing."""
        git.cleanup_sandbox_branch_repo("", tmp_path)

    def test_empty_repo_root_noop(self):
        """Empty repo_root should do nothing."""
        git.cleanup_sandbox_branch_repo("feature", "")

    def test_dash_branch_rejected(self):
        """Branch starting with '-' must be rejected."""
        with pytest.raises(ValueError, match="must not start with"):
            git.cleanup_sandbox_branch_repo("--upload-pack=evil", "/repo")

    @patch("foundry_sandbox.git.subprocess.run")
    def test_protected_branches_skipped(self, mock_run, tmp_path):
        """Protected branches should not be deleted."""
        repo = tmp_path / "repo"
        repo.mkdir()

        for branch in ["main", "master", "develop", "production", "release/1.0", "hotfix/fix"]:
            git.cleanup_sandbox_branch_repo(branch, repo)

        mock_run.assert_not_called()

    @patch("foundry_sandbox.git.subprocess.run")
    def test_branch_in_use_skipped(self, mock_run, tmp_path):
        """Branch in use by another worktree should not be deleted."""
        repo = tmp_path / "repo"
        repo.mkdir()

        mock_run.return_value = Mock(
            returncode=0,
            stdout="worktree /path/to/wt\nHEAD abc123\nbranch refs/heads/sandbox-123\n",
            stderr="",
        )

        git.cleanup_sandbox_branch_repo("sandbox-123", repo)

        # Should only call worktree list, NOT branch -D
        assert mock_run.call_count == 1
        assert "worktree" in str(mock_run.call_args)

    @patch("foundry_sandbox.git.subprocess.run")
    def test_unprotected_branch_deleted(self, mock_run, tmp_path):
        """Unprotected branch not in use should be deleted."""
        repo = tmp_path / "repo"
        repo.mkdir()

        mock_run.side_effect = [
            Mock(returncode=0, stdout="worktree /repo\nHEAD abc\n", stderr=""),  # worktree list
            Mock(returncode=0, stdout="", stderr=""),  # branch -D
        ]

        git.cleanup_sandbox_branch_repo("sandbox-456", repo)

        assert mock_run.call_count == 2
        delete_call = mock_run.call_args_list[1]
        assert "branch" in str(delete_call)
        assert "-D" in str(delete_call)

    def test_nonexistent_repo_noop(self, tmp_path):
        """Non-existent repo directory should do nothing."""
        git.cleanup_sandbox_branch_repo("sandbox-branch", tmp_path / "nonexistent")


# ============================================================================
# Ref Injection Prevention Tests
# ============================================================================


class TestRefInjectionPrevention:
    """Branches starting with '-' must be rejected to prevent flag injection."""

    def test_cleanup_sandbox_branch_repo_rejects_dash(self):
        with pytest.raises(ValueError, match="must not start with"):
            git.cleanup_sandbox_branch_repo("--upload-pack=evil", "/repo")

    def test_ensure_repo_checkout_rejects_dash_branch(self):
        with pytest.raises(ValueError, match="must not start with"):
            git.ensure_repo_checkout("https://example.com/repo", "/checkout", branch="--upload-pack=evil")
