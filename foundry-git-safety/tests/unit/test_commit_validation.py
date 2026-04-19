"""Tests for foundry_git_safety.commit_validation."""

from unittest.mock import MagicMock, patch

import pytest

from foundry_git_safety.commit_validation import (
    check_commit_file_restrictions,
)
from foundry_git_safety.config import ConfigError, FileRestrictionsData


# ---------------------------------------------------------------------------
# TestCheckCommitFileRestrictions
# ---------------------------------------------------------------------------


class TestCheckCommitFileRestrictions:
    """Tests for check_commit_file_restrictions(repo_root, metadata)."""

    def test_blocked_file_in_staged_changes_returns_error(self):
        """A staged file matching a blocked pattern produces a ValidationError."""
        config = FileRestrictionsData(
            blocked_patterns=[".github/workflows/*"],
            warned_patterns=[],
            warn_action="log",
        )
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b".github/workflows/ci.yml\n"
        mock_result.stderr = b""

        with patch(
            "foundry_git_safety.commit_validation.get_file_restrictions_config",
            return_value=config,
        ), patch("foundry_git_safety.commit_validation.subprocess.run", return_value=mock_result):
            err = check_commit_file_restrictions("/fake/repo")

        assert err is not None
        assert "blocked" in err.reason.lower() or "ci.yml" in err.reason

    def test_config_error_allows_commit(self):
        """When get_file_restrictions_config raises ConfigError, commit is allowed.

        The security boundary is at push time, so commit validation
        warn-and-allows on config errors.
        """
        with patch(
            "foundry_git_safety.commit_validation.get_file_restrictions_config",
            side_effect=ConfigError("config missing"),
        ):
            err = check_commit_file_restrictions("/fake/repo")

        assert err is None

    def test_diff_failure_allows_commit(self):
        """When git diff --cached fails (non-zero exit), commit is allowed.

        The security boundary is at push time, so commit validation
        warn-and-allows when it cannot enumerate staged files.
        """
        config = FileRestrictionsData(
            blocked_patterns=[".github/workflows/*"],
            warned_patterns=[],
            warn_action="log",
        )
        mock_result = MagicMock()
        mock_result.returncode = 128
        mock_result.stderr = b"fatal: not a git repository"

        with patch(
            "foundry_git_safety.commit_validation.get_file_restrictions_config",
            return_value=config,
        ), patch("foundry_git_safety.commit_validation.subprocess.run", return_value=mock_result):
            err = check_commit_file_restrictions("/fake/repo")

        assert err is None

    def test_diff_exception_allows_commit(self):
        """When subprocess.run raises OSError, commit is allowed."""
        config = FileRestrictionsData(
            blocked_patterns=[".github/workflows/*"],
            warned_patterns=[],
            warn_action="log",
        )

        with patch(
            "foundry_git_safety.commit_validation.get_file_restrictions_config",
            return_value=config,
        ), patch(
            "foundry_git_safety.commit_validation.subprocess.run",
            side_effect=OSError("ENOENT"),
        ):
            err = check_commit_file_restrictions("/fake/repo")

        assert err is None

    def test_empty_staged_files_pass(self):
        """When no files are staged, commit passes with no error."""
        config = FileRestrictionsData(
            blocked_patterns=[".github/workflows/*"],
            warned_patterns=[],
            warn_action="log",
        )
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch(
            "foundry_git_safety.commit_validation.get_file_restrictions_config",
            return_value=config,
        ), patch("foundry_git_safety.commit_validation.subprocess.run", return_value=mock_result):
            err = check_commit_file_restrictions("/fake/repo")

        assert err is None

    def test_clean_files_pass(self):
        """When staged files do not match any blocked pattern, commit passes."""
        config = FileRestrictionsData(
            blocked_patterns=[".github/workflows/*"],
            warned_patterns=[],
            warn_action="log",
        )
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"src/main.py\nREADME.md\n"
        mock_result.stderr = b""

        with patch(
            "foundry_git_safety.commit_validation.get_file_restrictions_config",
            return_value=config,
        ), patch("foundry_git_safety.commit_validation.subprocess.run", return_value=mock_result):
            err = check_commit_file_restrictions("/fake/repo")

        assert err is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
