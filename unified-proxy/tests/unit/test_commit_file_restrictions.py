"""Unit tests for commit-time file restriction validation (Wave 2.2).

Tests cover:
- check_commit_file_restrictions() with blocked/warned/allowed staged files
- Fail-closed behavior on config or diff errors
- _enumerate_staged_files() subprocess interaction
- Integration with execute_git() commit detection
"""

import subprocess
import sys
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from config import (
    ConfigError,
    load_file_restrictions_config,
)

# git_operations imports mitmproxy indirectly; ensure mocks are in place.
for mod in ("mitmproxy", "mitmproxy.http", "mitmproxy.ctx", "mitmproxy.flow"):
    if mod not in sys.modules:
        sys.modules[mod] = mock.MagicMock()

from git_operations import (  # noqa: E402
    _enumerate_staged_files,
    check_commit_file_restrictions,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config_file(tmp_path):
    """Write a valid config YAML to a temp file and return its path."""
    content = """\
version: "1.0"
blocked_patterns:
  - ".github/workflows/"
  - "Makefile"
warned_patterns:
  - "package.json"
warn_action: "log"
"""
    p = tmp_path / "push-file-restrictions.yaml"
    p.write_text(content)
    return str(p)


@pytest.fixture
def reject_config_file(tmp_path):
    """Write a config with warn_action=reject."""
    content = """\
version: "1.0"
blocked_patterns:
  - ".github/workflows/"
  - "Makefile"
warned_patterns:
  - "package.json"
warn_action: "reject"
"""
    p = tmp_path / "push-file-restrictions.yaml"
    p.write_text(content)
    return str(p)


# ---------------------------------------------------------------------------
# _enumerate_staged_files Tests
# ---------------------------------------------------------------------------


class TestEnumerateStagedFiles:
    """Tests for _enumerate_staged_files()."""

    def test_returns_file_list_on_success(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"src/main.py\nlib/utils.js\n"
        with patch("git_operations.subprocess.run", return_value=mock_result):
            files = _enumerate_staged_files("/repo", {})
            assert files == ["src/main.py", "lib/utils.js"]

    def test_returns_none_on_failure(self):
        mock_result = MagicMock()
        mock_result.returncode = 128
        mock_result.stdout = b""
        with patch("git_operations.subprocess.run", return_value=mock_result):
            files = _enumerate_staged_files("/repo", {})
            assert files is None

    def test_returns_empty_list_on_no_staged_files(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        with patch("git_operations.subprocess.run", return_value=mock_result):
            files = _enumerate_staged_files("/repo", {})
            assert files == []

    def test_returns_none_on_timeout(self):
        with patch(
            "git_operations.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="git", timeout=10),
        ):
            files = _enumerate_staged_files("/repo", {})
            assert files is None

    def test_returns_none_on_os_error(self):
        with patch(
            "git_operations.subprocess.run",
            side_effect=OSError("git not found"),
        ):
            files = _enumerate_staged_files("/repo", {})
            assert files is None


# ---------------------------------------------------------------------------
# check_commit_file_restrictions Tests
# ---------------------------------------------------------------------------


META = {"sandbox_branch": "sandbox/test-branch"}


class TestCheckCommitFileRestrictions:
    """Tests for check_commit_file_restrictions()."""

    def _make_diff_result(self, files_str, returncode=0):
        result = MagicMock()
        result.returncode = returncode
        result.stdout = files_str.encode("utf-8")
        return result

    def test_blocked_workflow_file(self, config_file):
        """Commit with staged .github/workflows/ci.yml is rejected."""
        diff_result = self._make_diff_result(".github/workflows/ci.yml\n")

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_commit_file_restrictions("/repo", META)
            assert err is not None
            assert "blocked" in err.reason.lower() or "Blocked" in err.reason

    def test_blocked_makefile(self, config_file):
        """Commit with staged Makefile is rejected."""
        diff_result = self._make_diff_result("Makefile\n")

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_commit_file_restrictions("/repo", META)
            assert err is not None
            assert "Makefile" in err.reason

    def test_clean_files_pass(self, config_file):
        """Commit with only src/ files is allowed."""
        diff_result = self._make_diff_result("src/main.py\nsrc/utils.py\n")

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_commit_file_restrictions("/repo", META)
            assert err is None

    def test_warned_file_logs(self, config_file):
        """Commit with staged package.json passes with warn_action=log."""
        diff_result = self._make_diff_result("package.json\n")

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_commit_file_restrictions("/repo", META)
            assert err is None  # Not blocked, just warned

    def test_warned_file_rejects_when_configured(self, reject_config_file):
        """Commit with staged package.json rejected with warn_action=reject."""
        diff_result = self._make_diff_result("package.json\n")

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(reject_config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_commit_file_restrictions("/repo", META)
            assert err is not None
            assert "package.json" in err.reason

    def test_config_unavailable_fails_closed(self):
        """Commit is blocked when config cannot be loaded."""
        with patch(
            "git_operations.get_file_restrictions_config",
            side_effect=ConfigError("file not found"),
        ):
            err = check_commit_file_restrictions("/repo", META)
            assert err is not None
            assert "fail-closed" in err.reason

    def test_diff_failure_fails_closed(self, config_file):
        """Commit is blocked when git diff --cached fails."""
        fail_result = self._make_diff_result("", returncode=128)

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=fail_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_commit_file_restrictions("/repo", META)
            assert err is not None
            assert "fail-closed" in err.reason

    def test_no_staged_files_passes(self, config_file):
        """Commit with no staged files passes."""
        diff_result = self._make_diff_result("")

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_commit_file_restrictions("/repo", META)
            assert err is None

    def test_path_traversal_blocked(self, config_file):
        """Commit with path traversal in staged files is blocked."""
        diff_result = self._make_diff_result(
            "../../.github/workflows/ci.yml\n"
        )

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_commit_file_restrictions("/repo", META)
            assert err is not None
            assert "Path traversal" in err.reason


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
