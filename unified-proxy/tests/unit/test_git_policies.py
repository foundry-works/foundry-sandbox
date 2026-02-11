"""Unit tests for git_policies module.

Tests branch policy loading, protected branch enforcement,
and bootstrap creation logic.
"""

import os
from unittest.mock import patch

import pytest

from git_policies import (
    DEFAULT_PROTECTED_PATTERNS,
    ZERO_SHA,
    BranchPolicyConfig,
    check_protected_branches,
    load_branch_policy,
)


class TestLoadBranchPolicy:
    """Tests for load_branch_policy function."""

    def test_default_config(self):
        """Test default config has enabled=True and default patterns."""
        with patch.dict(os.environ, {}, clear=True):
            config = load_branch_policy()
            assert config.enabled is True
            assert config.patterns == DEFAULT_PROTECTED_PATTERNS

    def test_env_var_disables(self):
        """Test GIT_PROTECTED_BRANCHES_ENABLED=false disables policy."""
        with patch.dict(os.environ, {"GIT_PROTECTED_BRANCHES_ENABLED": "false"}, clear=True):
            config = load_branch_policy()
            assert config.enabled is False

    @pytest.mark.parametrize("value", ["true", "1", "yes", "TRUE"])
    def test_env_var_enables(self, value):
        """Test various truthy env var values enable policy."""
        with patch.dict(os.environ, {"GIT_PROTECTED_BRANCHES_ENABLED": value}, clear=True):
            config = load_branch_policy()
            assert config.enabled is True

    def test_env_var_patterns_override_defaults(self):
        """Test GIT_PROTECTED_BRANCHES_PATTERNS overrides default patterns."""
        with patch.dict(
            os.environ,
            {"GIT_PROTECTED_BRANCHES_PATTERNS": "refs/heads/main,refs/heads/develop"},
            clear=True,
        ):
            config = load_branch_policy()
            assert config.patterns == ["refs/heads/main", "refs/heads/develop"]

    def test_pattern_whitespace_trimming(self):
        """Test patterns with whitespace are trimmed."""
        with patch.dict(
            os.environ,
            {"GIT_PROTECTED_BRANCHES_PATTERNS": " refs/heads/main , refs/heads/master "},
            clear=True,
        ):
            config = load_branch_policy()
            assert config.patterns == ["refs/heads/main", "refs/heads/master"]

    def test_metadata_overrides_env_vars(self):
        """Test metadata enabled overrides env var enabled."""
        with patch.dict(
            os.environ,
            {"GIT_PROTECTED_BRANCHES_ENABLED": "false"},
            clear=True,
        ):
            metadata = {"git": {"protected_branches": {"enabled": True}}}
            config = load_branch_policy(metadata)
            assert config.enabled is True

    def test_metadata_patterns_override_env_patterns(self):
        """Test metadata patterns override env var patterns."""
        with patch.dict(
            os.environ,
            {"GIT_PROTECTED_BRANCHES_PATTERNS": "refs/heads/main"},
            clear=True,
        ):
            metadata = {
                "git": {
                    "protected_branches": {
                        "patterns": ["refs/heads/custom"]
                    }
                }
            }
            config = load_branch_policy(metadata)
            assert config.patterns == ["refs/heads/custom"]

    def test_invalid_metadata_types_gracefully_ignored(self):
        """Test non-dict git config is gracefully ignored."""
        with patch.dict(os.environ, {}, clear=True):
            metadata = {"git": "not a dict"}
            config = load_branch_policy(metadata)
            assert config.enabled is True
            assert config.patterns == DEFAULT_PROTECTED_PATTERNS

    def test_empty_env_patterns_keeps_defaults(self):
        """Test empty GIT_PROTECTED_BRANCHES_PATTERNS keeps defaults."""
        with patch.dict(
            os.environ,
            {"GIT_PROTECTED_BRANCHES_PATTERNS": ""},
            clear=True,
        ):
            config = load_branch_policy()
            assert config.patterns == DEFAULT_PROTECTED_PATTERNS


class TestCheckProtectedBranches:
    """Tests for check_protected_branches function."""

    def test_push_to_main_blocked(self):
        """Test direct push to main is blocked."""
        with patch.dict(os.environ, {}, clear=True):
            result = check_protected_branches(
                "refs/heads/main", "abc123" + "0" * 34, "def456" + "0" * 34
            )
            assert result is not None
            assert "Direct push" in result
            assert "refs/heads/main" in result

    def test_push_to_master_blocked(self):
        """Test direct push to master is blocked."""
        with patch.dict(os.environ, {}, clear=True):
            result = check_protected_branches(
                "refs/heads/master", "abc123" + "0" * 34, "def456" + "0" * 34
            )
            assert result is not None
            assert "Direct push" in result

    def test_push_to_feature_allowed(self):
        """Test push to feature/foo is allowed."""
        with patch.dict(os.environ, {}, clear=True):
            result = check_protected_branches(
                "refs/heads/feature/foo", "abc123" + "0" * 34, "def456" + "0" * 34
            )
            assert result is None

    def test_deletion_of_main_blocked(self):
        """Test deletion of main (new_sha=ZERO_SHA) is blocked."""
        with patch.dict(os.environ, {}, clear=True):
            result = check_protected_branches(
                "refs/heads/main", "abc123" + "0" * 34, ZERO_SHA
            )
            assert result is not None
            assert "Deletion" in result

    def test_creation_of_non_main_protected_blocked(self):
        """Test creation of non-main protected branch is blocked."""
        with patch.dict(os.environ, {}, clear=True):
            result = check_protected_branches(
                "refs/heads/master", ZERO_SHA, "def456" + "0" * 34
            )
            assert result is not None
            assert "Creation" in result
            assert "not allowed" in result

    def test_wildcard_release_branch_matches(self):
        """Test refs/heads/release/v2.0 matches release/* pattern."""
        with patch.dict(os.environ, {}, clear=True):
            result = check_protected_branches(
                "refs/heads/release/v2.0", "abc123" + "0" * 34, "def456" + "0" * 34
            )
            assert result is not None
            assert "Direct push" in result

    def test_policy_disabled_allows_all(self):
        """Test disabled policy allows all operations."""
        with patch.dict(
            os.environ,
            {"GIT_PROTECTED_BRANCHES_ENABLED": "false"},
            clear=True,
        ):
            result = check_protected_branches(
                "refs/heads/main", "abc123" + "0" * 34, "def456" + "0" * 34
            )
            assert result is None

    def test_non_matching_ref_allowed(self):
        """Test non-matching ref (e.g. tags) is allowed."""
        with patch.dict(os.environ, {}, clear=True):
            result = check_protected_branches(
                "refs/tags/v1.0", ZERO_SHA, "def456" + "0" * 34
            )
            assert result is None


class TestBootstrapCreation:
    """Tests for bootstrap creation logic."""

    def test_first_main_creation_allowed(self):
        """Test first main creation succeeds when lock file doesn't exist."""
        with patch.dict(os.environ, {}, clear=True):
            with patch("git_policies.os.open", return_value=3) as mock_open:
                with patch("git_policies.os.close") as mock_close:
                    result = check_protected_branches(
                        "refs/heads/main", ZERO_SHA, "def456" + "0" * 34,
                        bare_repo_path="/repo.git",
                    )
                    assert result is None
                    mock_open.assert_called_once()
                    mock_close.assert_called_once_with(3)

    def test_second_creation_blocked(self):
        """Test second main creation is blocked (lock file exists)."""
        with patch.dict(os.environ, {}, clear=True):
            with patch("git_policies.os.open", side_effect=FileExistsError):
                result = check_protected_branches(
                    "refs/heads/main", ZERO_SHA, "def456" + "0" * 34,
                    bare_repo_path="/repo.git",
                )
                assert result is not None
                assert "bootstrap already completed" in result

    def test_no_bare_repo_path_blocked(self):
        """Test creation blocked when no bare_repo_path."""
        with patch.dict(os.environ, {}, clear=True):
            result = check_protected_branches(
                "refs/heads/main", ZERO_SHA, "def456" + "0" * 34,
                bare_repo_path=None,
            )
            assert result is not None
            assert "not allowed" in result

    def test_os_error_on_lock_blocked(self):
        """Test OSError on lock file creation is blocked with error message."""
        with patch.dict(os.environ, {}, clear=True):
            with patch("git_policies.os.open", side_effect=OSError("Permission denied")):
                result = check_protected_branches(
                    "refs/heads/main", ZERO_SHA, "def456" + "0" * 34,
                    bare_repo_path="/repo.git",
                )
                assert result is not None
                assert "lock file error" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
