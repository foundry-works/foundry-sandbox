"""Tests for foundry_git_safety.policies."""

import os
from unittest.mock import patch

import pytest

from foundry_git_safety.policies import (
    DEFAULT_PROTECTED_PATTERNS,
    ZERO_SHA,
    BranchPolicyConfig,
    _check_bootstrap_creation,
    check_protected_branches,
    load_branch_policy,
)


# ---------------------------------------------------------------------------
# TestLoadBranchPolicy
# ---------------------------------------------------------------------------

class TestLoadBranchPolicy:
    """Tests for load_branch_policy(metadata=None) precedence rules."""

    def test_defaults_enabled_with_four_patterns(self):
        """With no env vars or metadata, policy is enabled with DEFAULT_PROTECTED_PATTERNS."""
        with patch.dict("os.environ", {}, clear=True):
            config = load_branch_policy()
        assert config.enabled is True
        assert config.patterns == DEFAULT_PROTECTED_PATTERNS
        assert len(config.patterns) == 4

    def test_env_var_disable(self):
        """GIT_PROTECTED_BRANCHES_ENABLED=false disables the policy."""
        with patch.dict(
            "os.environ",
            {"GIT_PROTECTED_BRANCHES_ENABLED": "false"},
            clear=True,
        ):
            config = load_branch_policy()
        assert config.enabled is False

    def test_env_var_patterns_override(self):
        """GIT_PROTECTED_BRANCHES_PATTERNS overrides default patterns."""
        custom = "refs/heads/main,refs/heads/staging"
        with patch.dict(
            "os.environ",
            {"GIT_PROTECTED_BRANCHES_PATTERNS": custom},
            clear=True,
        ):
            config = load_branch_policy()
        assert config.patterns == ["refs/heads/main", "refs/heads/staging"]

    def test_metadata_override_for_enabled(self):
        """Metadata git.protected_branches.enabled overrides defaults."""
        metadata = {"git": {"protected_branches": {"enabled": False}}}
        with patch.dict("os.environ", {}, clear=True):
            config = load_branch_policy(metadata=metadata)
        assert config.enabled is False

    def test_metadata_override_for_patterns(self):
        """Metadata git.protected_branches.patterns overrides defaults."""
        custom_patterns = ["refs/heads/main", "refs/heads/custom/*"]
        metadata = {
            "git": {"protected_branches": {"patterns": custom_patterns}}
        }
        with patch.dict("os.environ", {}, clear=True):
            config = load_branch_policy(metadata=metadata)
        assert config.patterns == custom_patterns

    def test_metadata_takes_precedence_over_env_vars(self):
        """Metadata wins when both env vars and metadata are present."""
        with patch.dict(
            "os.environ",
            {
                "GIT_PROTECTED_BRANCHES_ENABLED": "false",
                "GIT_PROTECTED_BRANCHES_PATTERNS": "refs/heads/env-only",
            },
            clear=True,
        ):
            metadata = {
                "git": {
                    "protected_branches": {
                        "enabled": True,
                        "patterns": ["refs/heads/meta-pattern"],
                    }
                }
            }
            config = load_branch_policy(metadata=metadata)
        assert config.enabled is True
        assert config.patterns == ["refs/heads/meta-pattern"]


# ---------------------------------------------------------------------------
# TestCheckProtectedBranches
# ---------------------------------------------------------------------------

class TestCheckProtectedBranches:
    """Tests for check_protected_branches() gate logic."""

    def test_update_to_main_blocked(self):
        """Direct push to refs/heads/main is blocked."""
        result = check_protected_branches(
            "refs/heads/main",
            "a" * 40,
            "b" * 40,
        )
        assert result is not None
        assert "protected branch" in result

    def test_deletion_blocked(self):
        """Deletion of a protected branch (new_sha=ZERO_SHA) is blocked."""
        result = check_protected_branches(
            "refs/heads/main",
            "a" * 40,
            ZERO_SHA,
        )
        assert result is not None
        assert "Deletion" in result

    def test_non_protected_branch_allowed(self):
        """Push to a non-protected branch is allowed."""
        result = check_protected_branches(
            "refs/heads/feature/my-thing",
            "a" * 40,
            "b" * 40,
        )
        assert result is None

    def test_disabled_policy_allows_all(self):
        """When policy is disabled, even protected branches are allowed."""
        metadata = {"git": {"protected_branches": {"enabled": False}}}
        result = check_protected_branches(
            "refs/heads/main",
            "a" * 40,
            "b" * 40,
            metadata=metadata,
        )
        assert result is None

    def test_custom_pattern_matching(self):
        """Custom patterns supplied via metadata are matched via fnmatch."""
        metadata = {
            "git": {
                "protected_branches": {
                    "patterns": ["refs/heads/custom/*"]
                }
            }
        }
        result = check_protected_branches(
            "refs/heads/custom/special",
            "a" * 40,
            "b" * 40,
            metadata=metadata,
        )
        assert result is not None

    def test_release_wildcard_matches_release_v1(self):
        """refs/heads/release/v1.0 matches the default refs/heads/release/* pattern."""
        result = check_protected_branches(
            "refs/heads/release/v1.0",
            "a" * 40,
            "b" * 40,
        )
        assert result is not None

    def test_feature_branch_allowed(self):
        """refs/heads/feature/x does not match any default protected pattern."""
        result = check_protected_branches(
            "refs/heads/feature/x",
            "a" * 40,
            "b" * 40,
        )
        assert result is None

    def test_creation_of_non_main_protected_branch_blocked(self):
        """Creating refs/heads/production (a protected non-main branch) is blocked."""
        result = check_protected_branches(
            "refs/heads/production",
            ZERO_SHA,
            "a" * 40,
        )
        assert result is not None
        assert "Creation" in result or "protected" in result


# ---------------------------------------------------------------------------
# TestBootstrapCreation
# ---------------------------------------------------------------------------

class TestBootstrapCreation:
    """Tests for _check_bootstrap_creation() atomic lock file logic."""

    def test_first_creation_of_main_succeeds(self, tmp_path):
        """First creation of refs/heads/main is allowed and creates lock file."""
        result = _check_bootstrap_creation("refs/heads/main", str(tmp_path))
        assert result is None
        lock_file = tmp_path / "foundry-bootstrap-refs_heads_main.lock"
        assert lock_file.exists()

    def test_second_creation_blocked(self, tmp_path):
        """Second creation of refs/heads/main is blocked (lock exists)."""
        lock_file = tmp_path / "foundry-bootstrap-refs_heads_main.lock"
        lock_file.write_text("")
        result = _check_bootstrap_creation("refs/heads/main", str(tmp_path))
        assert result is not None
        assert "bootstrap" in result

    def test_first_creation_of_production_succeeds(self, tmp_path):
        """First creation of refs/heads/production is also allowed via bootstrap."""
        result = _check_bootstrap_creation("refs/heads/production", str(tmp_path))
        assert result is None
        lock_file = tmp_path / "foundry-bootstrap-refs_heads_production.lock"
        assert lock_file.exists()

    def test_none_bare_repo_path_blocks_creation(self):
        """When bare_repo_path is None, even refs/heads/main creation is blocked."""
        result = _check_bootstrap_creation("refs/heads/main", None)
        assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
