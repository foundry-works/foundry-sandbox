"""Unit tests for push-time file restriction validation.

Tests cover:
- Config loading and validation
- Pattern matching (directory, glob, bare name)
- check_file_restrictions() with blocked/warned/allowed files
- Path traversal rejection
- check_push_file_restrictions() integration with git diff
- Fail-closed behavior on config or diff errors
- First push fallback to default branch
"""

import os
import subprocess
import sys
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from config import (
    ConfigError,
    FileRestrictionsConfig,
    _matches_pattern,
    check_file_restrictions,
    get_file_restrictions_config,
    load_file_restrictions_config,
    matches_any,
)

# git_operations imports mitmproxy indirectly; ensure mocks are in place.
for mod in ("mitmproxy", "mitmproxy.http", "mitmproxy.ctx", "mitmproxy.flow"):
    if mod not in sys.modules:
        sys.modules[mod] = mock.MagicMock()

from git_operations import (  # noqa: E402
    _enumerate_push_changed_files,
    check_push_file_restrictions,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_config():
    """Return a FileRestrictionsConfig with the default patterns."""
    return FileRestrictionsConfig(
        blocked_patterns=[
            ".github/workflows/",
            ".github/actions/",
            "Makefile",
            "Justfile",
            "Taskfile.yml",
            ".pre-commit-config.yaml",
            "CODEOWNERS",
            ".github/FUNDING.yml",
        ],
        warned_patterns=[
            "package.json",
            "pyproject.toml",
            "requirements.txt",
            "requirements-*.txt",
            "Gemfile",
            "go.mod",
            "go.sum",
            "Cargo.toml",
            "Cargo.lock",
            "docker-compose*.yml",
            "Dockerfile",
            ".env*",
        ],
        warn_action="log",
    )


@pytest.fixture
def reject_config():
    """Return a config with warn_action=reject."""
    return FileRestrictionsConfig(
        blocked_patterns=[".github/workflows/", "Makefile"],
        warned_patterns=["package.json", "pyproject.toml"],
        warn_action="reject",
    )


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


# ---------------------------------------------------------------------------
# Config Loading Tests
# ---------------------------------------------------------------------------


class TestLoadFileRestrictionsConfig:
    """Tests for load_file_restrictions_config()."""

    def test_loads_valid_config(self, config_file):
        config = load_file_restrictions_config(config_file)
        assert config.blocked_patterns == [".github/workflows/", "Makefile"]
        assert config.warned_patterns == ["package.json"]
        assert config.warn_action == "log"

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_file_restrictions_config(str(tmp_path / "nonexistent.yaml"))

    def test_missing_blocked_patterns_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text('version: "1.0"\nwarned_patterns: []\nwarn_action: "log"\n')
        with pytest.raises(ConfigError, match="blocked_patterns"):
            load_file_restrictions_config(str(p))

    def test_missing_warned_patterns_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text('version: "1.0"\nblocked_patterns: []\nwarn_action: "log"\n')
        with pytest.raises(ConfigError, match="warned_patterns"):
            load_file_restrictions_config(str(p))

    def test_missing_warn_action_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text('version: "1.0"\nblocked_patterns: []\nwarned_patterns: []\n')
        with pytest.raises(ConfigError, match="warn_action"):
            load_file_restrictions_config(str(p))

    def test_invalid_warn_action_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text(
            'version: "1.0"\nblocked_patterns: []\n'
            'warned_patterns: []\nwarn_action: "block"\n'
        )
        with pytest.raises(ConfigError, match="'log' or 'reject'"):
            load_file_restrictions_config(str(p))

    def test_env_var_override(self, config_file):
        with patch.dict(
            os.environ, {"PROXY_FILE_RESTRICTIONS_PATH": config_file}
        ):
            config = load_file_restrictions_config()
            assert config.blocked_patterns == [".github/workflows/", "Makefile"]


class TestGetFileRestrictionsConfig:
    """Tests for get_file_restrictions_config() caching."""

    def test_caches_result(self, config_file):
        import config as config_module

        # Reset module-level cache
        config_module._file_restrictions_config = None
        try:
            c1 = get_file_restrictions_config(config_file)
            # Calling with path always bypasses cache
            c2 = get_file_restrictions_config(config_file)
            assert c1.blocked_patterns == c2.blocked_patterns
        finally:
            config_module._file_restrictions_config = None


# ---------------------------------------------------------------------------
# Pattern Matching Tests
# ---------------------------------------------------------------------------


class TestMatchesPattern:
    """Tests for _matches_pattern()."""

    # Directory patterns (ending in /)
    def test_directory_pattern_matches_file_under_dir(self):
        assert _matches_pattern(".github/workflows/ci.yml", ".github/workflows/")

    def test_directory_pattern_matches_nested_file(self):
        assert _matches_pattern(
            ".github/workflows/subdir/build.yml", ".github/workflows/"
        )

    def test_directory_pattern_no_match_outside_dir(self):
        assert not _matches_pattern("src/workflows/ci.yml", ".github/workflows/")

    def test_directory_pattern_no_match_partial_name(self):
        assert not _matches_pattern(".github/workflowsci.yml", ".github/workflows/")

    # Glob patterns
    def test_glob_matches_basename(self):
        assert _matches_pattern("requirements-dev.txt", "requirements-*.txt")

    def test_glob_matches_nested_basename(self):
        assert _matches_pattern("sub/requirements-prod.txt", "requirements-*.txt")

    def test_glob_no_match(self):
        assert not _matches_pattern("requirements.txt", "requirements-*.txt")

    def test_glob_docker_compose(self):
        assert _matches_pattern("docker-compose.override.yml", "docker-compose*.yml")

    def test_glob_docker_compose_plain(self):
        assert _matches_pattern("docker-compose.yml", "docker-compose*.yml")

    def test_glob_env_star(self):
        assert _matches_pattern(".env.production", ".env*")

    def test_glob_env_plain(self):
        assert _matches_pattern(".env", ".env*")

    def test_glob_no_match_unrelated(self):
        assert not _matches_pattern("src/main.py", "docker-compose*.yml")

    # Bare name patterns (no /, no glob)
    def test_bare_matches_root(self):
        assert _matches_pattern("Makefile", "Makefile")

    def test_bare_matches_nested(self):
        assert _matches_pattern("sub/Makefile", "Makefile")

    def test_bare_matches_deep_nested(self):
        assert _matches_pattern("a/b/c/Makefile", "Makefile")

    def test_bare_no_match_different_name(self):
        assert not _matches_pattern("Makefile.bak", "Makefile")

    def test_bare_no_match_prefix(self):
        assert not _matches_pattern("NotMakefile", "Makefile")

    def test_bare_codeowners(self):
        assert _matches_pattern("CODEOWNERS", "CODEOWNERS")

    def test_bare_pre_commit(self):
        assert _matches_pattern(".pre-commit-config.yaml", ".pre-commit-config.yaml")


class TestMatchesAny:
    """Tests for matches_any()."""

    def test_matches_first_pattern(self):
        assert matches_any(
            ".github/workflows/ci.yml",
            [".github/workflows/", "Makefile"],
        )

    def test_matches_second_pattern(self):
        assert matches_any("Makefile", [".github/workflows/", "Makefile"])

    def test_no_match(self):
        assert not matches_any("src/main.py", [".github/workflows/", "Makefile"])

    def test_empty_patterns(self):
        assert not matches_any("anything", [])


# ---------------------------------------------------------------------------
# check_file_restrictions Tests
# ---------------------------------------------------------------------------


class TestCheckFileRestrictions:
    """Tests for check_file_restrictions()."""

    def test_blocked_file_blocks(self, sample_config):
        result = check_file_restrictions(
            [".github/workflows/ci.yml"], sample_config
        )
        assert result.blocked is True
        assert ".github/workflows/ci.yml" in result.reason

    def test_multiple_blocked_files(self, sample_config):
        result = check_file_restrictions(
            [".github/workflows/ci.yml", "Makefile", "src/main.py"],
            sample_config,
        )
        assert result.blocked is True
        assert ".github/workflows/ci.yml" in result.reason
        assert "Makefile" in result.reason

    def test_warned_file_logs(self, sample_config):
        result = check_file_restrictions(["package.json"], sample_config)
        assert result.blocked is False
        assert result.warned_files == ["package.json"]

    def test_warned_file_rejects_when_configured(self, reject_config):
        result = check_file_restrictions(["package.json"], reject_config)
        assert result.blocked is True
        assert "package.json" in result.reason

    def test_clean_files_pass(self, sample_config):
        result = check_file_restrictions(
            ["src/main.py", "lib/utils.js"], sample_config
        )
        assert result.blocked is False
        assert result.warned_files == []

    def test_empty_file_list(self, sample_config):
        result = check_file_restrictions([], sample_config)
        assert result.blocked is False

    def test_path_traversal_blocked(self, sample_config):
        result = check_file_restrictions(
            ["../../.github/workflows/ci.yml"], sample_config
        )
        assert result.blocked is True
        assert "Path traversal" in result.reason

    def test_path_traversal_in_middle_blocked(self, sample_config):
        result = check_file_restrictions(
            ["src/../../../etc/passwd"], sample_config
        )
        assert result.blocked is True
        assert "Path traversal" in result.reason

    def test_normalization_collapses_double_slashes(self, sample_config):
        result = check_file_restrictions(
            [".github//workflows//ci.yml"], sample_config
        )
        assert result.blocked is True

    def test_normalization_strips_dot_slash(self, sample_config):
        result = check_file_restrictions(
            ["./src/main.py"], sample_config
        )
        assert result.blocked is False

    def test_blocked_takes_priority_over_warned(self):
        """If a file matches both blocked and warned, it should be blocked."""
        config = FileRestrictionsConfig(
            blocked_patterns=["Makefile"],
            warned_patterns=["Makefile"],
            warn_action="log",
        )
        result = check_file_restrictions(["Makefile"], config)
        assert result.blocked is True

    def test_makefile_at_any_depth(self, sample_config):
        result = check_file_restrictions(["sub/Makefile"], sample_config)
        assert result.blocked is True

    def test_github_workflows_nested(self, sample_config):
        result = check_file_restrictions(
            [".github/workflows/deploy/production.yml"], sample_config
        )
        assert result.blocked is True

    def test_glob_warned_pattern(self, sample_config):
        result = check_file_restrictions(
            ["requirements-dev.txt"], sample_config
        )
        assert result.blocked is False
        assert "requirements-dev.txt" in result.warned_files

    def test_docker_compose_warned(self, sample_config):
        result = check_file_restrictions(
            ["docker-compose.override.yml"], sample_config
        )
        assert result.blocked is False
        assert "docker-compose.override.yml" in result.warned_files


# ---------------------------------------------------------------------------
# _enumerate_push_changed_files Tests
# ---------------------------------------------------------------------------


class TestEnumeratePushChangedFiles:
    """Tests for _enumerate_push_changed_files()."""

    def test_returns_file_list_on_success(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"src/main.py\nlib/utils.js\n"
        with patch("git_operations.subprocess.run", return_value=mock_result):
            files = _enumerate_push_changed_files("/repo", {}, "origin/main")
            assert files == ["src/main.py", "lib/utils.js"]

    def test_returns_none_on_failure(self):
        mock_result = MagicMock()
        mock_result.returncode = 128
        mock_result.stdout = b""
        with patch("git_operations.subprocess.run", return_value=mock_result):
            files = _enumerate_push_changed_files("/repo", {}, "origin/main")
            assert files is None

    def test_returns_empty_list_on_no_changes(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        with patch("git_operations.subprocess.run", return_value=mock_result):
            files = _enumerate_push_changed_files("/repo", {}, "origin/main")
            assert files == []

    def test_returns_none_on_timeout(self):
        with patch(
            "git_operations.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="git", timeout=10),
        ):
            files = _enumerate_push_changed_files("/repo", {}, "origin/main")
            assert files is None

    def test_returns_none_on_os_error(self):
        with patch(
            "git_operations.subprocess.run",
            side_effect=OSError("git not found"),
        ):
            files = _enumerate_push_changed_files("/repo", {}, "origin/main")
            assert files is None

    def test_ref_range_before_separator(self):
        """The revision range must come BEFORE '--' in the git diff command.

        If '--' comes first, git treats the range as a pathspec and silently
        returns empty output, bypassing file restrictions entirely.
        """
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"src/main.py\n"
        with patch(
            "git_operations.subprocess.run", return_value=mock_result
        ) as mock_run:
            _enumerate_push_changed_files("/repo", {}, "origin/main")
            cmd = mock_run.call_args[0][0]
            separator_idx = cmd.index("--")
            range_idx = cmd.index("origin/main..HEAD")
            assert range_idx < separator_idx, (
                f"Revision range (index {range_idx}) must come before "
                f"'--' separator (index {separator_idx}): {cmd}"
            )


# ---------------------------------------------------------------------------
# check_push_file_restrictions Integration Tests
# ---------------------------------------------------------------------------

BRANCH = "sandbox/test-branch"
META = {"sandbox_branch": BRANCH}


class TestCheckPushFileRestrictions:
    """Tests for check_push_file_restrictions()."""

    def _make_diff_result(self, files_str, returncode=0):
        result = MagicMock()
        result.returncode = returncode
        result.stdout = files_str.encode("utf-8")
        return result

    def test_blocked_workflow_file(self, config_file):
        """Push modifying .github/workflows/ci.yml is rejected."""
        diff_result = self._make_diff_result(".github/workflows/ci.yml\n")

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", META
            )
            assert err is not None
            assert "blocked" in err.reason.lower() or "Blocked" in err.reason

    def test_warned_file_logs(self, config_file):
        """Push modifying package.json passes with warn_action=log."""
        diff_result = self._make_diff_result("package.json\n")

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", META
            )
            assert err is None  # Not blocked, just warned

    def test_clean_files_pass(self, config_file):
        """Push modifying only src/ files is allowed."""
        diff_result = self._make_diff_result("src/main.py\nsrc/utils.py\n")

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", META
            )
            assert err is None

    def test_config_unavailable_fails_closed(self):
        """Push is blocked when config cannot be loaded."""
        with patch(
            "git_operations.get_file_restrictions_config",
            side_effect=ConfigError("file not found"),
        ):
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", META
            )
            assert err is not None
            assert "fail-closed" in err.reason

    def test_diff_failure_falls_back_to_default_branch(self, config_file):
        """When remote branch diff fails, falls back to default branch."""
        fail_result = self._make_diff_result("", returncode=128)
        ok_result = self._make_diff_result("src/main.py\n")

        call_count = 0

        def run_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return fail_result  # First diff fails (remote branch missing)
            return ok_result  # Fallback diff succeeds

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", side_effect=run_side_effect
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ), patch(
            "git_operations.resolve_bare_repo_path", return_value="/bare.git"
        ), patch(
            "git_operations._detect_default_branch", return_value="main"
        ):
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", META
            )
            assert err is None
            assert call_count == 2

    def test_both_diffs_fail_blocks(self, config_file):
        """When both diffs fail, push is blocked (fail-closed)."""
        fail_result = self._make_diff_result("", returncode=128)

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=fail_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ), patch(
            "git_operations.resolve_bare_repo_path", return_value="/bare.git"
        ), patch(
            "git_operations._detect_default_branch", return_value="main"
        ):
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", META
            )
            assert err is not None
            assert "fail-closed" in err.reason

    def test_no_changed_files_passes(self, config_file):
        """Push with no changed files passes."""
        diff_result = self._make_diff_result("")

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", META
            )
            assert err is None

    def test_path_traversal_blocked(self, config_file):
        """Push with path traversal is blocked."""
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
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", META
            )
            assert err is not None
            assert "Path traversal" in err.reason

    def test_from_branch_fallback_when_bare_repo_unavailable(self, config_file):
        """When bare repo is unavailable, from_branch metadata is used."""
        fail_result = self._make_diff_result("", returncode=128)
        ok_result = self._make_diff_result("src/main.py\n")

        call_count = 0

        def run_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                return fail_result  # Remote branch diff fails
            return ok_result  # from_branch diff succeeds

        meta = {**META, "from_branch": "main"}

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", side_effect=run_side_effect
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ), patch(
            "git_operations.resolve_bare_repo_path", return_value=None
        ):
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", meta
            )
            assert err is None
            assert call_count == 2

    def test_from_branch_fallback_after_default_branch_fallback_fails(
        self, config_file
    ):
        """All three fallbacks tried: remote, default branch, from_branch."""
        fail_result = self._make_diff_result("", returncode=128)
        ok_result = self._make_diff_result("src/main.py\n")

        call_count = 0

        def run_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return fail_result  # Remote + default branch fail
            return ok_result  # from_branch succeeds

        meta = {**META, "from_branch": "main"}

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", side_effect=run_side_effect
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ), patch(
            "git_operations.resolve_bare_repo_path", return_value="/bare.git"
        ), patch(
            "git_operations._detect_default_branch", return_value="main"
        ):
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", meta
            )
            assert err is None
            assert call_count == 3

    def test_all_fallbacks_fail_including_from_branch_blocks(self, config_file):
        """Fail-closed preserved when all fallbacks fail."""
        fail_result = self._make_diff_result("", returncode=128)

        meta = {**META, "from_branch": "main"}

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=fail_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ), patch(
            "git_operations.resolve_bare_repo_path", return_value="/bare.git"
        ), patch(
            "git_operations._detect_default_branch", return_value="main"
        ):
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", meta
            )
            assert err is not None
            assert "fail-closed" in err.reason

    def test_no_from_branch_in_metadata_still_blocks(self, config_file):
        """Backward compat: metadata without from_branch still fail-closes."""
        fail_result = self._make_diff_result("", returncode=128)

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=fail_result
        ), patch(
            "git_operations.build_clean_env", return_value={}
        ), patch(
            "git_operations.resolve_bare_repo_path", return_value=None
        ):
            err = check_push_file_restrictions(
                ["origin", BRANCH], "/repo", META
            )
            assert err is not None
            assert "fail-closed" in err.reason

    def test_explicit_refspec_uses_target(self, config_file):
        """Push with explicit refspec uses the target branch for diff."""
        diff_result = self._make_diff_result("src/main.py\n")

        with patch(
            "git_operations.get_file_restrictions_config",
            return_value=load_file_restrictions_config(config_file),
        ), patch(
            "git_operations.subprocess.run", return_value=diff_result
        ) as mock_run, patch(
            "git_operations.build_clean_env", return_value={}
        ):
            err = check_push_file_restrictions(
                ["origin", f"{BRANCH}:feature/target"],
                "/repo",
                META,
            )
            assert err is None
            # Should diff against origin/feature/target
            call_args = mock_run.call_args[0][0]
            assert "origin/feature/target..HEAD" in call_args


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
