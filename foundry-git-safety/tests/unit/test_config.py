"""Tests for foundry_git_safety.config — pattern matching, file restrictions, and config loading."""

import os
from unittest.mock import patch

import pytest
import yaml

from foundry_git_safety.config import (
    ConfigError,
    FileRestrictionsData,
    check_file_restrictions,
    load_file_restrictions_config,
    load_foundry_config,
    matches_any,
)


# ---------------------------------------------------------------------------
# TestMatchesAny
# ---------------------------------------------------------------------------


class TestMatchesAny:
    """Tests for matches_any() pattern matching logic."""

    def test_directory_prefix_match(self):
        """Pattern ending in '/' matches any file under that directory."""
        assert matches_any(".github/workflows/ci.yml", [".github/workflows/"]) is True

    def test_directory_prefix_no_match_different_dir(self):
        """Pattern ending in '/' does not match files outside that directory."""
        assert matches_any("src/main.py", [".github/workflows/"]) is False

    def test_glob_match_on_basename(self):
        """Glob pattern matches against both basename and full path."""
        assert matches_any("app/.env.production", [".env*"]) is True

    def test_glob_match_on_full_path(self):
        """Glob pattern with path separator matches full path."""
        assert matches_any("src/test_module.py", ["test_*.py"]) is True

    def test_glob_question_mark(self):
        """Glob '?' matches a single character."""
        assert matches_any("file_a.txt", ["file_?.txt"]) is True

    def test_basename_match(self):
        """Bare pattern (no slash, no glob) matches by basename."""
        assert matches_any("subdir/Makefile", ["Makefile"]) is True

    def test_basename_no_match(self):
        """Bare pattern does not match unrelated file."""
        assert matches_any("src/main.py", ["Makefile"]) is False

    def test_empty_patterns(self):
        """Empty pattern list matches nothing."""
        assert matches_any("any/file.txt", []) is False

    def test_multiple_patterns_first_match(self):
        """Returns True when the first pattern matches."""
        assert matches_any("Makefile", ["Makefile", "*.go"]) is True

    def test_multiple_patterns_later_match(self):
        """Returns True when a later pattern matches."""
        assert matches_any("main.go", ["Makefile", "*.go"]) is True


# ---------------------------------------------------------------------------
# TestCheckFileRestrictions
# ---------------------------------------------------------------------------


class TestCheckFileRestrictions:
    """Tests for check_file_restrictions() validation logic."""

    def _make_config(self, **overrides):
        defaults = {
            "blocked_patterns": [".github/workflows/", "Makefile"],
            "warned_patterns": ["pyproject.toml"],
            "warn_action": "log",
        }
        defaults.update(overrides)
        return FileRestrictionsData(**defaults)

    def test_blocked_file_triggers_block(self):
        """A file matching blocked_patterns produces blocked=True."""
        config = self._make_config()
        result = check_file_restrictions([".github/workflows/ci.yml"], config)
        assert result.blocked is True
        assert "blocked" in result.reason.lower()

    def test_blocked_basename_triggers_block(self):
        """Bare blocked pattern matches by basename."""
        config = self._make_config()
        result = check_file_restrictions(["src/Makefile"], config)
        assert result.blocked is True

    def test_warned_file_with_reject_triggers_block(self):
        """When warn_action='reject', warned files are treated as blocked."""
        config = self._make_config(warn_action="reject")
        result = check_file_restrictions(["pyproject.toml"], config)
        assert result.blocked is True
        assert "restricted" in result.reason.lower()

    def test_warned_file_with_log_warns_but_allows(self):
        """When warn_action='log', warned files are allowed with a warning."""
        config = self._make_config(warn_action="log")
        result = check_file_restrictions(["pyproject.toml"], config)
        assert result.blocked is False
        assert "pyproject.toml" in result.warned_files

    def test_clean_files_pass(self):
        """Files not matching any pattern pass cleanly."""
        config = self._make_config()
        result = check_file_restrictions(["src/main.py", "README.md"], config)
        assert result.blocked is False
        assert result.warned_files == []

    def test_mixed_blocked_and_warned_reports_blocked(self):
        """When both blocked and warned files are present, blocked takes priority."""
        config = self._make_config(warn_action="log")
        result = check_file_restrictions(
            ["Makefile", "pyproject.toml"], config
        )
        assert result.blocked is True
        assert "Makefile" in result.reason

    def test_path_traversal_detected(self):
        """Paths with '..' components are blocked as path traversal."""
        config = self._make_config()
        result = check_file_restrictions(["../etc/passwd"], config)
        assert result.blocked is True
        assert "traversal" in result.reason.lower()

    def test_dot_slash_prefix_normalized(self):
        """Leading './' is stripped from paths during normalization."""
        config = self._make_config()
        result = check_file_restrictions(["./src/main.py"], config)
        assert result.blocked is False

    def test_empty_file_list_passes(self):
        """Empty changed_files list passes with no block."""
        config = self._make_config()
        result = check_file_restrictions([], config)
        assert result.blocked is False
        assert result.warned_files == []


# ---------------------------------------------------------------------------
# TestFileRestrictionsData
# ---------------------------------------------------------------------------


class TestFileRestrictionsData:
    """Tests for FileRestrictionsData validation."""

    def test_valid_construction(self):
        """Valid arguments produce a correct dataclass instance."""
        frd = FileRestrictionsData(
            blocked_patterns=["a"], warned_patterns=["b"], warn_action="log"
        )
        assert frd.blocked_patterns == ["a"]
        assert frd.warned_patterns == ["b"]
        assert frd.warn_action == "log"

    def test_invalid_blocked_patterns_type_raises(self):
        """Non-list blocked_patterns raises ConfigError."""
        with pytest.raises(ConfigError, match="blocked_patterns must be a list"):
            FileRestrictionsData(
                blocked_patterns="not-a-list", warned_patterns=[], warn_action="log"
            )

    def test_invalid_warned_patterns_type_raises(self):
        """Non-list warned_patterns raises ConfigError."""
        with pytest.raises(ConfigError, match="warned_patterns must be a list"):
            FileRestrictionsData(
                blocked_patterns=[], warned_patterns=42, warn_action="log"
            )

    def test_invalid_warn_action_raises(self):
        """Invalid warn_action value raises ConfigError."""
        with pytest.raises(ConfigError, match="warn_action must be"):
            FileRestrictionsData(
                blocked_patterns=[], warned_patterns=[], warn_action="delete"
            )


# ---------------------------------------------------------------------------
# TestLoadFoundryConfig
# ---------------------------------------------------------------------------


class TestLoadFoundryConfig:
    """Tests for load_foundry_config() loading and defaults."""

    def test_missing_file_returns_defaults(self, tmp_path):
        """When the file does not exist, returns a FoundryConfig with defaults."""
        config = load_foundry_config(str(tmp_path / "nonexistent.yaml"))
        assert config.version == "1.0"
        assert config.git_safety.server.host == "127.0.0.1"
        assert config.git_safety.server.port == 8083

    def test_valid_yaml_loads_correctly(self, tmp_path):
        """A valid foundry.yaml is parsed into a FoundryConfig."""
        yaml_content = {
            "version": "1.0",
            "git_safety": {
                "server": {"host": "0.0.0.0", "port": 9999},
            },
        }
        yaml_file = tmp_path / "foundry.yaml"
        yaml_file.write_text(yaml.dump(yaml_content))
        config = load_foundry_config(str(yaml_file))
        assert config.git_safety.server.host == "0.0.0.0"
        assert config.git_safety.server.port == 9999

    def test_env_var_path_used_when_no_arg(self, tmp_path):
        """FOUNDRY_CONFIG_PATH env var is used when path is not provided."""
        yaml_content = {"version": "1.0"}
        yaml_file = tmp_path / "custom.yaml"
        yaml_file.write_text(yaml.dump(yaml_content))
        with patch.dict(os.environ, {"FOUNDRY_CONFIG_PATH": str(yaml_file)}):
            config = load_foundry_config()
        assert config.version == "1.0"

    def test_invalid_yaml_raises_config_error(self, tmp_path):
        """Malformed YAML raises ConfigError."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{{{invalid yaml::::")
        with pytest.raises(ConfigError, match="Failed to parse"):
            load_foundry_config(str(bad_file))

    def test_non_dict_yaml_raises_config_error(self, tmp_path):
        """YAML that parses to a non-dict (e.g. a list) raises ConfigError."""
        list_file = tmp_path / "list.yaml"
        list_file.write_text("- item1\n- item2\n")
        with pytest.raises(ConfigError, match="expected YAML dictionary"):
            load_foundry_config(str(list_file))


# ---------------------------------------------------------------------------
# TestLoadFileRestrictionsConfig
# ---------------------------------------------------------------------------


class TestLoadFileRestrictionsConfig:
    """Tests for load_file_restrictions_config() loading."""

    def _write_config(self, tmp_path, **overrides):
        data = {
            "blocked_patterns": [".github/workflows/"],
            "warned_patterns": ["pyproject.toml"],
            "warn_action": "log",
        }
        data.update(overrides)
        path = tmp_path / "restrictions.yaml"
        path.write_text(yaml.dump(data))
        return str(path)

    def test_loads_from_file(self, tmp_path):
        """Loads a well-formed restrictions YAML file."""
        path = self._write_config(tmp_path)
        result = load_file_restrictions_config(path)
        assert isinstance(result, FileRestrictionsData)
        assert result.blocked_patterns == [".github/workflows/"]
        assert result.warned_patterns == ["pyproject.toml"]
        assert result.warn_action == "log"

    def test_missing_file_raises_config_error(self, tmp_path):
        """Non-existent file raises ConfigError."""
        with pytest.raises(ConfigError, match="not found"):
            load_file_restrictions_config(str(tmp_path / "nope.yaml"))

    def test_missing_required_field_raises(self, tmp_path):
        """YAML missing a required field raises ConfigError."""
        path = tmp_path / "incomplete.yaml"
        path.write_text(yaml.dump({"blocked_patterns": []}))
        with pytest.raises(ConfigError, match="Missing required fields"):
            load_file_restrictions_config(str(path))

    def test_non_list_blocked_patterns_raises(self, tmp_path):
        """blocked_patterns as a non-list raises ConfigError."""
        path = tmp_path / "bad.yaml"
        path.write_text(yaml.dump({
            "blocked_patterns": "not-a-list",
            "warned_patterns": [],
            "warn_action": "log",
        }))
        with pytest.raises(ConfigError, match="blocked_patterns must be a list"):
            load_file_restrictions_config(str(path))

    def test_non_list_warned_patterns_raises(self, tmp_path):
        """warned_patterns as a non-list raises ConfigError."""
        path = tmp_path / "bad_warned.yaml"
        path.write_text(yaml.dump({
            "blocked_patterns": [],
            "warned_patterns": 123,
            "warn_action": "log",
        }))
        with pytest.raises(ConfigError, match="warned_patterns must be a list"):
            load_file_restrictions_config(str(path))

    def test_coerces_pattern_values_to_strings(self, tmp_path):
        """Numeric pattern values are coerced to strings."""
        path = tmp_path / "numeric.yaml"
        path.write_text(yaml.dump({
            "blocked_patterns": [42],
            "warned_patterns": [7],
            "warn_action": "log",
        }))
        result = load_file_restrictions_config(str(path))
        assert result.blocked_patterns == ["42"]
        assert result.warned_patterns == ["7"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
