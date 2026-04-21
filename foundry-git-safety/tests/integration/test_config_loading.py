"""Integration tests for configuration loading (foundry.yaml + push-file-restrictions.yaml).

Tests that config files are loaded, validated, and merged with defaults correctly.
"""

import pytest
import yaml

from foundry_git_safety.config import (
    ConfigError,
    FileRestrictionsData,
    check_file_restrictions,
    load_file_restrictions_config,
    load_foundry_config,
)
from foundry_git_safety.schemas.foundry_yaml import FoundryConfig


# ---------------------------------------------------------------------------
# TestFoundryYamlIntegration
# ---------------------------------------------------------------------------


class TestFoundryYamlIntegration:
    """End-to-end tests for loading foundry.yaml."""

    def test_load_complete_foundry_yaml(self, tmp_path):
        """A complete foundry.yaml file is parsed into a FoundryConfig."""
        config_data = {
            "version": "1.0",
            "git_safety": {
                "server": {
                    "host": "0.0.0.0",
                    "port": 9090,
                    "secrets_path": "/custom/secrets",
                    "data_dir": "/custom/data",
                },
                "protected_branches": {
                    "enabled": True,
                    "patterns": [
                        "refs/heads/main",
                        "refs/heads/release/*",
                    ],
                },
                "file_restrictions": {
                    "blocked_patterns": [".github/workflows/"],
                    "warned_patterns": ["package.json"],
                    "warn_action": "reject",
                },
                "branch_isolation": {
                    "enabled": True,
                },
                "rate_limits": {
                    "burst": 500,
                    "sustained": 200,
                    "global_ceiling": 2000,
                },
            },
        }

        config_path = tmp_path / "foundry.yaml"
        config_path.write_text(yaml.dump(config_data))

        config = load_foundry_config(str(config_path))

        assert isinstance(config, FoundryConfig)
        assert config.version == "1.0"
        assert config.git_safety.server.host == "0.0.0.0"
        assert config.git_safety.server.port == 9090
        assert config.git_safety.server.secrets_path == "/custom/secrets"
        assert config.git_safety.rate_limits.burst == 500
        assert config.git_safety.rate_limits.sustained == 200
        assert config.git_safety.file_restrictions.warn_action == "reject"

    def test_missing_file_returns_defaults(self, tmp_path):
        """When the config file does not exist, defaults are returned."""
        config = load_foundry_config(str(tmp_path / "nonexistent.yaml"))
        assert isinstance(config, FoundryConfig)
        assert config.version == "1.0"
        # Default server port
        assert config.git_safety.server.port == 8083
        # Default rate limits
        assert config.git_safety.rate_limits.burst == 300

    def test_partial_config_merges_with_defaults(self, tmp_path):
        """A partial config file merges with defaults for missing sections."""
        config_data = {
            "version": "1.0",
            "git_safety": {
                "rate_limits": {
                    "burst": 999,
                },
            },
        }

        config_path = tmp_path / "foundry.yaml"
        config_path.write_text(yaml.dump(config_data))

        config = load_foundry_config(str(config_path))
        # Custom value
        assert config.git_safety.rate_limits.burst == 999
        # Default value for unmodified field
        assert config.git_safety.rate_limits.sustained == 120
        assert config.git_safety.server.port == 8083

    def test_invalid_warn_action_raises(self, tmp_path):
        """An invalid warn_action value raises ConfigError."""
        config_data = {
            "version": "1.0",
            "git_safety": {
                "file_restrictions": {
                    "warn_action": "invalid",
                },
            },
        }

        config_path = tmp_path / "foundry.yaml"
        config_path.write_text(yaml.dump(config_data))

        with pytest.raises(ConfigError, match="Invalid foundry.yaml"):
            load_foundry_config(str(config_path))


# ---------------------------------------------------------------------------
# TestFileRestrictionsIntegration
# ---------------------------------------------------------------------------


class TestFileRestrictionsIntegration:
    """End-to-end tests for loading and applying push file restrictions."""

    def test_load_default_push_file_restrictions(self):
        """The default push-file-restrictions.yaml loads and validates."""
        config = load_file_restrictions_config()
        assert isinstance(config, FileRestrictionsData)
        assert ".github/workflows/" in config.blocked_patterns
        assert ".github/actions/" in config.blocked_patterns
        assert "package.json" in config.warned_patterns
        assert config.warn_action in ("log", "reject")

    def test_custom_config_overrides_defaults(self, tmp_path):
        """A custom push-file-restrictions.yaml overrides default patterns."""
        custom_data = {
            "blocked_patterns": ["secrets/", "*.pem"],
            "warned_patterns": ["docker-compose*.yml"],
            "warn_action": "log",
        }

        config_path = tmp_path / "push-file-restrictions.yaml"
        config_path.write_text(yaml.dump(custom_data))

        config = load_file_restrictions_config(str(config_path))

        assert config.blocked_patterns == ["secrets/", "*.pem"]
        assert config.warned_patterns == ["docker-compose*.yml"]
        assert config.warn_action == "log"

    def test_missing_required_field_raises(self, tmp_path):
        """A config file missing required fields raises ConfigError."""
        bad_data = {
            "blocked_patterns": ["*.pem"],
            # Missing warned_patterns and warn_action
        }

        config_path = tmp_path / "push-file-restrictions.yaml"
        config_path.write_text(yaml.dump(bad_data))

        with pytest.raises(ConfigError, match="Missing required fields"):
            load_file_restrictions_config(str(config_path))

    def test_check_file_restrictions_blocks_github_workflows(self):
        """Files under .github/workflows/ are blocked by default config."""
        config = load_file_restrictions_config()
        result = check_file_restrictions(
            [".github/workflows/ci.yml", "src/main.py"],
            config,
        )
        assert result.blocked is True
        assert ".github/workflows/ci.yml" in result.reason

    def test_check_file_restrictions_warns_on_package_json(self):
        """package.json is warned (not blocked) when warn_action is 'log'."""
        custom_config = FileRestrictionsData(
            blocked_patterns=[".github/workflows/"],
            warned_patterns=["package.json"],
            warn_action="log",
        )
        result = check_file_restrictions(["package.json"], custom_config)
        assert result.blocked is False
        assert "package.json" in result.warned_files

    def test_check_file_restrictions_rejects_warned_when_action_reject(self):
        """Warned files are rejected when warn_action is 'reject'."""
        config = FileRestrictionsData(
            blocked_patterns=[],
            warned_patterns=["package.json"],
            warn_action="reject",
        )
        result = check_file_restrictions(["package.json"], config)
        assert result.blocked is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
