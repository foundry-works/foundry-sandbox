"""Tests for foundry_git_safety.schemas.foundry_yaml."""

import pytest
from pydantic import ValidationError

from foundry_git_safety.schemas.foundry_yaml import (
    BranchIsolationConfig,
    FileRestrictionsConfig,
    FoundryConfig,
    GitHubAPIConfig,
    GitSafetyConfig,
    GitSafetyServerConfig,
    ProtectedBranchesConfig,
    RateLimitsConfig,
)


class TestGitSafetyServerConfig:
    def test_defaults(self):
        cfg = GitSafetyServerConfig()
        assert cfg.host == "127.0.0.1"
        assert cfg.port == 8083
        assert cfg.secrets_path == "/run/secrets/sandbox-hmac"

    def test_port_validation_rejects_zero(self):
        with pytest.raises(ValidationError):
            GitSafetyServerConfig(port=0)

    def test_port_validation_rejects_65536(self):
        with pytest.raises(ValidationError):
            GitSafetyServerConfig(port=65536)

    def test_port_accepts_valid(self):
        cfg = GitSafetyServerConfig(port=8080)
        assert cfg.port == 8080


class TestProtectedBranchesConfig:
    def test_defaults(self):
        cfg = ProtectedBranchesConfig()
        assert cfg.enabled is True
        assert "refs/heads/main" in cfg.patterns

    def test_custom_patterns(self):
        cfg = ProtectedBranchesConfig(patterns=["refs/heads/custom/*"])
        assert cfg.patterns == ["refs/heads/custom/*"]


class TestFileRestrictionsConfig:
    def test_defaults(self):
        cfg = FileRestrictionsConfig()
        assert cfg.warn_action == "reject"
        assert len(cfg.blocked_patterns) > 0

    def test_warn_action_validation_rejects_invalid(self):
        with pytest.raises(ValidationError):
            FileRestrictionsConfig(warn_action="invalid")

    def test_warn_action_accepts_reject(self):
        cfg = FileRestrictionsConfig(warn_action="reject")
        assert cfg.warn_action == "reject"


class TestBranchIsolationConfig:
    def test_defaults(self):
        cfg = BranchIsolationConfig()
        assert cfg.enabled is True
        assert "main" in cfg.well_known_branches
        assert "release/" in cfg.well_known_prefixes


class TestGitHubAPIConfig:
    def test_defaults(self):
        cfg = GitHubAPIConfig()
        assert cfg.enabled is True
        assert cfg.proxy_port == 8084
        assert cfg.allow_pr_operations is False

    def test_proxy_port_validation(self):
        with pytest.raises(ValidationError):
            GitHubAPIConfig(proxy_port=0)


class TestRateLimitsConfig:
    def test_defaults(self):
        cfg = RateLimitsConfig()
        assert cfg.burst == 300
        assert cfg.sustained == 120
        assert cfg.global_ceiling == 1000


class TestGitSafetyConfig:
    def test_nested_defaults(self):
        cfg = GitSafetyConfig()
        assert isinstance(cfg.server, GitSafetyServerConfig)
        assert isinstance(cfg.protected_branches, ProtectedBranchesConfig)
        assert isinstance(cfg.file_restrictions, FileRestrictionsConfig)

    def test_partial_override(self):
        cfg = GitSafetyConfig(server=GitSafetyServerConfig(port=9999))
        assert cfg.server.port == 9999
        assert cfg.protected_branches.enabled is True  # default


class TestFoundryConfig:
    def test_defaults(self):
        cfg = FoundryConfig()
        assert cfg.version == "1.0"
        assert isinstance(cfg.git_safety, GitSafetyConfig)

    def test_override(self):
        cfg = FoundryConfig(version="2.0")
        assert cfg.version == "2.0"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
