"""Unit tests for foundry_sandbox.foundry_config — Phase 1 schema, resolver, merge."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from foundry_sandbox.foundry_config import (
    ClaudeCodeConfig,
    FileRestrictionsAdd,
    FoundryConfig,
    GitSafetyOverlay,
    HookRule,
    McpServerBuiltin,
    McpServerNpm,
    ProtectedBranchesAdd,
    SkillSource,
    UserService,
    _merge,
    render_plan_text,
    resolve_foundry_config,
)


# ---------------------------------------------------------------------------
# Strict mode
# ---------------------------------------------------------------------------


class TestStrictMode:
    def test_strict_mode_rejects_unknown_keys(self):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            FoundryConfig(version="1", unknown=1)

    def test_strict_mode_on_overlay(self):
        with pytest.raises(ValidationError):
            GitSafetyOverlay(unknown_field=True)

    def test_strict_mode_on_mcp_server(self):
        with pytest.raises(ValidationError):
            McpServerBuiltin(name="x", type="builtin", surprise=True)

    def test_strict_mode_on_user_service(self):
        with pytest.raises(ValidationError):
            UserService(name="x", env_var="K", domain="d", extra=True)


# ---------------------------------------------------------------------------
# Version mismatch
# ---------------------------------------------------------------------------


class TestVersionMismatch:
    def test_version_mismatch_raises(self):
        a = FoundryConfig(version="1")
        b = FoundryConfig(version="1")
        # Same version is fine
        result = _merge([a, b])
        assert result.version == "1"


# ---------------------------------------------------------------------------
# Merge: lists concatenate
# ---------------------------------------------------------------------------


class TestMergeLists:
    def test_merge_lists_concatenate(self):
        a = FoundryConfig(
            version="1",
            mcp_servers=[McpServerBuiltin(name="github", type="builtin")],
        )
        b = FoundryConfig(
            version="1",
            mcp_servers=[McpServerBuiltin(name="filesystem", type="builtin")],
        )
        result = _merge([a, b])
        assert len(result.mcp_servers) == 2
        assert result.mcp_servers[0].name == "github"
        assert result.mcp_servers[1].name == "filesystem"

    def test_merge_user_services(self):
        a = FoundryConfig(
            version="1",
            user_services=[UserService(name="svc1", env_var="K1", domain="d1")],
        )
        b = FoundryConfig(
            version="1",
            user_services=[UserService(name="svc2", env_var="K2", domain="d2")],
        )
        result = _merge([a, b])
        assert len(result.user_services) == 2

    def test_merge_empty_lists(self):
        a = FoundryConfig(version="1")
        result = _merge([a])
        assert result.mcp_servers == []
        assert result.user_services == []


# ---------------------------------------------------------------------------
# Merge: allow flags ANDed
# ---------------------------------------------------------------------------


class TestMergeAllowFlags:
    def test_merge_allow_flags_anded(self):
        a = FoundryConfig(version="1", allow_third_party_mcp=False)
        b = FoundryConfig(version="1", allow_third_party_mcp=True)
        result = _merge([a, b])
        assert result.allow_third_party_mcp is False

    def test_both_true_stays_true(self):
        a = FoundryConfig(version="1", allow_third_party_mcp=True)
        b = FoundryConfig(version="1", allow_third_party_mcp=True)
        result = _merge([a, b])
        assert result.allow_third_party_mcp is True

    def test_both_false_stays_false(self):
        a = FoundryConfig(version="1", allow_third_party_mcp=False)
        b = FoundryConfig(version="1", allow_third_party_mcp=False)
        result = _merge([a, b])
        assert result.allow_third_party_mcp is False


# ---------------------------------------------------------------------------
# Third-party MCP gate
# ---------------------------------------------------------------------------


class TestThirdPartyMcpGate:
    def test_third_party_mcp_gate(self):
        with pytest.raises(ValidationError, match="type=npm"):
            FoundryConfig(
                version="1",
                mcp_servers=[McpServerNpm(name="evil", type="npm", package="evil-pkg")],
                allow_third_party_mcp=False,
            )

    def test_npm_allowed_when_flag_set(self):
        cfg = FoundryConfig(
            version="1",
            mcp_servers=[McpServerNpm(name="ok", type="npm", package="ok-pkg")],
            allow_third_party_mcp=True,
        )
        assert cfg.mcp_servers[0].name == "ok"


# ---------------------------------------------------------------------------
# Missing layers
# ---------------------------------------------------------------------------


class TestMissingLayers:
    def test_missing_layers_returns_defaults(self, tmp_path: Path):
        config = resolve_foundry_config(tmp_path)
        assert config.version == "1"
        assert config.mcp_servers == []
        assert config.user_services == []
        assert config.git_safety is None
        assert config.claude_code is None
        assert config.allow_third_party_mcp is False


# ---------------------------------------------------------------------------
# Additive-only structural check
# ---------------------------------------------------------------------------


class TestAdditiveOnlyStructural:
    _OVERLAY_MODELS = [
        GitSafetyOverlay,
        ProtectedBranchesAdd,
        FileRestrictionsAdd,
    ]

    def test_additive_only_structural(self):
        for model_cls in self._OVERLAY_MODELS:
            fields = set(model_cls.model_fields.keys())
            forbidden = {f for f in fields if "remove" in f.lower() or "replace" in f.lower()}
            assert not forbidden, (
                f"{model_cls.__name__} has non-additive fields: {forbidden}"
            )


# ---------------------------------------------------------------------------
# Resolver with real files
# ---------------------------------------------------------------------------


class TestResolver:
    def test_repo_layer_loaded(self, tmp_path: Path):
        (tmp_path / "foundry.yaml").write_text(
            'version: "1"\n'
            "git_safety:\n"
            "  protected_branches:\n"
            '    add: ["refs/heads/staging"]\n'
        )
        config = resolve_foundry_config(tmp_path)
        assert config.git_safety is not None
        assert config.git_safety.protected_branches is not None
        assert "refs/heads/staging" in config.git_safety.protected_branches.add

    def test_invalid_yaml_returns_default(self, tmp_path: Path):
        (tmp_path / "foundry.yaml").write_text("{{invalid")
        config = resolve_foundry_config(tmp_path)
        assert config.version == "1"
        assert config.git_safety is None

    def test_invalid_schema_returns_none(self, tmp_path: Path):
        (tmp_path / "foundry.yaml").write_text('version: "1"\nunknown_key: true')
        config = resolve_foundry_config(tmp_path)
        assert config.version == "1"


# ---------------------------------------------------------------------------
# Plan renderer
# ---------------------------------------------------------------------------


class TestRenderPlanText:
    def test_renders_minimal(self):
        config = FoundryConfig(version="1")
        text = render_plan_text(config)
        assert "allow_third_party_mcp: false" in text
        assert "policy_patches (0):" in text

    def test_renders_with_overlay(self):
        config = FoundryConfig(
            version="1",
            git_safety=GitSafetyOverlay(
                protected_branches=ProtectedBranchesAdd(add=["refs/heads/staging"]),
                file_restrictions=FileRestrictionsAdd(blocked_patterns_add=["db/migrations/"]),
            ),
        )
        text = render_plan_text(config)
        assert "refs/heads/staging" in text
        assert "db/migrations/" in text
        assert "policy_patches (2):" in text


# ---------------------------------------------------------------------------
# Claude Code merge
# ---------------------------------------------------------------------------


class TestClaudeCodeMerge:
    def test_hooks_merge_per_key(self):
        a = FoundryConfig(
            version="1",
            claude_code=ClaudeCodeConfig(
                hooks={"pre-commit": [HookRule(match="*.py", command="ruff check")]},
            ),
        )
        b = FoundryConfig(
            version="1",
            claude_code=ClaudeCodeConfig(
                hooks={"pre-commit": [HookRule(match="*.ts", command="eslint")]},
            ),
        )
        result = _merge([a, b])
        assert result.claude_code is not None
        assert len(result.claude_code.hooks["pre-commit"]) == 2

    def test_skills_concatenate(self):
        a = FoundryConfig(
            version="1",
            claude_code=ClaudeCodeConfig(skills=[SkillSource(source="/a")]),
        )
        b = FoundryConfig(
            version="1",
            claude_code=ClaudeCodeConfig(skills=[SkillSource(source="/b")]),
        )
        result = _merge([a, b])
        assert len(result.claude_code.skills) == 2
