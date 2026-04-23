"""Unit tests for foundry_sandbox.models domain models.

Tests construction, validation, defaults, .model_dump(), and JSON round-trip
for all Pydantic models.
"""
from __future__ import annotations


import pytest

from pydantic import ValidationError

from foundry_sandbox.models import (
    CastNewPreset,
    SbxSandboxMetadata,
)


# ---------------------------------------------------------------------------
# SbxSandboxMetadata
# ---------------------------------------------------------------------------


class TestSbxSandboxMetadata:
    """SbxSandboxMetadata construction, validation, defaults, and serialization."""

    def test_minimal_construction(self):
        meta = SbxSandboxMetadata(
            sbx_name="test-sandbox",
            agent="claude",
            repo_url="https://github.com/org/repo",
            branch="main",
        )
        assert meta.sbx_name == "test-sandbox"
        assert meta.agent == "claude"
        assert meta.git_safety_enabled is True
        assert meta.copies == []

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            SbxSandboxMetadata()

    def test_missing_sbx_name(self):
        with pytest.raises(ValidationError):
            SbxSandboxMetadata(agent="claude", repo_url="u", branch="b")

    def test_missing_agent(self):
        with pytest.raises(ValidationError):
            SbxSandboxMetadata(sbx_name="test", repo_url="u", branch="b")

    def test_full_construction(self):
        meta = SbxSandboxMetadata(
            sbx_name="test",
            agent="codex",
            repo_url="https://github.com/org/repo",
            branch="feature-x",
            from_branch="main",
            git_safety_enabled=False,
            working_dir="src",
            pip_requirements="requirements.txt",
            allow_pr=True,
            enable_opencode=True,
            enable_zai=True,
            copies=["/host/path:/container/path"],
        )
        assert meta.agent == "codex"
        assert meta.git_safety_enabled is False
        assert meta.copies == ["/host/path:/container/path"]

    def test_model_dump_roundtrip(self):
        meta = SbxSandboxMetadata(
            sbx_name="test",
            agent="claude",
            repo_url="u",
            branch="b",
            allow_pr=True,
        )
        data = meta.model_dump()
        restored = SbxSandboxMetadata(**data)
        assert restored == meta

    def test_json_roundtrip(self):
        meta = SbxSandboxMetadata(
            sbx_name="test",
            agent="gemini",
            repo_url="https://github.com/org/repo",
            branch="main",
            copies=["/a:/b", "/c:/d"],
        )
        json_str = meta.model_dump_json()
        restored = SbxSandboxMetadata.model_validate_json(json_str)
        assert restored == meta

    def test_wrapper_checksum_roundtrip(self):
        meta = SbxSandboxMetadata(
            sbx_name="test",
            agent="claude",
            repo_url="u",
            branch="b",
            wrapper_checksum="abc123def456",
            wrapper_last_verified="2026-04-20T12:00:00Z",
        )
        data = meta.model_dump()
        restored = SbxSandboxMetadata(**data)
        assert restored.wrapper_checksum == "abc123def456"
        assert restored.wrapper_last_verified == "2026-04-20T12:00:00Z"

    def test_defaults(self):
        meta = SbxSandboxMetadata(
            sbx_name="test",
            agent="claude",
            repo_url="u",
            branch="b",
        )
        assert meta.from_branch == ""
        assert meta.git_safety_enabled is True
        assert meta.workspace_dir == "/workspace"
        assert meta.working_dir == ""
        assert meta.pip_requirements == ""
        assert meta.allow_pr is False
        assert meta.enable_opencode is False
        assert meta.enable_zai is False
        assert meta.copies == []
        assert meta.user_services == {}
        assert meta.wrapper_checksum == ""
        assert meta.wrapper_last_verified == ""
        assert meta.template_managed is False

    def test_template_managed_roundtrip(self):
        meta = SbxSandboxMetadata(
            sbx_name="test",
            agent="claude",
            repo_url="u",
            branch="b",
            template="preset-my-setup:latest",
            template_managed=True,
        )
        data = meta.model_dump()
        restored = SbxSandboxMetadata(**data)
        assert restored.template == "preset-my-setup:latest"
        assert restored.template_managed is True


# ---------------------------------------------------------------------------
# CastNewPreset
# ---------------------------------------------------------------------------


class TestCastNewPreset:
    """CastNewPreset construction, defaults, and serialization."""

    def test_minimal_construction(self):
        preset = CastNewPreset(repo="org/repo")
        assert preset.repo == "org/repo"
        assert preset.agent == "claude"
        assert preset.copies == []

    def test_full_construction(self):
        preset = CastNewPreset(
            repo="org/repo",
            agent="codex",
            branch="main",
            from_branch="develop",
            working_dir="src",
            pip_requirements="requirements.txt",
            allow_pr=True,
            enable_opencode=True,
            enable_zai=True,
            copies=["/src:/dst"],
        )
        assert preset.agent == "codex"
        assert preset.allow_pr is True
        assert preset.copies == ["/src:/dst"]

    def test_model_dump_roundtrip(self):
        preset = CastNewPreset(repo="org/repo", branch="main", allow_pr=True)
        data = preset.model_dump()
        restored = CastNewPreset(**data)
        assert restored == preset

    def test_json_roundtrip(self):
        preset = CastNewPreset(repo="org/repo", copies=["/a:/b", "/c:/d"])
        json_str = preset.model_dump_json()
        restored = CastNewPreset.model_validate_json(json_str)
        assert restored == preset

    def test_defaults_are_correct(self):
        preset = CastNewPreset(repo="x")
        dump = preset.model_dump()
        assert dump["allow_pr"] is False
        assert dump["enable_opencode"] is False
        assert dump["enable_zai"] is False
        assert dump["agent"] == "claude"
        assert dump["template"] == ""
        assert dump["template_managed"] is False

    def test_template_fields_roundtrip(self):
        preset = CastNewPreset(
            repo="org/repo",
            template="preset-my-setup:latest",
            template_managed=True,
        )
        data = preset.model_dump()
        restored = CastNewPreset(**data)
        assert restored.template == "preset-my-setup:latest"
        assert restored.template_managed is True

    def test_missing_repo_raises_validation_error(self):
        with pytest.raises(ValidationError):
            CastNewPreset()


# ---------------------------------------------------------------------------
# Validation Edge Cases
# ---------------------------------------------------------------------------


class TestModelEdgeCases:
    """Edge case and special character tests for all models."""

    def test_cast_new_preset_special_chars_in_repo(self):
        preset = CastNewPreset(repo="org/repo-name.with" + "dots")
        assert "." in preset.repo

    def test_cast_new_preset_long_string(self):
        long_repo = "org/" + "x" * 500
        preset = CastNewPreset(repo=long_repo)
        assert len(preset.repo) > 500

    def test_sbx_metadata_special_chars(self):
        meta = SbxSandboxMetadata(
            sbx_name="test",
            agent="claude",
            repo_url="https://github.com/org/repo?foo=bar&baz=qux",
            branch="feature/my-branch",
        )
        assert "?" in meta.repo_url
        assert "/" in meta.branch

    def test_cast_new_preset_ide_default(self):
        preset = CastNewPreset(repo="org/repo")
        assert preset.ide == ""

    def test_cast_new_preset_ide_explicit(self):
        preset = CastNewPreset(repo="org/repo", ide="cursor")
        assert preset.ide == "cursor"

    def test_sbx_metadata_ide_default(self):
        meta = SbxSandboxMetadata(
            sbx_name="test",
            agent="claude",
            repo_url="https://github.com/org/repo",
            branch="main",
        )
        assert meta.ide == ""

    def test_sbx_metadata_ide_explicit(self):
        meta = SbxSandboxMetadata(
            sbx_name="test",
            agent="claude",
            repo_url="https://github.com/org/repo",
            branch="main",
            ide="zed",
        )
        assert meta.ide == "zed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
