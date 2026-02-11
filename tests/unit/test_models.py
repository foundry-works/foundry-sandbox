"""Unit tests for foundry_sandbox.models domain models.

Tests construction, validation, defaults, .model_dump(), JSON round-trip,
and .to_env_dict() for all Pydantic models.
"""
from __future__ import annotations


import pytest

from foundry_sandbox.models import (
    CastNewPreset,
    CredentialPlaceholders,
    ProxyRegistration,
)


# ---------------------------------------------------------------------------
# CastNewPreset
# ---------------------------------------------------------------------------


class TestCastNewPreset:
    """CastNewPreset construction, defaults, and serialization."""

    def test_minimal_construction(self):
        preset = CastNewPreset(repo="org/repo")
        assert preset.repo == "org/repo"
        assert preset.branch == ""
        assert preset.network_mode == "limited"
        assert preset.mounts == []
        assert preset.copies == []

    def test_full_construction(self):
        preset = CastNewPreset(
            repo="org/repo",
            branch="main",
            from_branch="develop",
            working_dir="src",
            sparse=True,
            pip_requirements="requirements.txt",
            allow_pr=True,
            network_mode="host-only",
            sync_ssh=True,
            enable_opencode=True,
            enable_zai=True,
            mounts=["/host:/container"],
            copies=["/src:/dst"],
        )
        assert preset.sparse is True
        assert preset.allow_pr is True
        assert preset.mounts == ["/host:/container"]

    def test_model_dump_roundtrip(self):
        preset = CastNewPreset(repo="org/repo", branch="main", allow_pr=True)
        data = preset.model_dump()
        restored = CastNewPreset(**data)
        assert restored == preset

    def test_json_roundtrip(self):
        preset = CastNewPreset(repo="org/repo", mounts=["/a:/b", "/c:/d"])
        json_str = preset.model_dump_json()
        restored = CastNewPreset.model_validate_json(json_str)
        assert restored == preset

    def test_defaults_are_correct(self):
        preset = CastNewPreset(repo="x")
        dump = preset.model_dump()
        assert dump["sparse"] is False
        assert dump["allow_pr"] is False
        assert dump["sync_ssh"] is False
        assert dump["enable_opencode"] is False
        assert dump["enable_zai"] is False
        assert dump["network_mode"] == "limited"

    def test_missing_repo_raises(self):
        with pytest.raises(Exception):
            CastNewPreset()


# ---------------------------------------------------------------------------
# ProxyRegistration
# ---------------------------------------------------------------------------


class TestProxyRegistration:
    """ProxyRegistration construction and serialization."""

    def test_minimal_construction(self):
        reg = ProxyRegistration()
        assert reg.repo == ""
        assert reg.allow_pr is False
        assert reg.sandbox_branch == ""
        assert reg.from_branch == ""

    def test_full_construction(self):
        reg = ProxyRegistration(
            repo="org/repo",
            allow_pr=True,
            sandbox_branch="feature-x",
            from_branch="main",
        )
        assert reg.repo == "org/repo"
        assert reg.allow_pr is True

    def test_model_dump(self):
        reg = ProxyRegistration(repo="org/repo", allow_pr=True)
        data = reg.model_dump()
        assert data == {
            "repo": "org/repo",
            "allow_pr": True,
            "sandbox_branch": "",
            "from_branch": "",
        }

    def test_json_roundtrip(self):
        reg = ProxyRegistration(repo="a/b", sandbox_branch="dev")
        json_str = reg.model_dump_json()
        restored = ProxyRegistration.model_validate_json(json_str)
        assert restored == reg


# ---------------------------------------------------------------------------
# CredentialPlaceholders
# ---------------------------------------------------------------------------


class TestCredentialPlaceholders:
    """CredentialPlaceholders construction, to_env_dict, serialization."""

    def test_defaults(self):
        creds = CredentialPlaceholders()
        assert creds.sandbox_anthropic_api_key == ""
        assert creds.sandbox_claude_oauth == ""
        assert creds.sandbox_enable_tavily == "0"

    def test_to_env_dict(self):
        creds = CredentialPlaceholders(
            sandbox_anthropic_api_key="CRED_PROXY_abc",
            sandbox_claude_oauth="",
            sandbox_gemini_api_key="CRED_PROXY_def",
            sandbox_zhipu_api_key="",
            sandbox_enable_tavily="1",
        )
        env = creds.to_env_dict()
        assert env["SANDBOX_ANTHROPIC_API_KEY"] == "CRED_PROXY_abc"
        assert env["SANDBOX_CLAUDE_OAUTH"] == ""
        assert env["SANDBOX_GEMINI_API_KEY"] == "CRED_PROXY_def"
        assert env["SANDBOX_ZHIPU_API_KEY"] == ""
        assert env["SANDBOX_ENABLE_TAVILY"] == "1"

    def test_to_env_dict_keys(self):
        creds = CredentialPlaceholders()
        env = creds.to_env_dict()
        expected_keys = {
            "SANDBOX_ANTHROPIC_API_KEY",
            "SANDBOX_CLAUDE_OAUTH",
            "SANDBOX_GEMINI_API_KEY",
            "SANDBOX_ZHIPU_API_KEY",
            "SANDBOX_ENABLE_TAVILY",
        }
        assert set(env.keys()) == expected_keys

    def test_model_dump_roundtrip(self):
        creds = CredentialPlaceholders(
            sandbox_anthropic_api_key="key1",
            sandbox_enable_tavily="1",
        )
        data = creds.model_dump()
        restored = CredentialPlaceholders(**data)
        assert restored == creds

    def test_json_roundtrip(self):
        creds = CredentialPlaceholders(sandbox_claude_oauth="tok")
        json_str = creds.model_dump_json()
        restored = CredentialPlaceholders.model_validate_json(json_str)
        assert restored == creds


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
