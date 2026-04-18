"""Unit tests for foundry_sandbox.api_keys key detection and status reporting."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.api_keys import (
    check_any_ai_key,
    check_api_keys_status,
    check_claude_key_required,
    export_gh_token,
    get_cli_status,
    has_claude_key,
    has_codex_key,
    has_gemini_key,
    has_zai_key,
    warn_claude_auth_conflict,
)


class TestHasClaudeKey:
    """Test has_claude_key() detection."""

    def test_oauth_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert has_claude_key() is True

    def test_api_key_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        assert has_claude_key() is True

    def test_both_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        assert has_claude_key() is True

    def test_neither_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert has_claude_key() is False


class TestHasGeminiKey:
    """Test has_gemini_key() detection."""

    def test_oauth_file_exists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        with patch.object(Path, "is_file", return_value=True):
            assert has_gemini_key() is True

    def test_api_key_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "real-key-123")
        with patch.object(Path, "is_file", return_value=False):
            assert has_gemini_key() is True

    def test_placeholder_credential_proxy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "CREDENTIAL_PROXY_PLACEHOLDER")
        with patch.object(Path, "is_file", return_value=False):
            assert has_gemini_key() is False

    def test_placeholder_cred_proxy_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "CRED_PROXY_abc123")
        with patch.object(Path, "is_file", return_value=False):
            assert has_gemini_key() is False

    def test_empty_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "")
        with patch.object(Path, "is_file", return_value=False):
            assert has_gemini_key() is False


class TestHasZaiKey:
    """Test has_zai_key() placeholder filtering."""

    def test_real_key_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ZHIPU_API_KEY", "real-zai-key-abc")
        assert has_zai_key() is True

    def test_credential_proxy_placeholder_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ZHIPU_API_KEY", "CREDENTIAL_PROXY_PLACEHOLDER")
        assert has_zai_key() is False

    def test_proxy_placeholder_opencode_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ZHIPU_API_KEY", "PROXY_PLACEHOLDER_OPENCODE")
        assert has_zai_key() is False

    def test_cred_proxy_prefix_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ZHIPU_API_KEY", "CRED_PROXY_abcdef1234567890")
        assert has_zai_key() is False

    def test_empty_key_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ZHIPU_API_KEY", "")
        assert has_zai_key() is False

    def test_unset_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ZHIPU_API_KEY", raising=False)
        assert has_zai_key() is False


class TestHasCodexKey:
    """Test has_codex_key() detection."""

    def test_auth_file_exists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with patch.object(Path, "is_file", return_value=True):
            assert has_codex_key() is True

    def test_openai_key_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-xxx")
        with patch.object(Path, "is_file", return_value=False):
            assert has_codex_key() is True

    def test_neither(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with patch.object(Path, "is_file", return_value=False):
            assert has_codex_key() is False


class TestCheckAnyAiKey:
    """Test check_any_ai_key() aggregation."""

    def test_at_least_one_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        assert check_any_ai_key() is True

    def test_none_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        assert check_any_ai_key() is False


class TestWarnClaudeAuthConflict:
    """Test warn_claude_auth_conflict() conflict detection."""

    def test_conflict_when_both_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        result = warn_claude_auth_conflict()
        assert "Both" in result
        assert "OAuth" in result

    def test_no_conflict_oauth_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert warn_claude_auth_conflict() == ""

    def test_no_conflict_api_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        assert warn_claude_auth_conflict() == ""


class TestCheckClaudeKeyRequired:
    """Test check_claude_key_required() mandatory check."""

    def test_no_key_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        has_key, msg = check_claude_key_required()
        assert has_key is False
        assert "Error" in msg

    def test_key_present_returns_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        has_key, msg = check_claude_key_required()
        assert has_key is True

    def test_conflict_warning_returned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        has_key, msg = check_claude_key_required()
        assert has_key is True
        assert "Both" in msg


class TestExportGhToken:
    """Test export_gh_token() precedence and fallback."""

    def test_github_token_takes_precedence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_first")
        monkeypatch.setenv("GH_TOKEN", "ghp_second")
        assert export_gh_token() == "ghp_first"

    def test_gh_token_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("GH_TOKEN", "ghp_fallback")
        assert export_gh_token() == "ghp_fallback"

    def test_gh_cli_extraction(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GH_TOKEN", raising=False)

        status_result = MagicMock(returncode=0)
        token_result = MagicMock(returncode=0, stdout="ghp_from_cli\n")

        with patch("shutil.which", return_value="/usr/bin/gh"), \
             patch("subprocess.run", side_effect=[status_result, token_result]):
            assert export_gh_token() == "ghp_from_cli"

    def test_no_token_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GH_TOKEN", raising=False)
        with patch("shutil.which", return_value=None):
            assert export_gh_token() == ""


class TestCheckApiKeysStatus:
    """Test check_api_keys_status() structured status dict."""

    def test_all_keys_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.setenv("TAVILY_API_KEY", "tvly-xxx")
        status = check_api_keys_status()
        assert status["has_ai_key"] is True
        assert status["has_search_key"] is True
        assert status["can_proceed"] is True
        assert isinstance(status["conflict_warning"], str)
        assert isinstance(status["missing_warning"], str)

    def test_no_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
        status = check_api_keys_status()
        assert status["has_ai_key"] is False
        assert status["has_search_key"] is False
        assert status["can_proceed"] is False


class TestGetCliStatus:
    """Test get_cli_status() status line format."""

    def test_returns_list_of_strings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
        with patch("shutil.which", return_value=None), \
             patch.object(Path, "is_file", return_value=False):
            lines = get_cli_status()
        assert isinstance(lines, list)
        assert all(isinstance(line, str) for line in lines)
        assert any("Claude" in line for line in lines)

    def test_claude_always_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
        with patch("shutil.which", return_value=None), \
             patch.object(Path, "is_file", return_value=False):
            lines = get_cli_status()
        assert "Claude: configured" in lines

    def test_search_providers_listed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAVILY_API_KEY", "tvly-xxx")
        monkeypatch.setenv("PERPLEXITY_API_KEY", "pplx-xxx")
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        with patch("shutil.which", return_value=None), \
             patch.object(Path, "is_file", return_value=False):
            lines = get_cli_status()
        search_line = [line for line in lines if line.startswith("Search:")][0]
        assert "Tavily" in search_line
        assert "Perplexity" in search_line
