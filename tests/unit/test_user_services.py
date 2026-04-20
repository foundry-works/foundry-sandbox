"""Tests for the user services config loader."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from foundry_sandbox.user_services import (
    _slug,
    clear_cache,
    get_proxy_env_overrides,
    load_user_services,
)


@pytest.fixture(autouse=True)
def _clear():
    clear_cache()
    yield
    clear_cache()


class TestSlug:
    def test_simple(self):
        assert _slug("Tavily") == "tavily"

    def test_multi_word(self):
        assert _slug("Semantic Scholar") == "semantic-scholar"

    def test_special_chars(self):
        assert _slug("My API (v2)") == "my-api-v2"

    def test_empty(self):
        assert _slug("") == "unknown"


class TestLoadUserServices:
    def test_no_config_returns_empty(self, tmp_path):
        result = load_user_services(tmp_path / "nonexistent.yaml")
        assert result == []

    def test_valid_yaml(self, tmp_path):
        config = tmp_path / "user-services.yaml"
        config.write_text(
            'version: "1"\n'
            "services:\n"
            "  - name: Tavily\n"
            "    env_var: TAVILY_API_KEY\n"
            "    domain: api.tavily.com\n"
            "    header: Authorization\n"
            "    format: bearer\n"
        )
        result = load_user_services(config)
        assert len(result) == 1
        assert result[0]["name"] == "Tavily"
        assert result[0]["env_var"] == "TAVILY_API_KEY"
        assert result[0]["domain"] == "api.tavily.com"
        assert result[0]["format"] == "bearer"

    def test_invalid_env_var_returns_empty(self, tmp_path):
        config = tmp_path / "user-services.yaml"
        config.write_text(
            'version: "1"\n'
            "services:\n"
            "  - name: Bad\n"
            "    env_var: lowercase-key\n"
            "    domain: api.example.com\n"
            "    header: Authorization\n"
            "    format: bearer\n"
        )
        result = load_user_services(config)
        assert result == []

    def test_empty_yaml_returns_empty(self, tmp_path):
        config = tmp_path / "user-services.yaml"
        config.write_text("")
        result = load_user_services(config)
        assert result == []

    def test_env_var_override(self, tmp_path):
        config = tmp_path / "custom.yaml"
        config.write_text(
            'version: "1"\n'
            "services:\n"
            "  - name: Test\n"
            "    env_var: TEST_API_KEY\n"
            "    domain: api.test.com\n"
            "    header: Authorization\n"
            "    format: bearer\n"
        )
        with patch.dict(os.environ, {"FOUNDRY_USER_SERVICES_PATH": str(config)}):
            result = load_user_services()
            assert len(result) == 1
            assert result[0]["name"] == "Test"

    def test_multiple_services(self, tmp_path):
        config = tmp_path / "user-services.yaml"
        config.write_text(
            'version: "1"\n'
            "services:\n"
            "  - name: Tavily\n"
            "    env_var: TAVILY_API_KEY\n"
            "    domain: api.tavily.com\n"
            "    header: Authorization\n"
            "    format: bearer\n"
            "  - name: Groq\n"
            "    env_var: GROQ_API_KEY\n"
            "    domain: api.groq.com\n"
            "    header: Authorization\n"
            "    format: bearer\n"
            "  - name: Custom\n"
            "    env_var: CUSTOM_KEY\n"
            "    domain: custom.io\n"
            "    header: X-Api-Key\n"
            "    format: value\n"
        )
        result = load_user_services(config)
        assert len(result) == 3
        assert result[0]["format"] == "bearer"
        assert result[2]["header"] == "X-Api-Key"

    def test_invalid_yaml_syntax_returns_empty(self, tmp_path):
        config = tmp_path / "user-services.yaml"
        config.write_text("{{invalid: yaml: [}")
        result = load_user_services(config)
        assert result == []


class TestGetProxyEnvOverrides:
    def test_returns_proxy_urls(self, tmp_path):
        config = tmp_path / "user-services.yaml"
        config.write_text(
            'version: "1"\n'
            "services:\n"
            "  - name: Tavily\n"
            "    env_var: TAVILY_API_KEY\n"
            "    domain: api.tavily.com\n"
            "    header: Authorization\n"
            "    format: bearer\n"
        )
        with patch.dict(os.environ, {"FOUNDRY_USER_SERVICES_PATH": str(config)}):
            clear_cache()
            overrides = get_proxy_env_overrides()
            assert "TAVILY_API_KEY" in overrides
            assert overrides["TAVILY_API_KEY"] == "http://host.docker.internal:8083/proxy/tavily"

    def test_custom_port(self, tmp_path):
        config = tmp_path / "user-services.yaml"
        config.write_text(
            'version: "1"\n'
            "services:\n"
            "  - name: Tavily\n"
            "    env_var: TAVILY_API_KEY\n"
            "    domain: api.tavily.com\n"
            "    header: Authorization\n"
            "    format: bearer\n"
        )
        with patch.dict(os.environ, {"FOUNDRY_USER_SERVICES_PATH": str(config)}):
            clear_cache()
            overrides = get_proxy_env_overrides(port=9090)
            assert "TAVILY_API_KEY" in overrides
            assert ":9090/proxy/" in overrides["TAVILY_API_KEY"]

    def test_no_config_returns_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            clear_cache()
            # Path("config/user-services.yaml") likely doesn't exist in test env
            overrides = get_proxy_env_overrides()
            assert overrides == {}

    def test_multi_word_slug(self, tmp_path):
        config = tmp_path / "user-services.yaml"
        config.write_text(
            'version: "1"\n'
            "services:\n"
            "  - name: Semantic Scholar\n"
            "    env_var: SEMANTIC_SCHOLAR_KEY\n"
            "    domain: api.semanticscholar.org\n"
            "    header: X-Api-Key\n"
            "    format: value\n"
        )
        with patch.dict(os.environ, {"FOUNDRY_USER_SERVICES_PATH": str(config)}):
            clear_cache()
            overrides = get_proxy_env_overrides()
            assert "SEMANTIC_SCHOLAR_KEY" in overrides
            assert "/proxy/semantic-scholar" in overrides["SEMANTIC_SCHOLAR_KEY"]
