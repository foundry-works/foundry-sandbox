"""Unit tests for OpenAI API gateway.

Tests credential loading from environment variables and gateway app creation.
"""

import os
import sys
from unittest import mock
from unittest.mock import MagicMock, patch

# openai_gateway.py imports aiohttp at module level. Install a minimal
# mock so the module can be imported without aiohttp installed.
if "aiohttp" not in sys.modules:
    sys.modules["aiohttp"] = mock.MagicMock()
    sys.modules["aiohttp.web"] = mock.MagicMock()

# conftest.py adds unified-proxy to sys.path.

import openai_gateway


# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------


class TestLoadOpenAICredential:
    """Tests for _load_openai_credential()."""

    def test_returns_bearer_token_when_key_set(self):
        """Returns Bearer token when OPENAI_API_KEY is set."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-key-123"}, clear=False):
            cred = openai_gateway._load_openai_credential()
        assert cred is not None
        assert cred["header"] == "Authorization"
        assert cred["value"] == "Bearer sk-test-key-123"

    def test_returns_none_when_env_var_missing(self):
        """Returns None when OPENAI_API_KEY is not set."""
        env = os.environ.copy()
        env.pop("OPENAI_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            cred = openai_gateway._load_openai_credential()
        assert cred is None

    def test_returns_none_when_env_var_empty(self):
        """Returns None when OPENAI_API_KEY is empty string."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False):
            cred = openai_gateway._load_openai_credential()
        assert cred is None

    def test_returns_none_when_env_var_whitespace(self):
        """Returns None when OPENAI_API_KEY is whitespace only."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "   "}, clear=False):
            cred = openai_gateway._load_openai_credential()
        assert cred is None

    def test_strips_whitespace_from_key(self):
        """Strips leading/trailing whitespace from API key."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "  sk-key-456  "}, clear=False):
            cred = openai_gateway._load_openai_credential()
        assert cred is not None
        assert cred["value"] == "Bearer sk-key-456"


# ---------------------------------------------------------------------------
# App creation
# ---------------------------------------------------------------------------


class TestCreateOpenAIGatewayApp:
    """Tests for create_openai_gateway_app()."""

    def test_creates_app(self):
        """Creates a valid aiohttp app."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False):
            app = openai_gateway.create_openai_gateway_app(
                registry=MagicMock(),
            )
        assert app is not None

    def test_calls_create_gateway_app_with_correct_args(self):
        """Passes correct service_name and upstream to create_gateway_app."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False), \
             patch.object(openai_gateway, "create_gateway_app", return_value=MagicMock()) as mock_create:
            openai_gateway.create_openai_gateway_app(registry=MagicMock())

        mock_create.assert_called_once()
        kwargs = mock_create.call_args[1]
        assert kwargs["service_name"] == "openai-gateway"
        assert kwargs["upstream_base_url"] == "https://api.openai.com"
        assert kwargs["upstream_host"] == "api.openai.com"
        assert kwargs["credential_required"] is True

    def test_catch_all_route(self):
        """App registers a catch-all route."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False), \
             patch.object(openai_gateway, "create_gateway_app", return_value=MagicMock()) as mock_create:
            openai_gateway.create_openai_gateway_app(registry=MagicMock())

        kwargs = mock_create.call_args[1]
        assert ("*", "/{path_info:.*}") in kwargs["routes"]


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------


class TestOpenAIGatewayConfig:
    """Tests for OpenAI gateway configuration constants."""

    def test_default_port(self):
        """Default port is 9849."""
        assert openai_gateway.OPENAI_GATEWAY_PORT == 9849

    def test_default_bind(self):
        """Default bind address is 0.0.0.0."""
        assert openai_gateway.OPENAI_GATEWAY_BIND == "0.0.0.0"
