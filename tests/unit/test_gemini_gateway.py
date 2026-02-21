"""Unit tests for Gemini API gateway.

Tests credential loading in both API-key and OAuth modes,
the request hook for OAuth token refresh, and gateway app creation.
"""

import json
import os
import sys
import tempfile
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

# gemini_gateway.py imports aiohttp at module level.  Install a minimal
# mock so the module can be imported without aiohttp installed.
if "aiohttp" not in sys.modules:
    sys.modules["aiohttp"] = mock.MagicMock()
    sys.modules["aiohttp.web"] = mock.MagicMock()

# conftest.py adds unified-proxy to sys.path.

import gemini_gateway


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_module_state():
    """Reset module-level state between tests."""
    gemini_gateway._token_manager = None
    gemini_gateway._credential_mode = "none"


# ---------------------------------------------------------------------------
# API-key credential loading
# ---------------------------------------------------------------------------


class TestLoadGeminiCredentialApiKey:
    """Tests for _load_gemini_credential() in API-key mode."""

    def setup_method(self):
        _reset_module_state()

    def test_gemini_api_key_preferred(self):
        """GEMINI_API_KEY takes priority over GOOGLE_API_KEY."""
        with patch.dict(os.environ, {
            "GEMINI_API_KEY": "gemini-primary",
            "GOOGLE_API_KEY": "google-fallback",
        }, clear=False):
            cred = gemini_gateway._load_gemini_credential()
        assert cred is not None
        assert cred["header"] == "x-goog-api-key"
        assert cred["value"] == "gemini-primary"
        assert gemini_gateway._credential_mode == "api_key"

    def test_google_api_key_fallback(self):
        """GOOGLE_API_KEY is used when GEMINI_API_KEY is empty."""
        env = os.environ.copy()
        env.pop("GEMINI_API_KEY", None)
        env["GOOGLE_API_KEY"] = "google-key"
        with patch.dict(os.environ, env, clear=True):
            cred = gemini_gateway._load_gemini_credential()
        assert cred is not None
        assert cred["header"] == "x-goog-api-key"
        assert cred["value"] == "google-key"
        assert gemini_gateway._credential_mode == "api_key"

    def test_empty_keys_treated_as_missing(self):
        """Empty string keys are treated as missing."""
        with patch.dict(os.environ, {
            "GEMINI_API_KEY": "",
            "GOOGLE_API_KEY": "",
        }, clear=False):
            with patch.object(gemini_gateway, "_token_manager", None):
                cred = gemini_gateway._load_gemini_credential()
        assert cred is None
        assert gemini_gateway._credential_mode == "none"


# ---------------------------------------------------------------------------
# OAuth credential loading
# ---------------------------------------------------------------------------


class TestLoadGeminiCredentialOAuth:
    """Tests for _load_gemini_credential() in OAuth mode."""

    def setup_method(self):
        _reset_module_state()

    def test_oauth_fallback_when_no_api_key(self):
        """Falls back to OAuth when no API key is set."""
        manager = MagicMock()
        manager.get_valid_token.return_value = "ya29.oauth-token"

        env = os.environ.copy()
        env.pop("GEMINI_API_KEY", None)
        env.pop("GOOGLE_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            with patch.object(gemini_gateway, "_token_manager", manager):
                cred = gemini_gateway._load_gemini_credential()

        assert cred is not None
        assert cred["header"] == "Authorization"
        assert cred["value"] == "Bearer ya29.oauth-token"
        assert gemini_gateway._credential_mode == "oauth"

    def test_api_key_wins_over_oauth(self):
        """API key takes priority even when OAuth manager is available."""
        manager = MagicMock()
        manager.get_valid_token.return_value = "ya29.oauth-token"

        with patch.dict(os.environ, {"GEMINI_API_KEY": "api-key-123"}, clear=False):
            with patch.object(gemini_gateway, "_token_manager", manager):
                cred = gemini_gateway._load_gemini_credential()

        assert cred is not None
        assert cred["header"] == "x-goog-api-key"
        assert gemini_gateway._credential_mode == "api_key"
        manager.get_valid_token.assert_not_called()

    def test_returns_none_on_oauth_error(self):
        """Returns None when OAuth token manager raises."""
        manager = MagicMock()
        manager.get_valid_token.side_effect = RuntimeError("token expired")

        env = os.environ.copy()
        env.pop("GEMINI_API_KEY", None)
        env.pop("GOOGLE_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            with patch.object(gemini_gateway, "_token_manager", manager):
                cred = gemini_gateway._load_gemini_credential()

        assert cred is None
        assert gemini_gateway._credential_mode == "none"


# ---------------------------------------------------------------------------
# Token manager initialization
# ---------------------------------------------------------------------------


class TestInitTokenManager:
    """Tests for _init_token_manager()."""

    def setup_method(self):
        _reset_module_state()

    def test_skips_when_env_not_set(self):
        """Does not initialize when GEMINI_OAUTH_FILE is unset."""
        env = os.environ.copy()
        env.pop("GEMINI_OAUTH_FILE", None)
        with patch.dict(os.environ, env, clear=True):
            gemini_gateway._init_token_manager()
        assert gemini_gateway._token_manager is None

    def test_skips_when_file_missing(self):
        """Does not initialize when OAuth file does not exist."""
        with patch.dict(os.environ, {"GEMINI_OAUTH_FILE": "/nonexistent/oauth.json"}):
            gemini_gateway._init_token_manager()
        assert gemini_gateway._token_manager is None

    def test_initializes_with_valid_oauth_file(self):
        """Initializes token manager from a valid oauth_creds.json."""
        oauth_data = {
            "access_token": "ya29.test-token",
            "refresh_token": "1//test-refresh",
            "expiry_date": 9999999999000,  # milliseconds
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(oauth_data, f)
            oauth_path = f.name

        # Mock the GeminiTokenManager import so it succeeds in the test env
        mock_manager_instance = MagicMock()
        mock_manager_cls = MagicMock(return_value=mock_manager_instance)
        mock_module = MagicMock()
        mock_module.GeminiTokenManager = mock_manager_cls

        try:
            with patch.dict(os.environ, {"GEMINI_OAUTH_FILE": oauth_path}), \
                 patch.dict(sys.modules, {
                     "addons": MagicMock(),
                     "addons.oauth_managers": MagicMock(),
                     "addons.oauth_managers.gemini": mock_module,
                 }):
                gemini_gateway._init_token_manager()
            assert gemini_gateway._token_manager is mock_manager_instance
        finally:
            os.unlink(oauth_path)
            _reset_module_state()


# ---------------------------------------------------------------------------
# Request hook
# ---------------------------------------------------------------------------


class TestGeminiRequestHook:
    """Tests for _gemini_request_hook()."""

    def setup_method(self):
        _reset_module_state()

    @pytest.mark.asyncio
    async def test_noop_in_api_key_mode(self):
        """Request hook is a no-op in API-key mode."""
        gemini_gateway._credential_mode = "api_key"
        mock_request = MagicMock()
        mock_request.app = {"credential": {"header": "x-goog-api-key", "value": "key"}}

        result = await gemini_gateway._gemini_request_hook(
            mock_request, "POST", b"", "test-container"
        )
        assert result is None
        # Credential should be unchanged
        assert mock_request.app["credential"]["value"] == "key"

    @pytest.mark.asyncio
    async def test_refreshes_token_in_oauth_mode(self):
        """Mutates credential dict in-place with fresh OAuth token."""
        gemini_gateway._credential_mode = "oauth"
        manager = MagicMock()
        manager.get_valid_token.return_value = "ya29.refreshed-token"

        mock_request = MagicMock()
        existing = {"header": "Authorization", "value": "Bearer ya29.old-token"}
        mock_request.app = {"credential": existing}

        with patch.object(gemini_gateway, "_token_manager", manager):
            result = await gemini_gateway._gemini_request_hook(
                mock_request, "POST", b"", "test-container"
            )

        assert result is None
        assert mock_request.app["credential"]["value"] == "Bearer ya29.refreshed-token"

    @pytest.mark.asyncio
    async def test_returns_error_when_no_manager(self):
        """Returns 502 when in OAuth mode but manager is missing."""
        gemini_gateway._credential_mode = "oauth"
        mock_request = MagicMock()
        mock_request.app = {"credential": None}

        mock_error_resp = MagicMock(status=502)
        with patch.object(gemini_gateway, "_token_manager", None), \
             patch.object(gemini_gateway, "gateway_error", return_value=mock_error_resp) as mock_gw:
            result = await gemini_gateway._gemini_request_hook(
                mock_request, "POST", b"", "test-container"
            )
        assert result is mock_error_resp
        mock_gw.assert_called_once_with(502, "Gemini OAuth credential not configured")

    @pytest.mark.asyncio
    async def test_creates_credential_when_none(self):
        """Creates credential when it was None at startup."""
        gemini_gateway._credential_mode = "oauth"
        manager = MagicMock()
        manager.get_valid_token.return_value = "ya29.new-token"

        mock_request = MagicMock()
        mock_request.app = {"credential": None}

        with patch.object(gemini_gateway, "_token_manager", manager):
            result = await gemini_gateway._gemini_request_hook(
                mock_request, "POST", b"", "test-container"
            )

        assert result is None
        assert mock_request.app["credential"]["header"] == "Authorization"
        assert mock_request.app["credential"]["value"] == "Bearer ya29.new-token"
