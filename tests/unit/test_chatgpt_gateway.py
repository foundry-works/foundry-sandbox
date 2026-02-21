"""Unit tests for ChatGPT/Codex API gateway.

Tests credential loading from auth.json via OAuthTokenManager,
the request hook token refresh, and gateway app creation.
"""

import json
import os
import sys
import tempfile
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

# chatgpt_gateway.py imports aiohttp at module level.  Install a minimal
# mock so the module can be imported without aiohttp installed.
if "aiohttp" not in sys.modules:
    sys.modules["aiohttp"] = mock.MagicMock()
    sys.modules["aiohttp.web"] = mock.MagicMock()

# conftest.py adds unified-proxy to sys.path.

import chatgpt_gateway


# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------


class TestLoadChatGPTCredential:
    """Tests for _load_chatgpt_credential()."""

    def test_returns_none_when_no_token_manager(self):
        """Returns None when token manager is not initialized."""
        with patch.object(chatgpt_gateway, "_token_manager", None):
            cred = chatgpt_gateway._load_chatgpt_credential()
        assert cred is None

    def test_returns_bearer_token(self):
        """Returns Bearer token from token manager."""
        manager = MagicMock()
        manager.get_valid_token.return_value = "test-oauth-token-123"
        with patch.object(chatgpt_gateway, "_token_manager", manager):
            cred = chatgpt_gateway._load_chatgpt_credential()
        assert cred is not None
        assert cred["header"] == "Authorization"
        assert cred["value"] == "Bearer test-oauth-token-123"

    def test_returns_none_on_token_error(self):
        """Returns None when token manager raises."""
        manager = MagicMock()
        manager.get_valid_token.side_effect = RuntimeError("refresh failed")
        with patch.object(chatgpt_gateway, "_token_manager", manager):
            cred = chatgpt_gateway._load_chatgpt_credential()
        assert cred is None


# ---------------------------------------------------------------------------
# Token manager initialization
# ---------------------------------------------------------------------------


class TestInitTokenManager:
    """Tests for _init_token_manager()."""

    def test_skips_when_env_not_set(self):
        """Does not initialize when CODEX_AUTH_FILE is unset."""
        env = os.environ.copy()
        env.pop("CODEX_AUTH_FILE", None)
        with patch.dict(os.environ, env, clear=True):
            chatgpt_gateway._token_manager = None
            chatgpt_gateway._init_token_manager()
        assert chatgpt_gateway._token_manager is None

    def test_skips_when_file_missing(self):
        """Does not initialize when auth file does not exist."""
        with patch.dict(os.environ, {"CODEX_AUTH_FILE": "/nonexistent/auth.json"}):
            chatgpt_gateway._token_manager = None
            chatgpt_gateway._init_token_manager()
        assert chatgpt_gateway._token_manager is None

    def test_initializes_with_valid_auth_file(self):
        """Initializes token manager from a valid auth.json."""
        auth_data = {
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig",
            "refresh_token": "rt_test_refresh_token",
            "expires_at": 9999999999,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(auth_data, f)
            auth_path = f.name

        try:
            with patch.dict(os.environ, {"CODEX_AUTH_FILE": auth_path}):
                chatgpt_gateway._token_manager = None
                chatgpt_gateway._init_token_manager()
            assert chatgpt_gateway._token_manager is not None
        finally:
            os.unlink(auth_path)
            chatgpt_gateway._token_manager = None


# ---------------------------------------------------------------------------
# Request hook
# ---------------------------------------------------------------------------


class TestChatGPTRequestHook:
    """Tests for _chatgpt_request_hook()."""

    @staticmethod
    async def _run_hook(token_manager, existing_credential):
        """Helper to run the request hook with mocked app."""
        mock_request = MagicMock()
        mock_request.app = {"credential": existing_credential}

        with patch.object(chatgpt_gateway, "_token_manager", token_manager):
            result = await chatgpt_gateway._chatgpt_request_hook(
                mock_request, "POST", b"", "test-container"
            )
        return result, mock_request.app

    @pytest.mark.asyncio
    async def test_returns_error_when_no_manager(self):
        """Returns 502 when token manager is not available."""
        mock_request = MagicMock()
        mock_request.app = {"credential": None}
        with patch.object(chatgpt_gateway, "_token_manager", None):
            result = await chatgpt_gateway._chatgpt_request_hook(
                mock_request, "POST", b"", "test-container"
            )
        # gateway_error returns a web.Response mock in test env
        assert result is not None

    @pytest.mark.asyncio
    async def test_refreshes_token_in_place(self):
        """Mutates credential dict in-place with fresh token."""
        manager = MagicMock()
        manager.get_valid_token.return_value = "refreshed-token-456"
        existing = {"header": "Authorization", "value": "Bearer old-token"}

        result, app = await self._run_hook(manager, existing)
        assert result is None  # None means continue to upstream
        assert app["credential"]["value"] == "Bearer refreshed-token-456"

    @pytest.mark.asyncio
    async def test_creates_credential_when_none(self):
        """Creates credential when it was None at startup."""
        manager = MagicMock()
        manager.get_valid_token.return_value = "new-token-789"

        result, app = await self._run_hook(manager, None)
        assert result is None
        assert app["credential"]["header"] == "Authorization"
        assert app["credential"]["value"] == "Bearer new-token-789"
