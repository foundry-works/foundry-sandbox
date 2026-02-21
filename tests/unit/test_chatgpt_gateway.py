"""Unit tests for ChatGPT/Codex API gateway.

Tests credential loading from auth.json via OAuthTokenManager,
the request hook token refresh, gateway app creation, and
dual-port TLS server startup.
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
        mock_error_resp = MagicMock(status=502)
        with patch.object(chatgpt_gateway, "_token_manager", None), \
             patch.object(chatgpt_gateway, "gateway_error", return_value=mock_error_resp) as mock_gw:
            result = await chatgpt_gateway._chatgpt_request_hook(
                mock_request, "POST", b"", "test-container"
            )
        assert result is mock_error_resp
        mock_gw.assert_called_once_with(502, "ChatGPT OAuth credential not configured")

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


# ---------------------------------------------------------------------------
# TLS listener (dual-port server)
# ---------------------------------------------------------------------------


class TestRunChatGPTGatewayServer:
    """Tests for run_chatgpt_gateway_server() dual-port startup."""

    def _run_server(self, *, tls_cert_exists: bool, tls_port: int = 8443):
        """Run the server with fully mocked asyncio/aiohttp, returning call records."""
        # Track TCPSite construction calls
        tcp_site_calls: list[tuple] = []

        def _tcp_site_factory(*args, **kwargs):
            tcp_site_calls.append((args, kwargs))
            return MagicMock()

        mock_runner = MagicMock()
        mock_app = MagicMock()

        # Fully mock the event loop so we don't need real async execution
        mock_loop = MagicMock()
        mock_loop.run_forever.side_effect = KeyboardInterrupt

        ssl_ctx_instances: list[MagicMock] = []

        def _mock_ssl_ctx(protocol):
            ctx = MagicMock()
            ctx._protocol = protocol
            ssl_ctx_instances.append(ctx)
            return ctx

        with patch("chatgpt_gateway.web.AppRunner", return_value=mock_runner), \
             patch("chatgpt_gateway.web.TCPSite", side_effect=_tcp_site_factory), \
             patch("chatgpt_gateway.asyncio.new_event_loop", return_value=mock_loop), \
             patch("chatgpt_gateway.asyncio.set_event_loop"), \
             patch("chatgpt_gateway.os.path.isfile", return_value=tls_cert_exists), \
             patch("chatgpt_gateway.ssl.SSLContext", side_effect=_mock_ssl_ctx):
            try:
                chatgpt_gateway.run_chatgpt_gateway_server(
                    app=mock_app,
                    tls_port=tls_port,
                    tls_cert="/fake/cert.pem",
                    tls_key="/fake/key.pem",
                )
            except KeyboardInterrupt:
                pass

        return tcp_site_calls, ssl_ctx_instances

    def test_starts_http_only_when_no_tls_cert(self):
        """Starts only HTTP listener when TLS cert files are missing."""
        calls, ssl_ctxs = self._run_server(tls_cert_exists=False)

        # Only one TCPSite (HTTP)
        assert len(calls) == 1
        # No SSL context created
        assert len(ssl_ctxs) == 0
        # No ssl_context kwarg
        _, kwargs = calls[0]
        assert "ssl_context" not in kwargs

    def test_starts_both_http_and_tls_when_cert_exists(self):
        """Starts both HTTP and TLS listeners when cert files exist."""
        calls, ssl_ctxs = self._run_server(tls_cert_exists=True, tls_port=8443)

        # Two TCPSite instances: HTTP + TLS
        assert len(calls) == 2

        # First call: HTTP (port 9852, no ssl_context)
        http_args, http_kwargs = calls[0]
        assert http_args[2] == chatgpt_gateway.CHATGPT_GATEWAY_PORT
        assert "ssl_context" not in http_kwargs

        # Second call: TLS (port 8443, with ssl_context)
        tls_args, tls_kwargs = calls[1]
        assert tls_args[2] == 8443
        assert "ssl_context" in tls_kwargs
        assert tls_kwargs["ssl_context"] is ssl_ctxs[0]

        # SSLContext configured with cert chain
        assert len(ssl_ctxs) == 1
        ssl_ctxs[0].load_cert_chain.assert_called_once_with(
            "/fake/cert.pem", "/fake/key.pem"
        )

    def test_tls_config_constants(self):
        """Verifies TLS configuration constants have correct defaults."""
        assert chatgpt_gateway.CHATGPT_TLS_PORT == 443
        assert chatgpt_gateway.CHATGPT_TLS_CERT == "/etc/proxy/certs/chatgpt-gw.pem"
        assert chatgpt_gateway.CHATGPT_TLS_KEY == "/etc/proxy/certs/chatgpt-gw.key"
