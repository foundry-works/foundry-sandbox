"""Unit tests for gateway_base.py — core forwarding, header filtering,
credential injection, and error handling.

Tests _proxy_request() through the create_gateway_app() factory with
mocked upstream sessions and container registry.
"""

import asyncio
import json
import sys
from unittest.mock import MagicMock

import pytest

# Install aiohttp mocks only if not already available
try:
    import aiohttp
    from aiohttp.test_utils import TestClient, TestServer

    _REAL_AIOHTTP = True
except ImportError:
    _REAL_AIOHTTP = False
    if "aiohttp" not in sys.modules:
        sys.modules["aiohttp"] = MagicMock()
        sys.modules["aiohttp.web"] = MagicMock()


# conftest.py adds unified-proxy to sys.path

from gateway_base import (
    _PLACEHOLDER_MARKERS,
    _BASE_STRIPPED_HEADERS,
    _HOP_BY_HOP,
    create_gateway_app,
    gateway_error,
)


# ---------------------------------------------------------------------------
# Async context manager helper for mocking session.request(...)
# ---------------------------------------------------------------------------


class MockUpstreamResponse:
    """Async context manager that simulates aiohttp.ClientSession.request()."""

    def __init__(self, *, status=200, reason="OK", headers=None, body=b"",
                 error=None):
        self.status = status
        self.reason = reason
        self.headers = headers or {}
        self._body = body
        self._error = error

    async def __aenter__(self):
        if self._error:
            raise self._error
        return self

    async def __aexit__(self, *args):
        pass

    @property
    def content(self):
        body = self._body

        class _Content:
            async def iter_any(self_inner):
                if body:
                    yield body

        return _Content()


class MockSession:
    """Mock aiohttp.ClientSession with request() returning async ctx mgr."""

    def __init__(self, response=None, error=None):
        self._response = response or MockUpstreamResponse()
        self._error = error
        self.last_call_kwargs = None
        self.closed = False

    def request(self, **kwargs):
        self.last_call_kwargs = kwargs
        if self._error:
            return MockUpstreamResponse(error=self._error)
        return self._response

    async def close(self):
        self.closed = True


# ---------------------------------------------------------------------------
# gateway_error() tests (require real aiohttp for web.Response)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _REAL_AIOHTTP, reason="aiohttp not installed")
class TestGatewayError:
    """Tests for the gateway_error() helper."""

    def test_returns_json_body(self):
        resp = gateway_error(502, "upstream down")
        body = json.loads(resp.body)
        assert body["error"]["type"] == "gateway_error"
        assert body["error"]["message"] == "upstream down"

    def test_status_code_propagated(self):
        resp = gateway_error(429, "rate limited")
        assert resp.status == 429

    def test_content_type_is_json(self):
        resp = gateway_error(500, "boom")
        assert resp.content_type == "application/json"


# ---------------------------------------------------------------------------
# Header filtering tests
# ---------------------------------------------------------------------------


class TestHeaderConstants:
    """Verify stripped header sets are complete."""

    def test_authorization_stripped(self):
        assert "authorization" in _BASE_STRIPPED_HEADERS

    def test_host_stripped(self):
        assert "host" in _BASE_STRIPPED_HEADERS

    def test_hop_by_hop_headers_stripped(self):
        for header in ("connection", "keep-alive", "transfer-encoding", "upgrade"):
            assert header in _BASE_STRIPPED_HEADERS
            assert header in _HOP_BY_HOP

    def test_proxy_headers_stripped(self):
        assert "proxy-authenticate" in _BASE_STRIPPED_HEADERS
        assert "proxy-authorization" in _BASE_STRIPPED_HEADERS


# ---------------------------------------------------------------------------
# Placeholder credential filtering
# ---------------------------------------------------------------------------


class TestPlaceholderMarkers:
    """Tests for placeholder credential detection logic."""

    def test_cred_proxy_prefix_detected(self):
        value = "CRED_PROXY_abc123def456"
        assert any(value.startswith(m) for m in _PLACEHOLDER_MARKERS)

    def test_full_placeholder_detected(self):
        value = "CREDENTIAL_PROXY_PLACEHOLDER"
        assert any(value.startswith(m) for m in _PLACEHOLDER_MARKERS)

    def test_real_bearer_token_not_detected(self):
        value = "Bearer ghp_1234567890abcdef"
        assert not any(value.startswith(m) for m in _PLACEHOLDER_MARKERS)

    def test_mid_string_marker_not_detected(self):
        value = "some-prefix-CRED_PROXY_suffix"
        assert not any(value.startswith(m) for m in _PLACEHOLDER_MARKERS)

    def test_empty_value_not_detected(self):
        value = ""
        assert not any(value.startswith(m) for m in _PLACEHOLDER_MARKERS)


# ---------------------------------------------------------------------------
# Full _proxy_request integration tests (require real aiohttp)
# ---------------------------------------------------------------------------

pytestmark_aiohttp = pytest.mark.skipif(
    not _REAL_AIOHTTP,
    reason="aiohttp not installed — skipping handler integration tests",
)


def _make_mock_registry(container_id="test-container-abc"):
    """Create a mock ContainerRegistry that always resolves to container_id."""
    registry = MagicMock()
    container = MagicMock()
    container.container_id = container_id
    container.is_expired = False
    registry.get_by_ip.return_value = container
    return registry


_UNSET = object()  # sentinel to distinguish "not provided" from None


def _make_credential(header="Authorization", value="Bearer test-token-123"):
    """Create a standard credential dict."""
    return {"header": header, "value": value}


@pytestmark_aiohttp
class TestProxyRequestHandler:
    """Integration tests for _proxy_request via aiohttp test client."""

    @pytest.fixture
    def mock_registry(self):
        return _make_mock_registry()

    def _create_app(self, *, credential=_UNSET, registry=None, request_hook=None,
                    credential_required=True, extra_stripped_headers=frozenset()):
        """Create a gateway app for testing."""
        if credential is _UNSET:
            credential = _make_credential()

        return create_gateway_app(
            upstream_base_url="https://api.example.com",
            upstream_host="api.example.com",
            service_name="test-gateway",
            credential_loader=lambda: credential,
            routes=[("*", "/{path_info:.*}")],
            port=9999,
            credential_required=credential_required,
            registry=registry or _make_mock_registry(),
            extra_stripped_headers=extra_stripped_headers,
            request_hook=request_hook,
        )

    @pytest.fixture
    def app(self, mock_registry):
        return self._create_app(registry=mock_registry)

    # --- Success path ---

    @pytest.mark.asyncio
    async def test_success_forwards_and_streams(self, app, mock_registry):
        """Successful request forwards to upstream and streams response."""
        mock_session = MockSession(
            response=MockUpstreamResponse(
                status=200, reason="OK",
                headers={"Content-Type": "application/json"},
                body=b'{"ok": true}',
            )
        )

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session

            resp = await client.get("/v1/messages")
            assert resp.status == 200
            body = await resp.read()
            assert body == b'{"ok": true}'

    @pytest.mark.asyncio
    async def test_credential_injected_in_upstream_headers(self, app, mock_registry):
        """The credential header is injected into upstream request."""
        mock_session = MockSession(
            response=MockUpstreamResponse(status=200, headers={}, body=b"")
        )

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session

            await client.get("/test")

            headers = mock_session.last_call_kwargs["headers"]
            assert headers.get("Authorization") == "Bearer test-token-123"

    @pytest.mark.asyncio
    async def test_host_header_set_to_upstream(self, app, mock_registry):
        """Host header is set to the upstream host, not the sandbox host."""
        mock_session = MockSession(
            response=MockUpstreamResponse(status=200, headers={}, body=b"")
        )

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session
            await client.get("/test")

            headers = mock_session.last_call_kwargs["headers"]
            assert headers.get("Host") == "api.example.com"

    # --- Error paths ---

    @pytest.mark.asyncio
    async def test_unknown_container_returns_403(self, mock_registry):
        """Request from unknown container gets 403."""
        mock_registry.get_by_ip.return_value = None
        app = self._create_app(registry=mock_registry)

        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/test")
            assert resp.status == 403
            body = await resp.json()
            assert "error" in body

    @pytest.mark.asyncio
    async def test_expired_container_returns_403(self, mock_registry):
        """Request from expired container gets 403."""
        container = MagicMock()
        container.container_id = "expired-container"
        container.is_expired = True
        mock_registry.get_by_ip.return_value = container
        app = self._create_app(registry=mock_registry)

        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/test")
            assert resp.status == 403

    @pytest.mark.asyncio
    async def test_missing_credential_returns_502(self, mock_registry):
        """credential_required=True with no credential returns 502."""
        app = self._create_app(
            credential=None,
            registry=mock_registry,
            credential_required=True,
        )

        async with TestClient(TestServer(app)) as client:
            # Replace session so no real upstream call is attempted
            app["upstream_session"] = MockSession(
                response=MockUpstreamResponse(status=200, headers={}, body=b"")
            )
            resp = await client.get("/test")
            assert resp.status == 502
            body = await resp.json()
            assert "credential" in body["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_missing_credential_allowed_when_not_required(self, mock_registry):
        """credential_required=False with no credential still forwards."""
        mock_session = MockSession(
            response=MockUpstreamResponse(status=200, headers={}, body=b"")
        )

        app = self._create_app(
            credential=None,
            registry=mock_registry,
            credential_required=False,
        )

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session
            resp = await client.get("/test")
            assert resp.status == 200

    @pytest.mark.asyncio
    async def test_upstream_timeout_returns_504(self, app, mock_registry):
        """Upstream timeout returns 504."""
        mock_session = MockSession(error=asyncio.TimeoutError())

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session
            resp = await client.get("/test")
            assert resp.status == 504
            body = await resp.json()
            assert "timed out" in body["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_upstream_connection_error_returns_502(self, app, mock_registry):
        """Upstream connection error returns 502."""
        mock_session = MockSession(
            error=aiohttp.ClientConnectorError(
                connection_key=MagicMock(),
                os_error=OSError("Connection refused"),
            )
        )

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session
            resp = await client.get("/test")
            assert resp.status == 502
            body = await resp.json()
            assert "connect" in body["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_connection_reset_before_prepare_returns_499(self, app, mock_registry):
        """ConnectionResetError before response.prepare() returns 499."""
        mock_session = MockSession(error=ConnectionResetError())

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session
            resp = await client.get("/test")
            assert resp.status == 499
            body = await resp.json()
            assert "disconnect" in body["error"]["message"].lower()

    # --- Header filtering ---

    @pytest.mark.asyncio
    async def test_placeholder_credentials_not_forwarded(self, mock_registry):
        """Headers with placeholder credential markers are stripped."""
        mock_session = MockSession(
            response=MockUpstreamResponse(status=200, headers={}, body=b"")
        )

        app = self._create_app(registry=mock_registry)

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session

            await client.get(
                "/test",
                headers={"X-Api-Key": "CRED_PROXY_abc123"},
            )

            upstream_headers = mock_session.last_call_kwargs["headers"]
            assert "X-Api-Key" not in upstream_headers

    @pytest.mark.asyncio
    async def test_hop_by_hop_not_in_response(self, mock_registry):
        """Hop-by-hop headers from upstream are not forwarded to client."""
        mock_session = MockSession(
            response=MockUpstreamResponse(
                status=200,
                headers={
                    "Content-Type": "application/json",
                    "Transfer-Encoding": "chunked",
                    "Connection": "keep-alive",
                    "X-Request-Id": "abc123",
                },
                body=b"{}",
            )
        )

        app = self._create_app(registry=mock_registry)

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session
            resp = await client.get("/test")
            assert "X-Request-Id" in resp.headers

    # --- Request hook ---

    @pytest.mark.asyncio
    async def test_request_hook_can_short_circuit(self, mock_registry):
        """A request hook returning a Response short-circuits the request."""

        async def _block_hook(request, method, body, container_id):
            return gateway_error(403, "Blocked by policy")

        app = self._create_app(registry=mock_registry, request_hook=_block_hook)

        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/test")
            assert resp.status == 403
            body = await resp.json()
            assert "blocked" in body["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_request_hook_returning_none_continues(self, mock_registry):
        """A request hook returning None allows the request to proceed."""
        hook_called = {"count": 0}

        async def _noop_hook(request, method, body, container_id):
            hook_called["count"] += 1
            return None

        mock_session = MockSession(
            response=MockUpstreamResponse(status=200, headers={}, body=b"")
        )

        app = self._create_app(registry=mock_registry, request_hook=_noop_hook)

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session
            resp = await client.get("/test")
            assert resp.status == 200
            assert hook_called["count"] == 1

    @pytest.mark.asyncio
    async def test_invalid_credential_after_hook_returns_502(self, mock_registry):
        """Request hook that corrupts credential dict triggers 502."""

        async def _corrupt_hook(request, method, body, container_id):
            request.app["credential"] = {"bad": "structure"}
            return None

        app = self._create_app(registry=mock_registry, request_hook=_corrupt_hook)

        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/test")
            assert resp.status == 502
            body = await resp.json()
            assert "credential" in body["error"]["message"].lower()

    # --- Health check ---

    @pytest.mark.asyncio
    async def test_health_check_returns_ok(self, app):
        """Health endpoint returns 200 with service name."""
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/health")
            assert resp.status == 200
            body = await resp.json()
            assert body["status"] == "ok"
            assert body["service"] == "test-gateway"

    # --- Query string forwarding ---

    @pytest.mark.asyncio
    async def test_query_string_forwarded(self, mock_registry):
        """Query string is forwarded to upstream."""
        mock_session = MockSession(
            response=MockUpstreamResponse(status=200, headers={}, body=b"")
        )

        app = self._create_app(registry=mock_registry)

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session
            await client.get("/v1/models?per_page=10&page=2")

            url = mock_session.last_call_kwargs["url"]
            assert "per_page=10" in url
            assert "page=2" in url
