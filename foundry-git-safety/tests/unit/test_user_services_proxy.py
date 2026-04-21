"""Tests for the user services proxy blueprint."""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock, patch

import pytest

from foundry_git_safety.auth import (
    NonceStore,
    RateLimiter,
    SecretStore,
    compute_signature,
)
from foundry_git_safety.schemas.foundry_yaml import UserServiceEntry
from foundry_git_safety.user_services_proxy import (
    _slug,
    create_user_services_blueprint,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEST_SANDBOX = "test-sandbox"
_TEST_SECRET = b"test-secret-key-for-proxy-unit-tests-0123456789a\n"


def _auth_headers(method: str, path: str, body: bytes = b"") -> dict[str, str]:
    """Build valid HMAC auth headers for the test sandbox."""
    ts = str(time.time())
    nonce = f"unit-nonce-{time.time_ns()}"
    sig = compute_signature(method, path, body, ts, nonce, _TEST_SECRET.rstrip(b"\n"))
    return {
        "X-Sandbox-Id": _TEST_SANDBOX,
        "X-Request-Signature": sig,
        "X-Request-Timestamp": ts,
        "X-Request-Nonce": nonce,
    }


@pytest.fixture
def secrets_dir(tmp_path):
    d = tmp_path / "secrets"
    d.mkdir()
    (d / _TEST_SANDBOX).write_bytes(_TEST_SECRET)
    return d


@pytest.fixture
def auth_stores(secrets_dir):
    return (
        SecretStore(secrets_path=str(secrets_dir)),
        NonceStore(),
        RateLimiter(),
    )


@pytest.fixture
def tavily_service():
    return UserServiceEntry(
        name="Tavily",
        env_var="TAVILY_API_KEY",
        domain="api.tavily.com",
        header="Authorization",
        format="bearer",
    )


@pytest.fixture
def custom_service():
    return UserServiceEntry(
        name="CustomService",
        env_var="CUSTOM_API_KEY",
        domain="api.custom.example",
        header="X-Api-Key",
        format="value",
    )


@pytest.fixture
def restricted_service():
    return UserServiceEntry(
        name="ReadOnlyAPI",
        env_var="READONLY_API_KEY",
        domain="api.readonly.example",
        header="Authorization",
        format="bearer",
        methods=["GET"],
        paths=["/v1/**"],
    )


@pytest.fixture
def proxy_app(tavily_service, auth_stores):
    """Create a Flask app with the user services blueprint and auth."""
    from flask import Flask

    secret_store, nonce_store, rate_limiter = auth_stores
    bp = create_user_services_blueprint(
        [tavily_service],
        secret_store=secret_store,
        nonce_store=nonce_store,
        rate_limiter=rate_limiter,
    )
    app = Flask(__name__)
    app.register_blueprint(bp)
    return app


class TestSlug:
    def test_simple(self):
        assert _slug("Tavily") == "tavily"

    def test_multi_word(self):
        assert _slug("Semantic Scholar") == "semantic-scholar"

    def test_special_chars(self):
        assert _slug("My API (v2)") == "my-api-v2"

    def test_uppercase(self):
        assert _slug("OPENAI") == "openai"


class TestProxyHealth:
    def test_lists_services(self, tavily_service, custom_service, auth_stores):
        from flask import Flask

        secret_store, nonce_store, rate_limiter = auth_stores
        bp = create_user_services_blueprint(
            [tavily_service, custom_service],
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        app = Flask(__name__)
        app.register_blueprint(bp)
        with app.test_client() as client:
            with patch.dict(os.environ, {"TAVILY_API_KEY": "tvly-123"}):
                resp = client.get("/proxy/health")
                assert resp.status_code == 200
                data = resp.get_json()
                assert len(data["services"]) == 2
                slugs = {s["slug"]: s for s in data["services"]}
                assert slugs["tavily"]["key_present"] is True
                assert slugs["customservice"]["key_present"] is False

    def test_empty_services(self, auth_stores):
        from flask import Flask

        secret_store, nonce_store, rate_limiter = auth_stores
        bp = create_user_services_blueprint(
            [],
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        app = Flask(__name__)
        app.register_blueprint(bp)
        with app.test_client() as client:
            resp = client.get("/proxy/health")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["services"] == []


class TestProxyRequest:
    def test_no_auth_returns_401(self, proxy_app):
        """Unauthenticated requests are rejected."""
        with proxy_app.test_client() as client:
            resp = client.get("/proxy/tavily/v1/search")
            assert resp.status_code == 401

    def test_unknown_service_returns_404(self, proxy_app):
        headers = _auth_headers("GET", "/proxy/unknown-service/v1/search")
        with proxy_app.test_client() as client:
            resp = client.get("/proxy/unknown-service/v1/search", headers=headers)
            assert resp.status_code == 404
            assert "Unknown service" in resp.get_json()["error"]

    def test_missing_api_key_returns_503(self, proxy_app):
        headers = _auth_headers("GET", "/proxy/tavily/v1/search")
        with proxy_app.test_client() as client:
            with patch.dict(os.environ, {}, clear=True):
                resp = client.get("/proxy/tavily/v1/search", headers=headers)
                assert resp.status_code == 503
                assert "not configured" in resp.get_json()["error"]

    def test_bearer_format(self, proxy_app):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheaders.return_value = [("content-type", "application/json")]
        mock_response.read.side_effect = [b'{"ok": true}', b""]

        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with proxy_app.test_client() as client:
            with patch.dict(os.environ, {"TAVILY_API_KEY": "tvly-secret"}):
                with patch(
                    "foundry_git_safety.user_services_proxy.http.client.HTTPSConnection",
                    return_value=mock_conn,
                ):
                    headers = _auth_headers("GET", "/proxy/tavily/v1/search")
                    resp = client.get("/proxy/tavily/v1/search", headers=headers)
                    assert resp.status_code == 200

                    call_args = mock_conn.request.call_args
                    headers_sent = call_args[1].get("headers", {})
                    assert headers_sent["Authorization"] == "Bearer tvly-secret"

    def test_value_format(self, custom_service, auth_stores):
        from flask import Flask

        secret_store, nonce_store, rate_limiter = auth_stores
        bp = create_user_services_blueprint(
            [custom_service],
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        app = Flask(__name__)
        app.register_blueprint(bp)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheaders.return_value = [("content-type", "text/plain")]
        mock_response.read.side_effect = [b"ok", b""]

        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with app.test_client() as client:
            with patch.dict(os.environ, {"CUSTOM_API_KEY": "my-key-123"}):
                with patch(
                    "foundry_git_safety.user_services_proxy.http.client.HTTPSConnection",
                    return_value=mock_conn,
                ):
                    headers = _auth_headers("GET", "/proxy/customservice/data")
                    resp = client.get("/proxy/customservice/data", headers=headers)
                    assert resp.status_code == 200

                    call_args = mock_conn.request.call_args
                    headers_sent = call_args[1].get("headers", {})
                    assert headers_sent["X-Api-Key"] == "my-key-123"

    def test_method_filtering_blocks_disallowed(self, restricted_service, auth_stores):
        from flask import Flask

        secret_store, nonce_store, rate_limiter = auth_stores
        bp = create_user_services_blueprint(
            [restricted_service],
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        app = Flask(__name__)
        app.register_blueprint(bp)
        with app.test_client() as client:
            with patch.dict(os.environ, {"READONLY_API_KEY": "key"}):
                headers = _auth_headers("POST", "/proxy/readonlyapi/v1/data")
                resp = client.post("/proxy/readonlyapi/v1/data", headers=headers)
                assert resp.status_code == 405
                assert "not allowed" in resp.get_json()["error"]

    def test_method_filtering_allows_permitted(self, restricted_service, auth_stores):
        from flask import Flask

        secret_store, nonce_store, rate_limiter = auth_stores
        bp = create_user_services_blueprint(
            [restricted_service],
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        app = Flask(__name__)
        app.register_blueprint(bp)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheaders.return_value = [("content-type", "application/json")]
        mock_response.read.side_effect = [b"{}", b""]

        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with app.test_client() as client:
            with patch.dict(os.environ, {"READONLY_API_KEY": "key"}):
                with patch(
                    "foundry_git_safety.user_services_proxy.http.client.HTTPSConnection",
                    return_value=mock_conn,
                ):
                    headers = _auth_headers("GET", "/proxy/readonlyapi/v1/data")
                    resp = client.get("/proxy/readonlyapi/v1/data", headers=headers)
                    assert resp.status_code == 200

    def test_path_filtering_blocks_disallowed(self, restricted_service, auth_stores):
        from flask import Flask

        secret_store, nonce_store, rate_limiter = auth_stores
        bp = create_user_services_blueprint(
            [restricted_service],
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        app = Flask(__name__)
        app.register_blueprint(bp)
        with app.test_client() as client:
            with patch.dict(os.environ, {"READONLY_API_KEY": "key"}):
                headers = _auth_headers("GET", "/proxy/readonlyapi/admin/settings")
                resp = client.get("/proxy/readonlyapi/admin/settings", headers=headers)
                assert resp.status_code == 403
                assert "not allowed" in resp.get_json()["error"]

    def test_upstream_connection_failure_returns_502(self, proxy_app):
        mock_conn = MagicMock()
        mock_conn.getresponse.side_effect = ConnectionError("refused")

        with proxy_app.test_client() as client:
            with patch.dict(os.environ, {"TAVILY_API_KEY": "key"}):
                with patch(
                    "foundry_git_safety.user_services_proxy.http.client.HTTPSConnection",
                    return_value=mock_conn,
                ):
                    headers = _auth_headers("GET", "/proxy/tavily/v1/search")
                    resp = client.get("/proxy/tavily/v1/search", headers=headers)
                    assert resp.status_code == 502

    def test_query_string_preserved(self, proxy_app):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheaders.return_value = []
        mock_response.read.side_effect = [b"", b""]

        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with proxy_app.test_client() as client:
            with patch.dict(os.environ, {"TAVILY_API_KEY": "key"}):
                with patch(
                    "foundry_git_safety.user_services_proxy.http.client.HTTPSConnection",
                    return_value=mock_conn,
                ):
                    headers = _auth_headers("GET", "/proxy/tavily/v1/search")
                    resp = client.get("/proxy/tavily/v1/search?q=test", headers=headers)
                    assert resp.status_code == 200

                    call_args = mock_conn.request.call_args
                    path = call_args[0][1] if call_args[0] else call_args[1].get("path", "")
                    assert "q=test" in path
