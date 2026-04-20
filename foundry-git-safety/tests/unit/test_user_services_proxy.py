"""Tests for the user services proxy blueprint."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from foundry_git_safety.schemas.foundry_yaml import UserServiceEntry
from foundry_git_safety.user_services_proxy import (
    _slug,
    create_user_services_blueprint,
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
    def test_lists_services(self, tavily_service, custom_service):
        bp = create_user_services_blueprint([tavily_service, custom_service])
        from flask import Flask

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

    def test_empty_services(self):
        bp = create_user_services_blueprint([])
        from flask import Flask

        app = Flask(__name__)
        app.register_blueprint(bp)
        with app.test_client() as client:
            resp = client.get("/proxy/health")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["services"] == []


class TestProxyRequest:
    def test_unknown_service_returns_404(self, tavily_service):
        bp = create_user_services_blueprint([tavily_service])
        from flask import Flask

        app = Flask(__name__)
        app.register_blueprint(bp)
        with app.test_client() as client:
            resp = client.get("/proxy/unknown-service/v1/search")
            assert resp.status_code == 404
            assert "Unknown service" in resp.get_json()["error"]

    def test_missing_api_key_returns_503(self, tavily_service):
        bp = create_user_services_blueprint([tavily_service])
        from flask import Flask

        app = Flask(__name__)
        app.register_blueprint(bp)
        with app.test_client() as client:
            with patch.dict(os.environ, {}, clear=True):
                resp = client.get("/proxy/tavily/v1/search")
                assert resp.status_code == 503
                assert "not configured" in resp.get_json()["error"]

    def test_bearer_format(self, tavily_service):
        bp = create_user_services_blueprint([tavily_service])
        from flask import Flask

        app = Flask(__name__)
        app.register_blueprint(bp)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheaders.return_value = [("content-type", "application/json")]
        mock_response.read.side_effect = [b'{"ok": true}', b""]

        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with app.test_client() as client:
            with patch.dict(os.environ, {"TAVILY_API_KEY": "tvly-secret"}):
                with patch(
                    "foundry_git_safety.user_services_proxy.http.client.HTTPSConnection",
                    return_value=mock_conn,
                ):
                    resp = client.get("/proxy/tavily/v1/search")
                    assert resp.status_code == 200

                    # Verify the credential header was set correctly
                    call_args = mock_conn.request.call_args
                    headers = call_args[1].get("headers", {})
                    assert headers["Authorization"] == "Bearer tvly-secret"

    def test_value_format(self, custom_service):
        bp = create_user_services_blueprint([custom_service])
        from flask import Flask

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
                    resp = client.get("/proxy/customservice/data")
                    assert resp.status_code == 200

                    call_args = mock_conn.request.call_args
                    headers = call_args[1].get("headers", {})
                    assert headers["X-Api-Key"] == "my-key-123"

    def test_method_filtering_blocks_disallowed(self, restricted_service):
        bp = create_user_services_blueprint([restricted_service])
        from flask import Flask

        app = Flask(__name__)
        app.register_blueprint(bp)
        with app.test_client() as client:
            with patch.dict(os.environ, {"READONLY_API_KEY": "key"}):
                resp = client.post("/proxy/readonlyapi/v1/data")
                assert resp.status_code == 405
                assert "not allowed" in resp.get_json()["error"]

    def test_method_filtering_allows_permitted(self, restricted_service):
        bp = create_user_services_blueprint([restricted_service])
        from flask import Flask

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
                    resp = client.get("/proxy/readonlyapi/v1/data")
                    assert resp.status_code == 200

    def test_path_filtering_blocks_disallowed(self, restricted_service):
        bp = create_user_services_blueprint([restricted_service])
        from flask import Flask

        app = Flask(__name__)
        app.register_blueprint(bp)
        with app.test_client() as client:
            with patch.dict(os.environ, {"READONLY_API_KEY": "key"}):
                resp = client.get("/proxy/readonlyapi/admin/settings")
                assert resp.status_code == 403
                assert "not allowed" in resp.get_json()["error"]

    def test_upstream_connection_failure_returns_502(self, tavily_service):
        bp = create_user_services_blueprint([tavily_service])
        from flask import Flask

        app = Flask(__name__)
        app.register_blueprint(bp)

        mock_conn = MagicMock()
        mock_conn.getresponse.side_effect = ConnectionError("refused")

        with app.test_client() as client:
            with patch.dict(os.environ, {"TAVILY_API_KEY": "key"}):
                with patch(
                    "foundry_git_safety.user_services_proxy.http.client.HTTPSConnection",
                    return_value=mock_conn,
                ):
                    resp = client.get("/proxy/tavily/v1/search")
                    assert resp.status_code == 502

    def test_query_string_preserved(self, tavily_service):
        bp = create_user_services_blueprint([tavily_service])
        from flask import Flask

        app = Flask(__name__)
        app.register_blueprint(bp)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheaders.return_value = []
        mock_response.read.side_effect = [b"", b""]

        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with app.test_client() as client:
            with patch.dict(os.environ, {"TAVILY_API_KEY": "key"}):
                with patch(
                    "foundry_git_safety.user_services_proxy.http.client.HTTPSConnection",
                    return_value=mock_conn,
                ):
                    resp = client.get("/proxy/tavily/v1/search?q=test")
                    assert resp.status_code == 200

                    # Verify the path includes query string
                    call_args = mock_conn.request.call_args
                    path = call_args[0][1] if call_args[0] else call_args[1].get("path", "")
                    assert "q=test" in path
