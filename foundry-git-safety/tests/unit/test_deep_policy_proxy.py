"""Tests for the deep policy proxy Flask Blueprint."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from foundry_git_safety.auth import RateLimiter
from foundry_git_safety.deep_policy_engine import CircuitBreaker, PolicySet
from foundry_git_safety.deep_policy_proxy import create_deep_policy_blueprint
from foundry_git_safety.schemas.foundry_yaml import (
    DeepPolicyRule,
    DeepPolicyServiceConfig,
)


def _make_policy_set(
    slug: str = "test-svc",
    host: str = "api.example.com",
    rules: list[dict] | None = None,
    default_action: str = "deny",
) -> tuple[dict[str, PolicySet], dict[str, DeepPolicyServiceConfig]]:
    """Build policy_sets and services dicts for testing."""
    rule_defs = rules or [
        {"method": "GET", "path_pattern": r"^/v1/.*$", "action": "allow", "priority": 10},
        {"method": "DELETE", "path_pattern": r"^/.*$", "action": "deny",
         "reason": "no deletes", "priority": 100},
    ]
    svc = DeepPolicyServiceConfig(
        slug=slug,
        host=host,
        rules=[DeepPolicyRule(**r) for r in rule_defs],
        default_action=default_action,
    )
    ps = PolicySet(slug=slug, service_config=svc)
    return {slug: ps}, {slug: svc}


@pytest.fixture
def app_client():
    """Create a Flask test client with a basic deep policy blueprint."""
    from foundry_git_safety.server import create_git_api

    policy_sets, services = _make_policy_set()
    limiter = RateLimiter()
    cb = CircuitBreaker(threshold=5, recovery_seconds=30)

    app = create_git_api(rate_limiter=limiter)
    bp = create_deep_policy_blueprint(policy_sets, services, limiter, cb)
    app.register_blueprint(bp)
    return app.test_client()


class TestProxyHealth:
    def test_health_returns_services(self, app_client):
        resp = app_client.get("/deep-policy/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "services" in data
        assert len(data["services"]) == 1
        assert data["services"][0]["slug"] == "test-svc"
        assert data["services"][0]["circuit_breaker_state"] == "closed"


class TestProxyDeny:
    def test_blocked_request_returns_403(self, app_client):
        resp = app_client.delete("/deep-policy/test-svc/v1/resource")
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["error"] == "BLOCKED"
        assert "no deletes" in data["message"]
        assert resp.headers.get("X-Sandbox-Blocked") == "true"


class TestProxyAllow:
    @patch("foundry_git_safety.deep_policy_proxy.http.client.HTTPSConnection")
    def test_allowed_request_forwarded(self, mock_conn_cls, app_client):
        mock_conn = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheaders.return_value = [("Content-Type", "application/json")]
        mock_response.read.side_effect = [b'{"ok": true}', b""]
        mock_conn.getresponse.return_value = mock_response
        mock_conn_cls.return_value = mock_conn

        resp = app_client.get("/deep-policy/test-svc/v1/items")
        assert resp.status_code == 200


class TestProxyUnknownService:
    def test_unknown_slug_returns_404(self, app_client):
        resp = app_client.get("/deep-policy/nonexistent/path")
        assert resp.status_code == 404


class TestProxyCircuitBreaker:
    def test_open_breaker_returns_503(self):
        from foundry_git_safety.server import create_git_api

        policy_sets, services = _make_policy_set()
        limiter = RateLimiter()
        cb = CircuitBreaker(threshold=1, recovery_seconds=60)
        cb.record_failure("test-svc")
        assert cb.is_open("test-svc")

        app = create_git_api(rate_limiter=limiter)
        bp = create_deep_policy_blueprint(policy_sets, services, limiter, cb)
        app.register_blueprint(bp)
        client = app.test_client()

        resp = app_client_get(client, "GET", "/deep-policy/test-svc/v1/items")
        assert resp.status_code == 503


def app_client_get(client, method, path):
    if method == "GET":
        return client.get(path)
    return client.get(path)


class TestProxyUpstreamFailure:
    @patch("foundry_git_safety.deep_policy_proxy.http.client.HTTPSConnection")
    def test_connection_failure_returns_502(self, mock_conn_cls):
        from foundry_git_safety.server import create_git_api

        policy_sets, services = _make_policy_set()
        limiter = RateLimiter()
        cb = CircuitBreaker(threshold=5, recovery_seconds=30)

        app = create_git_api(rate_limiter=limiter)
        bp = create_deep_policy_blueprint(policy_sets, services, limiter, cb)
        app.register_blueprint(bp)
        client = app.test_client()

        mock_conn_cls.side_effect = Exception("connection failed")
        resp = client.get("/deep-policy/test-svc/v1/items")
        assert resp.status_code == 502

    @patch("foundry_git_safety.deep_policy_proxy.http.client.HTTPSConnection")
    def test_upstream_5xx_records_circuit_breaker_failure(self, mock_conn_cls):
        from foundry_git_safety.server import create_git_api

        policy_sets, services = _make_policy_set()
        limiter = RateLimiter()
        cb = CircuitBreaker(threshold=3, recovery_seconds=60)

        app = create_git_api(rate_limiter=limiter)
        bp = create_deep_policy_blueprint(policy_sets, services, limiter, cb)
        app.register_blueprint(bp)
        client = app.test_client()

        mock_conn = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 503
        mock_response.getheaders.return_value = []
        mock_response.read.return_value = b""
        mock_conn.getresponse.return_value = mock_response
        mock_conn_cls.return_value = mock_conn

        for _ in range(3):
            client.get("/deep-policy/test-svc/v1/items")

        assert cb.get_state("test-svc") == "open"


class TestProxyNoHost:
    def test_missing_host_returns_502(self):
        from foundry_git_safety.server import create_git_api

        policy_sets, services = _make_policy_set(host="")
        limiter = RateLimiter()
        cb = CircuitBreaker()

        app = create_git_api(rate_limiter=limiter)
        bp = create_deep_policy_blueprint(policy_sets, services, limiter, cb)
        app.register_blueprint(bp)
        client = app.test_client()

        resp = client.get("/deep-policy/test-svc/v1/items")
        assert resp.status_code == 502
