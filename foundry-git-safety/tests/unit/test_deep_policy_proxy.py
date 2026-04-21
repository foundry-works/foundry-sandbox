"""Tests for the deep policy proxy Flask Blueprint."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from foundry_git_safety.auth import (
    NonceStore,
    RateLimiter,
    SecretStore,
    compute_signature,
)
from foundry_git_safety.deep_policy_engine import CircuitBreaker, PolicySet
from foundry_git_safety.deep_policy_proxy import create_deep_policy_blueprint
from foundry_git_safety.schemas.foundry_yaml import (
    DeepPolicyRule,
    DeepPolicyServiceConfig,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEST_SANDBOX = "test-sandbox"
_TEST_SECRET = b"test-secret-key-for-deep-policy-unit-tests-0123456\n"


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
def app_client(auth_stores):
    """Create a Flask test client with a basic deep policy blueprint."""
    from foundry_git_safety.server import create_git_api

    policy_sets, services = _make_policy_set()
    secret_store, nonce_store, rate_limiter = auth_stores
    cb = CircuitBreaker(threshold=5, recovery_seconds=30)

    app = create_git_api(
        secret_store=secret_store,
        nonce_store=nonce_store,
        rate_limiter=rate_limiter,
    )
    bp = create_deep_policy_blueprint(
        policy_sets, services,
        secret_store=secret_store, nonce_store=nonce_store,
        rate_limiter=rate_limiter, circuit_breaker=cb,
    )
    app.register_blueprint(bp)
    return app.test_client()


def _signed_request(client, path, method="GET", body: bytes = b""):
    """Make an HTTP request with valid auth headers."""
    headers = _auth_headers(method, path, body)
    http_method = getattr(client, method.lower())
    if body:
        return http_method(path, headers=headers, data=body)
    return http_method(path, headers=headers)


class TestProxyHealth:
    def test_health_returns_services(self, app_client):
        resp = app_client.get("/deep-policy/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "services" in data
        assert len(data["services"]) == 1
        assert data["services"][0]["slug"] == "test-svc"
        assert data["services"][0]["circuit_breaker_state"] == "closed"


class TestProxyAuth:
    def test_no_auth_returns_401(self, app_client):
        resp = app_client.get("/deep-policy/test-svc/v1/items")
        assert resp.status_code == 401


class TestProxyDeny:
    def test_blocked_request_returns_403(self, app_client):
        resp = _signed_request(client=app_client, path="/deep-policy/test-svc/v1/resource", method="DELETE")
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

        resp = _signed_request(client=app_client, path="/deep-policy/test-svc/v1/items")
        assert resp.status_code == 200


class TestProxyUnknownService:
    def test_unknown_slug_returns_404(self, app_client):
        resp = _signed_request(client=app_client, path="/deep-policy/nonexistent/path")
        assert resp.status_code == 404


class TestProxyCircuitBreaker:
    def test_open_breaker_returns_503(self, tmp_path):
        from foundry_git_safety.server import create_git_api

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / _TEST_SANDBOX).write_bytes(_TEST_SECRET)

        secret_store = SecretStore(secrets_path=str(secrets_dir))
        nonce_store = NonceStore()
        rate_limiter = RateLimiter()

        policy_sets, services = _make_policy_set()
        cb = CircuitBreaker(threshold=1, recovery_seconds=60)
        cb.record_failure("test-svc")
        assert cb.is_open("test-svc")

        app = create_git_api(
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        bp = create_deep_policy_blueprint(
            policy_sets, services,
            secret_store=secret_store, nonce_store=nonce_store,
            rate_limiter=rate_limiter, circuit_breaker=cb,
        )
        app.register_blueprint(bp)
        client = app.test_client()

        resp = _signed_request(client=client, path="/deep-policy/test-svc/v1/items")
        assert resp.status_code == 503


class TestProxyUpstreamFailure:
    @patch("foundry_git_safety.deep_policy_proxy.http.client.HTTPSConnection")
    def test_connection_failure_returns_502(self, mock_conn_cls, tmp_path):
        from foundry_git_safety.server import create_git_api

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / _TEST_SANDBOX).write_bytes(_TEST_SECRET)

        secret_store = SecretStore(secrets_path=str(secrets_dir))
        nonce_store = NonceStore()
        rate_limiter = RateLimiter()

        policy_sets, services = _make_policy_set()
        cb = CircuitBreaker(threshold=5, recovery_seconds=30)

        app = create_git_api(
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        bp = create_deep_policy_blueprint(
            policy_sets, services,
            secret_store=secret_store, nonce_store=nonce_store,
            rate_limiter=rate_limiter, circuit_breaker=cb,
        )
        app.register_blueprint(bp)
        client = app.test_client()

        mock_conn_cls.side_effect = Exception("connection failed")
        resp = _signed_request(client=client, path="/deep-policy/test-svc/v1/items")
        assert resp.status_code == 502

    @patch("foundry_git_safety.deep_policy_proxy.http.client.HTTPSConnection")
    def test_upstream_5xx_records_circuit_breaker_failure(self, mock_conn_cls, tmp_path):
        from foundry_git_safety.server import create_git_api

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / _TEST_SANDBOX).write_bytes(_TEST_SECRET)

        secret_store = SecretStore(secrets_path=str(secrets_dir))
        nonce_store = NonceStore()
        rate_limiter = RateLimiter()

        policy_sets, services = _make_policy_set()
        cb = CircuitBreaker(threshold=3, recovery_seconds=60)

        app = create_git_api(
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        bp = create_deep_policy_blueprint(
            policy_sets, services,
            secret_store=secret_store, nonce_store=nonce_store,
            rate_limiter=rate_limiter, circuit_breaker=cb,
        )
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
            resp = _signed_request(client=client, path="/deep-policy/test-svc/v1/items")
            assert resp.status_code == 503

        assert cb.get_state("test-svc") == "open"


class TestProxyNoHost:
    def test_missing_host_returns_502(self, tmp_path):
        from foundry_git_safety.server import create_git_api

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / _TEST_SANDBOX).write_bytes(_TEST_SECRET)

        secret_store = SecretStore(secrets_path=str(secrets_dir))
        nonce_store = NonceStore()
        rate_limiter = RateLimiter()

        policy_sets, services = _make_policy_set(host="")
        cb = CircuitBreaker()

        app = create_git_api(
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        bp = create_deep_policy_blueprint(
            policy_sets, services,
            secret_store=secret_store, nonce_store=nonce_store,
            rate_limiter=rate_limiter, circuit_breaker=cb,
        )
        app.register_blueprint(bp)
        client = app.test_client()

        resp = _signed_request(client=client, path="/deep-policy/test-svc/v1/items")
        assert resp.status_code == 502
