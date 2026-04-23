"""Security tests for proxy authentication hardening (§3.6).

Validates that:
- Unauthenticated callers are rejected on both proxy paths
- Sandbox identity is verified via HMAC (no trusted caller-supplied header)
- One sandbox cannot spoof another's identity
- Rate limits use verified sandbox identity
- No shared "unknown" bucket for unauthenticated callers
"""

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
from foundry_git_safety.deep_policy_engine import CircuitBreaker, PolicySet
from foundry_git_safety.deep_policy_proxy import create_deep_policy_blueprint
from foundry_git_safety.schemas.foundry_yaml import (
    DeepPolicyRule,
    DeepPolicyServiceConfig,
    FoundryConfig,
    UserServiceEntry,
)
from foundry_git_safety.server import create_git_api
from foundry_git_safety.user_services_proxy import create_user_services_blueprint


pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_auth_headers(
    method: str,
    path: str,
    body: bytes,
    secret: bytes,
    sandbox_id: str,
) -> dict[str, str]:
    """Build HMAC auth headers for a request."""
    ts = str(time.time())
    nonce = f"test-nonce-{time.time_ns()}"
    sig = compute_signature(method, path, body, ts, nonce, secret)
    return {
        "X-Sandbox-Id": sandbox_id,
        "X-Request-Signature": sig,
        "X-Request-Timestamp": ts,
        "X-Request-Nonce": nonce,
    }


def _make_app_with_user_services(tmp_path, sandbox_id="test-sandbox", secret=b"test-secret-key-here-0123456789abcdef\n"):
    """Create a test app with user services proxy blueprint and registered sandbox."""
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / sandbox_id).write_bytes(secret)

    secret_store = SecretStore(secrets_path=str(secrets_dir))
    nonce_store = NonceStore()
    rate_limiter = RateLimiter()

    service = UserServiceEntry(
        name="Tavily",
        env_var="TAVILY_API_KEY",
        domain="api.tavily.com",
        header="Authorization",
        format="bearer",
    )

    app = create_git_api(
        secret_store=secret_store,
        nonce_store=nonce_store,
        rate_limiter=rate_limiter,
    )
    bp = create_user_services_blueprint(
        [service],
        secret_store=secret_store,
        nonce_store=nonce_store,
        rate_limiter=rate_limiter,
    )
    app.register_blueprint(bp)

    app._test_sandbox_id = sandbox_id
    app._test_secret = secret.rstrip(b"\n")
    app._test_secrets_dir = secrets_dir
    return app


def _make_app_with_deep_policy(tmp_path, sandbox_id="test-sandbox", secret=b"test-secret-key-here-0123456789abcdef\n"):
    """Create a test app with deep policy proxy blueprint and registered sandbox."""
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / sandbox_id).write_bytes(secret)

    secret_store = SecretStore(secrets_path=str(secrets_dir))
    nonce_store = NonceStore()
    rate_limiter = RateLimiter()

    rule = DeepPolicyRule(
        method="GET", path_pattern=r"^/v1/.*$", action="allow", priority=10,
    )
    svc = DeepPolicyServiceConfig(
        slug="test-svc", host="api.example.com",
        rules=[rule], default_action="deny",
    )
    ps = PolicySet(slug="test-svc", service_config=svc)
    cb = CircuitBreaker(threshold=5, recovery_seconds=30)

    app = create_git_api(
        secret_store=secret_store,
        nonce_store=nonce_store,
        rate_limiter=rate_limiter,
    )
    bp = create_deep_policy_blueprint(
        {"test-svc": ps}, {"test-svc": svc},
        secret_store=secret_store, nonce_store=nonce_store,
        rate_limiter=rate_limiter, circuit_breaker=cb,
    )
    app.register_blueprint(bp)

    app._test_sandbox_id = sandbox_id
    app._test_secret = secret.rstrip(b"\n")
    return app


# ---------------------------------------------------------------------------
# Test: Unauthorized sandbox cannot use a service credential
# ---------------------------------------------------------------------------

class TestUnauthorizedSandboxCannotUseService:
    """Sandbox without a valid HMAC secret cannot access user service proxy."""

    def test_create_git_api_registers_user_services_from_config(self, tmp_path):
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "test-sandbox").write_bytes(
            b"test-secret-key-here-0123456789abcdef\n"
        )

        app = create_git_api(
            secret_store=SecretStore(secrets_path=str(secrets_dir)),
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
            config=FoundryConfig(
                user_services=[
                    {
                        "name": "Tavily",
                        "env_var": "TAVILY_API_KEY",
                        "domain": "api.tavily.com",
                    }
                ],
            ),
        )

        with app.test_client() as client:
            resp = client.get("/proxy/health")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["services"][0]["slug"] == "tavily"

    def test_no_auth_headers_rejected(self, tmp_path):
        app = _make_app_with_user_services(tmp_path)
        with app.test_client() as client:
            with patch.dict(os.environ, {"TAVILY_API_KEY": "tvly-secret"}):
                resp = client.get("/proxy/tavily/v1/search")
                assert resp.status_code == 401
                data = resp.get_json()
                assert "authentication" in data["error"].lower() or "missing" in data["error"].lower()

    def test_wrong_secret_rejected(self, tmp_path):
        app = _make_app_with_user_services(tmp_path)
        headers = _make_auth_headers(
            "GET", "/proxy/tavily/v1/search", b"",
            b"wrong-secret-00000000000000000000000000000000",
            "test-sandbox",
        )
        with app.test_client() as client:
            with patch.dict(os.environ, {"TAVILY_API_KEY": "tvly-secret"}):
                resp = client.get("/proxy/tavily/v1/search", headers=headers)
                assert resp.status_code == 401
                assert "signature" in resp.get_json()["error"].lower()

    def test_unknown_sandbox_rejected(self, tmp_path):
        app = _make_app_with_user_services(tmp_path)
        headers = _make_auth_headers(
            "GET", "/proxy/tavily/v1/search", b"",
            app._test_secret,
            "nonexistent-sandbox",
        )
        with app.test_client() as client:
            with patch.dict(os.environ, {"TAVILY_API_KEY": "tvly-secret"}):
                resp = client.get("/proxy/tavily/v1/search", headers=headers)
                assert resp.status_code == 401

    def test_health_endpoint_remains_unauthenticated(self, tmp_path):
        app = _make_app_with_user_services(tmp_path)
        with app.test_client() as client:
            resp = client.get("/proxy/health")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Test: One sandbox cannot spoof another's identity
# ---------------------------------------------------------------------------

class TestSandboxSpoofing:
    """Sandbox A cannot impersonate sandbox B by spoofing X-Sandbox-Id."""

    def test_cross_sandbox_signature_rejected_user_services(self, tmp_path):
        """Signing with sandbox-A's secret but claiming sandbox-B identity fails."""
        secret_a = b"sandbox-a-secret-000000000000000000000000\n"
        secret_b = b"sandbox-b-secret-000000000000000000000000\n"

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "sandbox-a").write_bytes(secret_a)
        (secrets_dir / "sandbox-b").write_bytes(secret_b)

        secret_store = SecretStore(secrets_path=str(secrets_dir))
        nonce_store = NonceStore()
        rate_limiter = RateLimiter()

        service = UserServiceEntry(
            name="Tavily", env_var="TAVILY_API_KEY",
            domain="api.tavily.com", header="Authorization", format="bearer",
        )

        app = create_git_api(
            secret_store=secret_store, nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        bp = create_user_services_blueprint(
            [service], secret_store=secret_store,
            nonce_store=nonce_store, rate_limiter=rate_limiter,
        )
        app.register_blueprint(bp)

        # Sign with sandbox-a's secret but set X-Sandbox-Id to sandbox-b
        headers = _make_auth_headers(
            "GET", "/proxy/tavily/v1/search", b"",
            secret_a.rstrip(b"\n"), "sandbox-b",
        )
        with app.test_client() as client:
            with patch.dict(os.environ, {"TAVILY_API_KEY": "key"}):
                resp = client.get("/proxy/tavily/v1/search", headers=headers)
                assert resp.status_code == 401
                assert "signature" in resp.get_json()["error"].lower()

    def test_cross_sandbox_signature_rejected_deep_policy(self, tmp_path):
        """Signing with sandbox-A's secret but claiming sandbox-B identity fails on deep-policy."""
        secret_a = b"sandbox-a-secret-000000000000000000000000\n"
        secret_b = b"sandbox-b-secret-000000000000000000000000\n"

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "sandbox-a").write_bytes(secret_a)
        (secrets_dir / "sandbox-b").write_bytes(secret_b)

        secret_store = SecretStore(secrets_path=str(secrets_dir))
        nonce_store = NonceStore()
        rate_limiter = RateLimiter()

        rule = DeepPolicyRule(
            method="GET", path_pattern=r"^/v1/.*$", action="allow", priority=10,
        )
        svc = DeepPolicyServiceConfig(
            slug="test-svc", host="api.example.com",
            rules=[rule], default_action="deny",
        )
        ps = PolicySet(slug="test-svc", service_config=svc)
        cb = CircuitBreaker(threshold=5, recovery_seconds=30)

        app = create_git_api(
            secret_store=secret_store, nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        bp = create_deep_policy_blueprint(
            {"test-svc": ps}, {"test-svc": svc},
            secret_store=secret_store, nonce_store=nonce_store,
            rate_limiter=rate_limiter, circuit_breaker=cb,
        )
        app.register_blueprint(bp)

        headers = _make_auth_headers(
            "GET", "/deep-policy/test-svc/v1/items", b"",
            secret_a.rstrip(b"\n"), "sandbox-b",
        )
        with app.test_client() as client:
            resp = client.get("/deep-policy/test-svc/v1/items", headers=headers)
            assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Test: Rate limits use verified sandbox identity
# ---------------------------------------------------------------------------

class TestRateLimitsUseVerifiedIdentity:
    """Rate limiting uses the HMAC-verified sandbox_id, not caller-supplied headers."""

    def test_independent_rate_limits_per_sandbox(self, tmp_path):
        """Two different sandboxes have independent rate limits after auth."""
        secret_a = b"sandbox-a-secret-000000000000000000000000\n"
        secret_b = b"sandbox-b-secret-000000000000000000000000\n"

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "sandbox-a").write_bytes(secret_a)
        (secrets_dir / "sandbox-b").write_bytes(secret_b)

        secret_store = SecretStore(secrets_path=str(secrets_dir))
        nonce_store = NonceStore()
        rate_limiter = RateLimiter(burst=3, sustained=3)

        rule = DeepPolicyRule(
            method="GET", path_pattern=r"^/v1/.*$", action="allow", priority=10,
        )
        svc = DeepPolicyServiceConfig(
            slug="test-svc", host="api.example.com",
            rules=[rule], default_action="deny",
        )
        ps = PolicySet(slug="test-svc", service_config=svc)
        cb = CircuitBreaker(threshold=5, recovery_seconds=30)

        app = create_git_api(
            secret_store=secret_store, nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        bp = create_deep_policy_blueprint(
            {"test-svc": ps}, {"test-svc": svc},
            secret_store=secret_store, nonce_store=nonce_store,
            rate_limiter=rate_limiter, circuit_breaker=cb,
        )
        app.register_blueprint(bp)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheaders.return_value = [("Content-Type", "text/plain")]
        # Return a fresh response for each request (read returns b"" on second call)
        def _make_response(*args, **kwargs):
            r = MagicMock()
            r.status = 200
            r.getheaders.return_value = [("Content-Type", "text/plain")]
            r.read.side_effect = [b"ok", b""]
            return r

        mock_conn = MagicMock()
        mock_conn.getresponse.side_effect = _make_response

        with app.test_client() as client:
            with patch(
                "foundry_git_safety.deep_policy_proxy.http.client.HTTPSConnection",
                return_value=mock_conn,
            ):
                # Exhaust sandbox-a's rate limit (3 burst)
                for i in range(3):
                    headers = _make_auth_headers(
                        "GET", "/deep-policy/test-svc/v1/items", b"",
                        secret_a.rstrip(b"\n"), "sandbox-a",
                    )
                    resp = client.get("/deep-policy/test-svc/v1/items", headers=headers)
                    assert resp.status_code == 200, f"Request {i} failed"

                # sandbox-a should now be rate-limited
                headers_a = _make_auth_headers(
                    "GET", "/deep-policy/test-svc/v1/items", b"",
                    secret_a.rstrip(b"\n"), "sandbox-a",
                )
                resp_a = client.get("/deep-policy/test-svc/v1/items", headers=headers_a)
                assert resp_a.status_code == 429

                # sandbox-b should still have its own budget
                headers_b = _make_auth_headers(
                    "GET", "/deep-policy/test-svc/v1/items", b"",
                    secret_b.rstrip(b"\n"), "sandbox-b",
                )
                resp_b = client.get("/deep-policy/test-svc/v1/items", headers=headers_b)
                assert resp_b.status_code == 200


# ---------------------------------------------------------------------------
# Test: Unauthenticated callers are rejected on documented path
# ---------------------------------------------------------------------------

class TestUnauthenticatedRejection:
    """All unauthenticated proxy requests are rejected with 401."""

    def test_user_services_proxy_rejects_no_auth(self, tmp_path):
        app = _make_app_with_user_services(tmp_path)
        with app.test_client() as client:
            resp = client.get("/proxy/tavily/v1/search")
            assert resp.status_code == 401
            data = resp.get_json()
            assert "Missing authentication headers" in data["error"]

    def test_deep_policy_proxy_rejects_no_auth(self, tmp_path):
        app = _make_app_with_deep_policy(tmp_path)
        with app.test_client() as client:
            resp = client.get("/deep-policy/test-svc/v1/items")
            assert resp.status_code == 401
            data = resp.get_json()
            assert "Missing authentication headers" in data["error"]

    def test_no_unknown_rate_bucket(self, tmp_path):
        """Unauthenticated requests are rejected with 401, not rate-limited by sandbox bucket.

        The IP throttle (pre-auth) may return 429 after many requests from the
        same IP, but the per-sandbox "unknown" rate-limit bucket should never
        be reached because auth fails first.
        """
        app = _make_app_with_deep_policy(tmp_path)
        with app.test_client() as client:
            # Stay under the IP throttle limit (100 req/60s) — all should be 401
            for i in range(50):
                resp = client.get("/deep-policy/test-svc/v1/items")
                assert resp.status_code == 401, (
                    f"Request {i}: expected 401, got {resp.status_code}"
                )

    def test_partial_headers_rejected(self, tmp_path):
        """Providing some but not all auth headers still gets 401."""
        app = _make_app_with_deep_policy(tmp_path)
        with app.test_client() as client:
            resp = client.get(
                "/deep-policy/test-svc/v1/items",
                headers={"X-Sandbox-Id": "test-sandbox"},
            )
            assert resp.status_code == 401

    def test_expired_timestamp_rejected(self, tmp_path):
        """Request with expired timestamp gets 401."""
        app = _make_app_with_deep_policy(tmp_path)
        ts = str(time.time() - 600)  # 10 minutes ago (window is 5 min)
        nonce = f"test-nonce-{time.time_ns()}"
        sig = compute_signature(
            "GET", "/deep-policy/test-svc/v1/items", b"",
            ts, nonce, app._test_secret,
        )
        with app.test_client() as client:
            resp = client.get(
                "/deep-policy/test-svc/v1/items",
                headers={
                    "X-Sandbox-Id": app._test_sandbox_id,
                    "X-Request-Signature": sig,
                    "X-Request-Timestamp": ts,
                    "X-Request-Nonce": nonce,
                },
            )
            assert resp.status_code == 401
            assert "clock window" in resp.get_json()["error"].lower()

    def test_deep_policy_health_remains_unauthenticated(self, tmp_path):
        app = _make_app_with_deep_policy(tmp_path)
        with app.test_client() as client:
            resp = client.get("/deep-policy/health")
            assert resp.status_code == 200
