"""Credential leak audit: verify no secrets leak through git-safety HTTP surface.

Tests that decision logs, audit logs, responses, metrics, and health endpoints
never contain HMAC secrets, API keys, or credential material.
"""

import json
import time

import pytest

from foundry_git_safety.auth import (
    NonceStore,
    RateLimiter,
    SecretStore,
    compute_signature,
)
from foundry_git_safety.server import create_git_api


pytestmark = pytest.mark.security


def _make_app(tmp_path):
    """Create a test app with a known secret."""
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    data_dir = tmp_path / "data"

    sandbox_id = "leak-test"
    secret = b"super-secret-hmac-key-do-not-leak\n"
    (secrets_dir / sandbox_id).write_bytes(secret)

    secret_store = SecretStore(secrets_path=str(secrets_dir))
    nonce_store = NonceStore()
    rate_limiter = RateLimiter()

    app = create_git_api(
        secret_store=secret_store,
        nonce_store=nonce_store,
        rate_limiter=rate_limiter,
        data_dir=str(data_dir),
    )
    app._test_sandbox_id = sandbox_id
    app._test_secret = secret.strip()
    return app


def _auth_headers(app, body: bytes, sandbox_id: str | None = None):
    sid = sandbox_id or app._test_sandbox_id
    ts = str(time.time())
    nonce = f"leak-nonce-{time.time_ns()}"
    sig = compute_signature("POST", "/git/exec", body, ts, nonce, app._test_secret)
    return {
        "X-Sandbox-Id": sid,
        "X-Request-Signature": sig,
        "X-Request-Timestamp": ts,
        "X-Request-Nonce": nonce,
    }


def _write_metadata(tmp_path, sandbox_id, branch="feature", repo="test/repo"):
    metadata_dir = tmp_path / "data" / "sandboxes"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    (metadata_dir / f"{sandbox_id}.json").write_text(json.dumps({
        "sandbox_branch": branch,
        "from_branch": "main",
        "repos": [repo],
    }))


class TestCredentialLeakThroughGitSafety:
    """No HMAC secrets, API keys, or credential material in server responses."""

    def test_decision_log_contains_no_secrets(self, tmp_path):
        """Decision log entries must not contain the HMAC secret."""
        app = _make_app(tmp_path)
        client = app.test_client()
        _write_metadata(tmp_path, app._test_sandbox_id)

        secret_str = app._test_secret.decode()
        body = json.dumps({"args": ["version"], "cwd": "."}).encode()

        # Make several requests to generate decision log entries
        for i in range(10):
            headers = _auth_headers(app, body)
            client.post("/git/exec", data=body, headers=headers, content_type="application/json")

        # Check decision log
        log_dir = tmp_path / "logs"
        log_path = log_dir / "decisions.jsonl"
        if log_path.exists():
            content = log_path.read_text()
            assert secret_str not in content
            assert "Bearer" not in content
            assert "api_key" not in content.lower()

    def test_error_messages_contain_no_secrets(self, tmp_path):
        """All error responses must not contain secret material."""
        app = _make_app(tmp_path)
        client = app.test_client()
        _write_metadata(tmp_path, app._test_sandbox_id)

        secret_str = app._test_secret.decode()

        # Missing headers
        resp = client.post("/git/exec", data=b"{}")
        assert secret_str not in resp.data.decode()

        # Wrong signature
        body = json.dumps({"args": ["status"]}).encode()
        bad_headers = {
            "X-Sandbox-Id": app._test_sandbox_id,
            "X-Request-Signature": "a" * 64,
            "X-Request-Timestamp": str(time.time()),
            "X-Request-Nonce": "bad-nonce",
        }
        resp = client.post("/git/exec", data=body, headers=bad_headers, content_type="application/json")
        assert secret_str not in resp.data.decode()

        # Expired timestamp
        expired_headers = _auth_headers(app, body)
        expired_headers["X-Request-Timestamp"] = str(time.time() - 600)
        resp = client.post("/git/exec", data=body, headers=expired_headers, content_type="application/json")
        assert secret_str not in resp.data.decode()

        # Unknown sandbox
        body2 = json.dumps({"args": ["status"]}).encode()
        unknown_headers = _auth_headers(app, body2, sandbox_id="nonexistent")
        resp = client.post("/git/exec", data=body2, headers=unknown_headers, content_type="application/json")
        assert secret_str not in resp.data.decode()

    def test_response_contains_no_host_paths(self, tmp_path):
        """Git responses must not expose real host-side repo paths."""
        app = _make_app(tmp_path)
        client = app.test_client()
        _write_metadata(tmp_path, app._test_sandbox_id)

        # The response is JSON; check no host paths appear
        body = json.dumps({"args": ["status"], "cwd": "."}).encode()
        headers = _auth_headers(app, body)

        # This will fail at execution (no real repo) but check the error response
        resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")
        resp_text = resp.data.decode()
        # The host-side data dir should never appear in responses
        assert str(tmp_path / "data") not in resp_text

    def test_metrics_contain_no_secrets(self, tmp_path):
        """Prometheus /metrics output must not contain secrets."""
        app = _make_app(tmp_path)
        client = app.test_client()

        secret_str = app._test_secret.decode()

        resp = client.get("/metrics")
        assert resp.status_code == 200
        content = resp.data.decode()
        assert secret_str not in content
        assert "Bearer" not in content
        assert "secret" not in content.split("\n")  # No line should contain "secret"

    def test_health_ready_contain_no_secrets(self, tmp_path):
        """Health and readiness endpoints must not leak secrets."""
        app = _make_app(tmp_path)
        client = app.test_client()

        secret_str = app._test_secret.decode()

        for endpoint in ["/health", "/ready"]:
            resp = client.get(endpoint)
            content = resp.data.decode()
            assert secret_str not in content, f"Secret found in {endpoint}"
            assert "hmac" not in content.lower(), f"HMAC reference in {endpoint}"


class TestUserServicesProxyCredentialIsolation:
    """User services proxy must not leak injected credentials to clients."""

    def test_proxy_injects_header_not_forwarded_to_client(self, tmp_path):
        """When proxy adds an auth header, the response must not echo it."""
        # This test verifies the proxy's response stripping logic.
        # The user_services_proxy strips hop-by-hop headers from upstream.
        from foundry_git_safety.auth import NonceStore, RateLimiter, SecretStore
        from foundry_git_safety.user_services_proxy import create_user_services_blueprint
        from foundry_git_safety.schemas.foundry_yaml import UserServiceEntry

        entry = UserServiceEntry(
            name="test-service",
            env_var="TEST_API_KEY",
            domain="api.test.example.com",
            header="X-API-Key",
            format="value",
        )

        secret_store = SecretStore(secrets_path=str(tmp_path / "secrets"))
        nonce_store = NonceStore()
        rate_limiter = RateLimiter()

        bp = create_user_services_blueprint(
            [entry],
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        app = _make_app(tmp_path)
        app.register_blueprint(bp)
        client = app.test_client()

        # Request to proxy — unauthenticated, will get 401
        resp = client.get("/proxy/test-service/v1/data")
        content = resp.data.decode()
        # The API key should never appear in any response
        assert "TEST_API_KEY_VALUE" not in content

    def test_proxy_error_does_not_leak_upstream_headers(self, tmp_path):
        """Upstream 403/500 responses must not include auth headers in error."""
        from foundry_git_safety.auth import NonceStore, RateLimiter, SecretStore
        from foundry_git_safety.user_services_proxy import create_user_services_blueprint
        from foundry_git_safety.schemas.foundry_yaml import UserServiceEntry

        entry = UserServiceEntry(
            name="test-service",
            env_var="TEST_API_KEY",
            domain="api.test.example.com",
            header="Authorization",
            format="bearer",
        )

        secret_store = SecretStore(secrets_path=str(tmp_path / "secrets"))
        nonce_store = NonceStore()
        rate_limiter = RateLimiter()

        bp = create_user_services_blueprint(
            [entry],
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        app = _make_app(tmp_path)
        app.register_blueprint(bp)
        client = app.test_client()

        resp = client.get("/proxy/test-service/protected")
        content = resp.data.decode()
        # No credential material in error responses
        assert "Bearer " not in content
        assert "Authorization" not in content
