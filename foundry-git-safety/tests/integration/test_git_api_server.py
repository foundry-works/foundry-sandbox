"""Integration tests for the git API HTTP server (Flask test client).

Covers the full request path: authentication, rate limiting, command validation,
and error handling through the Flask application created by create_git_api().
"""

import json
import time
import uuid

import pytest

from foundry_git_safety.server import create_git_api
from foundry_git_safety.auth import (
    RateLimiter,
    SecretStore,
    compute_signature,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_authed_request(
    client,
    auth_headers_factory,
    body: dict,
    sandbox_id: str | None = None,
    timestamp_override: str | None = None,
):
    """POST /git/exec with properly signed headers."""
    body_bytes = json.dumps(body).encode("utf-8")
    headers = auth_headers_factory(
        sandbox_id=sandbox_id,
        body=body_bytes,
        timestamp_override=timestamp_override,
    )
    return client.post(
        "/git/exec",
        data=body_bytes,
        headers=headers,
        content_type="application/json",
    )


# ---------------------------------------------------------------------------
# TestHealthEndpoint
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    """GET /health returns 200 with status ok."""

    def test_health_returns_200(self, git_api_client):
        resp = git_api_client.get("/health")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"


# ---------------------------------------------------------------------------
# TestAuthentication
# ---------------------------------------------------------------------------


class TestAuthentication:
    """Authentication enforcement on POST /git/exec."""

    def test_missing_headers_returns_401(self, git_api_client):
        """Request with no auth headers returns 401."""
        resp = git_api_client.post(
            "/git/exec",
            data=json.dumps({"args": ["status"]}),
            content_type="application/json",
        )
        assert resp.status_code == 401
        data = json.loads(resp.data)
        assert "Missing authentication headers" in data["error"]

    def test_missing_signature_returns_401(self, git_api_client):
        """Request with sandbox-id but missing signature returns 401."""
        resp = git_api_client.post(
            "/git/exec",
            data=json.dumps({"args": ["status"]}),
            content_type="application/json",
            headers={
                "X-Sandbox-Id": "test-sandbox-1",
                "X-Request-Timestamp": str(time.time()),
                "X-Request-Nonce": uuid.uuid4().hex,
            },
        )
        assert resp.status_code == 401

    def test_invalid_signature_returns_401(self, git_api_client):
        """Request with wrong HMAC signature returns 401."""
        resp = git_api_client.post(
            "/git/exec",
            data=json.dumps({"args": ["status"]}),
            content_type="application/json",
            headers={
                "X-Sandbox-Id": "test-sandbox-1",
                "X-Request-Timestamp": str(time.time()),
                "X-Request-Nonce": uuid.uuid4().hex,
                "X-Request-Signature": "0" * 64,
            },
        )
        assert resp.status_code == 401
        data = json.loads(resp.data)
        assert "Invalid signature" in data["error"]

    def test_valid_request_passes_auth(
        self, git_api_client, auth_headers, sandbox_metadata_file
    ):
        """Valid HMAC-signed request passes authentication (may fail later at
        command validation if no real repo exists, but should not 401)."""
        # Write metadata so the server can resolve sandbox identity
        sandbox_metadata_file("test-sandbox-1", {
            "sandbox_branch": "sandbox/test-integration",
            "from_branch": "main",
            "repo_root": "/tmp/nonexistent-repo",
        })

        body_bytes = json.dumps({"args": ["status"]}).encode("utf-8")
        headers = auth_headers(body=body_bytes)
        resp = git_api_client.post(
            "/git/exec",
            data=body_bytes,
            headers=headers,
            content_type="application/json",
        )
        # Should NOT be 401 (auth passed); may be 422 from execution
        assert resp.status_code != 401

    def test_expired_timestamp_returns_401(self, git_api_client, auth_headers):
        """Timestamp outside the 5-minute clock window returns 401."""
        old_timestamp = str(time.time() - 600)  # 10 minutes ago
        body_bytes = json.dumps({"args": ["status"]}).encode("utf-8")
        headers = auth_headers(
            body=body_bytes,
            timestamp_override=old_timestamp,
        )
        resp = git_api_client.post(
            "/git/exec",
            data=body_bytes,
            headers=headers,
            content_type="application/json",
        )
        assert resp.status_code == 401
        data = json.loads(resp.data)
        assert "timestamp" in data["error"].lower()

    def test_unknown_sandbox_returns_401(self, git_api_client, auth_headers):
        """A sandbox_id with no secret file returns 401."""
        body_bytes = json.dumps({"args": ["status"]}).encode("utf-8")
        headers = auth_headers(
            sandbox_id="nonexistent-sandbox",
            body=body_bytes,
        )
        resp = git_api_client.post(
            "/git/exec",
            data=body_bytes,
            headers=headers,
            content_type="application/json",
        )
        assert resp.status_code == 401
        data = json.loads(resp.data)
        assert "Unknown sandbox" in data["error"]


# ---------------------------------------------------------------------------
# TestRateLimiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Rate limiting enforcement on POST /git/exec."""

    @pytest.mark.slow
    def test_ip_throttle_triggers_429(self, tmp_path):
        """Rapid requests beyond the IP throttle limit trigger 429."""
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "sbx-rl").write_bytes(b"rl-secret-key\n")

        # Use a very low IP throttle limit
        rate_limiter = RateLimiter(ip_window=60, ip_max=3)
        secret_store = SecretStore(secrets_path=str(secrets_dir))

        app = create_git_api(
            secret_store=secret_store,
            rate_limiter=rate_limiter,
            data_dir=str(tmp_path / "data"),
        )
        client = app.test_client()

        body_bytes = json.dumps({"args": ["status"]}).encode("utf-8")

        for i in range(3):
            ts = str(time.time())
            nonce = uuid.uuid4().hex
            sig = compute_signature(
                "POST", "/git/exec", body_bytes, ts, nonce, b"rl-secret-key"
            )
            resp = client.post(
                "/git/exec",
                data=body_bytes,
                headers={
                    "X-Sandbox-Id": "sbx-rl",
                    "X-Request-Timestamp": ts,
                    "X-Request-Nonce": nonce,
                    "X-Request-Signature": sig,
                },
                content_type="application/json",
            )
            # First 3 should not be rate limited at the IP level
            # (they may 401 for other reasons, but not 429)

        # 4th request should be IP-throttled
        ts = str(time.time())
        nonce = uuid.uuid4().hex
        sig = compute_signature(
            "POST", "/git/exec", body_bytes, ts, nonce, b"rl-secret-key"
        )
        resp = client.post(
            "/git/exec",
            data=body_bytes,
            headers={
                "X-Sandbox-Id": "sbx-rl",
                "X-Request-Timestamp": ts,
                "X-Request-Nonce": nonce,
                "X-Request-Signature": sig,
            },
            content_type="application/json",
        )
        assert resp.status_code == 429

    @pytest.mark.slow
    def test_sandbox_rate_limit_triggers_429(self, tmp_path):
        """Per-sandbox rate limit triggers 429 when burst is exhausted."""
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "sbx-burst").write_bytes(b"burst-key\n")

        rate_limiter = RateLimiter(burst=2, sustained=1, ip_window=60, ip_max=1000)
        secret_store = SecretStore(secrets_path=str(secrets_dir))

        app = create_git_api(
            secret_store=secret_store,
            rate_limiter=rate_limiter,
            data_dir=str(tmp_path / "data"),
        )
        client = app.test_client()

        body_bytes = json.dumps({"args": ["status"]}).encode("utf-8")

        # Exhaust the burst (2 requests), bypassing IP throttle limit
        for i in range(2):
            ts = str(time.time())
            nonce = uuid.uuid4().hex
            sig = compute_signature(
                "POST", "/git/exec", body_bytes, ts, nonce, b"burst-key"
            )
            client.post(
                "/git/exec",
                data=body_bytes,
                headers={
                    "X-Sandbox-Id": "sbx-burst",
                    "X-Request-Timestamp": ts,
                    "X-Request-Nonce": nonce,
                    "X-Request-Signature": sig,
                },
                content_type="application/json",
            )

        # 3rd request should be rate limited
        ts = str(time.time())
        nonce = uuid.uuid4().hex
        sig = compute_signature(
            "POST", "/git/exec", body_bytes, ts, nonce, b"burst-key"
        )
        resp = client.post(
            "/git/exec",
            data=body_bytes,
            headers={
                "X-Sandbox-Id": "sbx-burst",
                "X-Request-Timestamp": ts,
                "X-Request-Nonce": nonce,
                "X-Request-Signature": sig,
            },
            content_type="application/json",
        )
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers


# ---------------------------------------------------------------------------
# TestGitExecEndpoint
# ---------------------------------------------------------------------------


class TestGitExecEndpoint:
    """POST /git/exec command execution tests."""

    def test_blocked_command_returns_422(
        self, git_api_client, auth_headers, sandbox_metadata_file
    ):
        """A disallowed subcommand returns 422 (not command allowlisted)."""
        sandbox_metadata_file("test-sandbox-1", {
            "sandbox_branch": "sandbox/test-integration",
            "from_branch": "main",
            "repo_root": "/tmp/nonexistent",
        })

        # 'remote' add is not allowed
        body_bytes = json.dumps({"args": ["remote", "add", "origin", "https://example.com"]}).encode("utf-8")
        headers = auth_headers(body=body_bytes)
        resp = git_api_client.post(
            "/git/exec",
            data=body_bytes,
            headers=headers,
            content_type="application/json",
        )
        assert resp.status_code == 422

    def test_invalid_json_returns_400(self, git_api_client, auth_headers):
        """Malformed JSON body returns 400."""
        bad_body = b"not-json-at-all"
        headers = auth_headers(body=bad_body)
        resp = git_api_client.post(
            "/git/exec",
            data=bad_body,
            headers=headers,
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert "Invalid JSON" in data["error"]

    def test_empty_args_returns_400(self, git_api_client, auth_headers, sandbox_metadata_file):
        """Request with empty args array returns 400."""
        sandbox_metadata_file("test-sandbox-1", {
            "sandbox_branch": "sandbox/test-integration",
            "from_branch": "main",
        })

        body_bytes = json.dumps({"args": []}).encode("utf-8")
        headers = auth_headers(body=body_bytes)
        resp = git_api_client.post(
            "/git/exec",
            data=body_bytes,
            headers=headers,
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_blocked_flag_returns_422(
        self, git_api_client, auth_headers, sandbox_metadata_file
    ):
        """A blocked flag like --git-dir returns 422."""
        sandbox_metadata_file("test-sandbox-1", {
            "sandbox_branch": "sandbox/test-integration",
            "from_branch": "main",
        })

        body_bytes = json.dumps({"args": ["status", "--git-dir=/etc/shadow"]}).encode("utf-8")
        headers = auth_headers(body=body_bytes)
        resp = git_api_client.post(
            "/git/exec",
            data=body_bytes,
            headers=headers,
            content_type="application/json",
        )
        assert resp.status_code == 422

    def test_nonce_replay_returns_401(
        self, git_api_client, auth_headers, sandbox_metadata_file
    ):
        """Replaying the same nonce returns 401."""
        sandbox_metadata_file("test-sandbox-1", {
            "sandbox_branch": "sandbox/test-integration",
            "from_branch": "main",
        })

        body_bytes = json.dumps({"args": ["status"]}).encode("utf-8")
        headers = auth_headers(body=body_bytes)

        # First request: should not be 401 (may be 422 from missing repo)
        resp1 = git_api_client.post(
            "/git/exec",
            data=body_bytes,
            headers=headers,
            content_type="application/json",
        )
        assert resp1.status_code != 401

        # Replay the same headers (same nonce) — should get 401
        resp2 = git_api_client.post(
            "/git/exec",
            data=body_bytes,
            headers=headers,
            content_type="application/json",
        )
        assert resp2.status_code == 401
        data = json.loads(resp2.data)
        assert "nonce" in data["error"].lower()

    def test_404_for_unknown_route(self, git_api_client):
        """Request to an undefined route returns 404."""
        resp = git_api_client.get("/does-not-exist")
        assert resp.status_code == 404


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
