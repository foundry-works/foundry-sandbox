"""Integration tests for the full git push flow.

Tests the complete chain: git-wrapper serialization -> HMAC authentication
-> git API request handling -> command validation -> policy engine enforcement.

This validates that the components work together correctly, not just in
isolation. Each test exercises multiple layers of the security stack.
"""

import json
import os
import sys
import time

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from git_api import (
    SecretStore,
    NonceStore,
    RateLimiter,
    compute_signature,
    create_git_api,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def hmac_secret():
    """Generate a test HMAC secret."""
    return os.urandom(32)


@pytest.fixture
def secrets_dir(hmac_secret, tmp_path):
    """Create a temporary secrets directory with a test sandbox secret."""
    secret_file = tmp_path / "test-sandbox"
    secret_file.write_bytes(hmac_secret)
    return str(tmp_path)


@pytest.fixture
def repo_root(tmp_path):
    """Create a temporary git repository root."""
    repo = tmp_path / "repo"
    repo.mkdir()
    # Initialize a minimal git repo structure
    git_dir = repo / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
    return str(repo)


@pytest.fixture
def git_api_app(secrets_dir, repo_root):
    """Create a test Flask app with the git API."""
    secret_store = SecretStore(secrets_path=secrets_dir)
    nonce_store = NonceStore()
    rate_limiter = RateLimiter()

    def repo_root_resolver(sandbox_id, metadata):
        return repo_root

    app = create_git_api(
        secret_store=secret_store,
        nonce_store=nonce_store,
        rate_limiter=rate_limiter,
        repo_root_resolver=repo_root_resolver,
    )
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(git_api_app):
    """Create a test client for the git API."""
    return git_api_app.test_client()


def make_authenticated_request(
    client,
    sandbox_id,
    hmac_secret,
    args,
    cwd=".",
):
    """Helper to make an HMAC-authenticated request to the git API.

    This mirrors the authentication flow in stubs/git-wrapper.sh:
    1. Build JSON body with args and cwd
    2. Generate timestamp and nonce
    3. Compute HMAC-SHA256 signature
    4. Send POST with auth headers
    """
    body = json.dumps({"args": args, "cwd": cwd})
    body_bytes = body.encode("utf-8")

    timestamp = str(int(time.time()))
    nonce = os.urandom(16).hex()

    signature = compute_signature(
        method="POST",
        path="/git/exec",
        body=body_bytes,
        timestamp=timestamp,
        nonce=nonce,
        secret=hmac_secret,
    )

    return client.post(
        "/git/exec",
        data=body_bytes,
        content_type="application/json",
        headers={
            "X-Sandbox-Id": sandbox_id,
            "X-Request-Timestamp": timestamp,
            "X-Request-Nonce": nonce,
            "X-Request-Signature": signature,
        },
    )


# ---------------------------------------------------------------------------
# Test: Full Push Flow (wrapper -> auth -> validation -> policy)
# ---------------------------------------------------------------------------


class TestFullPushFlow:
    """Test the complete git push flow through all security layers."""

    def test_push_to_feature_branch_allowed(self, client, hmac_secret):
        """Push to a feature branch should pass all validation layers."""
        response = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["push", "origin", "feature-branch:feature-branch"],
        )
        # Command validation passes, but actual git execution may fail
        # (no real remote) — we check it gets past auth + validation
        assert response.status_code in (200, 422)
        data = response.get_json()
        # If 422, it should be a git execution error, not a policy block
        if response.status_code == 422:
            assert "protected branch" not in data.get("error", "").lower()

    def test_push_to_protected_branch_blocked(self, client, hmac_secret):
        """Push to main should be blocked by policy engine."""
        response = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["push", "origin", "main:main"],
        )
        assert response.status_code == 422
        data = response.get_json()
        assert "protected branch" in data.get("error", "").lower() or "not allowed" in data.get("error", "").lower()

    def test_push_all_blocked(self, client, hmac_secret):
        """Push --all should be blocked (requires explicit refspecs)."""
        response = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["push", "--all", "origin"],
        )
        assert response.status_code == 422
        data = response.get_json()
        assert "--all" in data.get("error", "") or "not allowed" in data.get("error", "").lower()

    def test_push_mirror_blocked(self, client, hmac_secret):
        """Push --mirror should be blocked."""
        response = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["push", "--mirror", "origin"],
        )
        assert response.status_code == 422
        data = response.get_json()
        assert "--mirror" in data.get("error", "") or "not allowed" in data.get("error", "").lower()

    def test_push_without_refspec_blocked(self, client, hmac_secret):
        """Push without explicit refspecs should be blocked."""
        response = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["push", "origin"],
        )
        assert response.status_code == 422
        data = response.get_json()
        assert "explicit" in data.get("error", "").lower() or "refspec" in data.get("error", "").lower()

    def test_push_wildcard_refspec_blocked(self, client, hmac_secret):
        """Push with wildcard refspecs should be blocked."""
        response = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["push", "origin", "refs/heads/*:refs/heads/*"],
        )
        assert response.status_code == 422
        data = response.get_json()
        assert "wildcard" in data.get("error", "").lower()

    def test_push_delete_protected_branch_blocked(self, client, hmac_secret):
        """Push --delete for a protected branch should be blocked."""
        response = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["push", "--delete", "origin", "main"],
        )
        assert response.status_code == 422
        data = response.get_json()
        assert "protected" in data.get("error", "").lower() or "not allowed" in data.get("error", "").lower()

    def test_push_force_flag_blocked(self, client, hmac_secret):
        """Push with --force should be blocked by command validation."""
        response = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["push", "--force", "origin", "feature:feature"],
        )
        assert response.status_code == 422
        data = response.get_json()
        assert "blocked" in data.get("error", "").lower() or "force" in data.get("error", "").lower()


# ---------------------------------------------------------------------------
# Test: HMAC Authentication Layer
# ---------------------------------------------------------------------------


class TestHMACAuthenticationFlow:
    """Test HMAC authentication in the context of the full API."""

    def test_missing_auth_headers_rejected(self, client):
        """Request without auth headers should be rejected with 401."""
        body = json.dumps({"args": ["status"], "cwd": "."})
        response = client.post(
            "/git/exec",
            data=body,
            content_type="application/json",
        )
        assert response.status_code == 401

    def test_invalid_signature_rejected(self, client):
        """Request with wrong signature should be rejected with 401."""
        body = json.dumps({"args": ["status"], "cwd": "."})
        response = client.post(
            "/git/exec",
            data=body,
            content_type="application/json",
            headers={
                "X-Sandbox-Id": "test-sandbox",
                "X-Request-Timestamp": str(int(time.time())),
                "X-Request-Nonce": os.urandom(16).hex(),
                "X-Request-Signature": "invalid-signature",
            },
        )
        assert response.status_code == 401

    def test_expired_timestamp_rejected(self, client, hmac_secret):
        """Request with expired timestamp should be rejected."""
        body = json.dumps({"args": ["status"], "cwd": "."})
        body_bytes = body.encode("utf-8")

        # Timestamp from 10 minutes ago (outside 5-min clock window)
        old_timestamp = str(int(time.time()) - 600)
        nonce = os.urandom(16).hex()

        signature = compute_signature(
            method="POST",
            path="/git/exec",
            body=body_bytes,
            timestamp=old_timestamp,
            nonce=nonce,
            secret=hmac_secret,
        )

        response = client.post(
            "/git/exec",
            data=body_bytes,
            content_type="application/json",
            headers={
                "X-Sandbox-Id": "test-sandbox",
                "X-Request-Timestamp": old_timestamp,
                "X-Request-Nonce": nonce,
                "X-Request-Signature": signature,
            },
        )
        assert response.status_code == 401

    def test_replayed_nonce_rejected(self, client, hmac_secret):
        """Request with replayed nonce should be rejected."""
        # First request should succeed (past auth, may fail on git exec)
        response1 = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["status"],
        )
        # Extract the nonce from the first request to replay it
        # Instead, make two requests with the same nonce
        body = json.dumps({"args": ["status"], "cwd": "."})
        body_bytes = body.encode("utf-8")
        timestamp = str(int(time.time()))
        nonce = "fixed-nonce-for-replay-test"

        signature = compute_signature(
            method="POST",
            path="/git/exec",
            body=body_bytes,
            timestamp=timestamp,
            nonce=nonce,
            secret=hmac_secret,
        )

        headers = {
            "X-Sandbox-Id": "test-sandbox",
            "X-Request-Timestamp": timestamp,
            "X-Request-Nonce": nonce,
            "X-Request-Signature": signature,
        }

        # First request
        client.post("/git/exec", data=body_bytes, content_type="application/json", headers=headers)

        # Second request with same nonce should be rejected
        response2 = client.post("/git/exec", data=body_bytes, content_type="application/json", headers=headers)
        assert response2.status_code == 401

    def test_unknown_sandbox_rejected(self, client):
        """Request from unknown sandbox should be rejected."""
        # Use a non-existent sandbox ID (no secret file)
        body = json.dumps({"args": ["status"], "cwd": "."})
        body_bytes = body.encode("utf-8")
        timestamp = str(int(time.time()))
        nonce = os.urandom(16).hex()

        response = client.post(
            "/git/exec",
            data=body_bytes,
            content_type="application/json",
            headers={
                "X-Sandbox-Id": "nonexistent-sandbox",
                "X-Request-Timestamp": timestamp,
                "X-Request-Nonce": nonce,
                "X-Request-Signature": "anything",
            },
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Test: Command Validation Through API
# ---------------------------------------------------------------------------


class TestCommandValidationThroughAPI:
    """Test that command validation works correctly through the full API stack."""

    def test_disallowed_command_rejected(self, client, hmac_secret):
        """Commands not in the allowlist should be rejected."""
        response = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["rm", "-rf", "/"],
        )
        assert response.status_code == 422
        data = response.get_json()
        assert "not allowed" in data.get("error", "").lower()

    def test_blocked_global_flag_rejected(self, client, hmac_secret):
        """Global blocked flags should be rejected."""
        response = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["--git-dir=/etc", "status"],
        )
        assert response.status_code == 422
        data = response.get_json()
        assert "blocked" in data.get("error", "").lower() or "git-dir" in data.get("error", "").lower()

    def test_path_traversal_rejected(self, client, hmac_secret):
        """Path traversal in cwd should be rejected."""
        response = make_authenticated_request(
            client,
            sandbox_id="test-sandbox",
            hmac_secret=hmac_secret,
            args=["status"],
            cwd="../../etc",
        )
        assert response.status_code == 422
        data = response.get_json()
        assert "traversal" in data.get("error", "").lower() or "outside" in data.get("error", "").lower()

    def test_empty_args_rejected(self, client, hmac_secret):
        """Empty args should be rejected at request validation."""
        body = json.dumps({"args": [], "cwd": "."})
        body_bytes = body.encode("utf-8")
        timestamp = str(int(time.time()))
        nonce = os.urandom(16).hex()

        signature = compute_signature(
            method="POST",
            path="/git/exec",
            body=body_bytes,
            timestamp=timestamp,
            nonce=nonce,
            secret=hmac_secret,
        )

        response = client.post(
            "/git/exec",
            data=body_bytes,
            content_type="application/json",
            headers={
                "X-Sandbox-Id": "test-sandbox",
                "X-Request-Timestamp": timestamp,
                "X-Request-Nonce": nonce,
                "X-Request-Signature": signature,
            },
        )
        assert response.status_code == 400


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
