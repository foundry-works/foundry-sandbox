"""Extended HMAC authentication tests for the git API.

Covers edge cases not in test_git_api.py:
- Empty/large body handling
- Tampered timestamp and nonce
- Method case sensitivity
- Clock skew boundary conditions
- Individual missing headers
- Nonce replay integration
"""

import json
import time

from git_api import (
    CLOCK_WINDOW_SECONDS,
    SecretStore,
    compute_signature,
    create_git_api,
    verify_signature,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SECRET = b"test-secret"
SANDBOX_ID = "sb-auth"
BODY = json.dumps({"args": ["status"]}).encode()


def _make_app(tmp_path):
    """Create a test app with a pre-provisioned secret."""
    secret_file = tmp_path / SANDBOX_ID
    secret_file.write_bytes(SECRET)
    return create_git_api(secret_store=SecretStore(str(tmp_path)))


def _auth_headers(body: bytes, ts: str | None = None, nonce: str = "n1"):
    """Build valid auth headers for a request."""
    timestamp = ts or str(int(time.time()))
    sig = compute_signature("POST", "/git/exec", body, timestamp, nonce, SECRET)
    return {
        "X-Sandbox-Id": SANDBOX_ID,
        "X-Request-Signature": sig,
        "X-Request-Timestamp": timestamp,
        "X-Request-Nonce": nonce,
    }


# ---------------------------------------------------------------------------
# TestHMACEdgeCases
# ---------------------------------------------------------------------------


class TestHMACEdgeCases:
    """Edge-case HMAC signature and body tests."""

    def test_empty_body(self, tmp_path):
        """Empty request body should still produce a valid signature."""
        sig = compute_signature("POST", "/git/exec", b"", "123", "n1", SECRET)
        assert verify_signature("POST", "/git/exec", b"", "123", "n1", sig, SECRET)

    def test_large_body(self, tmp_path):
        """Large body should produce a valid signature."""
        large = b"x" * 200_000
        sig = compute_signature("POST", "/git/exec", large, "123", "n1", SECRET)
        assert verify_signature("POST", "/git/exec", large, "123", "n1", sig, SECRET)

    def test_tampered_timestamp_fails(self):
        """Changing the timestamp after signing should invalidate the signature."""
        sig = compute_signature("POST", "/git/exec", BODY, "1000", "n1", SECRET)
        assert not verify_signature(
            "POST", "/git/exec", BODY, "2000", "n1", sig, SECRET
        )

    def test_tampered_nonce_fails(self):
        """Changing the nonce after signing should invalidate the signature."""
        sig = compute_signature("POST", "/git/exec", BODY, "123", "nonce-a", SECRET)
        assert not verify_signature(
            "POST", "/git/exec", BODY, "123", "nonce-b", sig, SECRET
        )

    def test_method_case_sensitivity(self):
        """Signature computed with 'POST' should not verify with 'post'."""
        sig = compute_signature("POST", "/git/exec", BODY, "123", "n1", SECRET)
        assert not verify_signature(
            "post", "/git/exec", BODY, "123", "n1", sig, SECRET
        )

    def test_empty_nonce_is_valid_hmac(self):
        """Empty nonce string is technically valid for HMAC computation."""
        sig = compute_signature("POST", "/git/exec", BODY, "123", "", SECRET)
        assert verify_signature("POST", "/git/exec", BODY, "123", "", sig, SECRET)


# ---------------------------------------------------------------------------
# TestClockSkewBoundary
# ---------------------------------------------------------------------------


class TestClockSkewBoundary:
    """Clock window boundary condition tests."""

    def test_exactly_at_window_boundary_accepted(self, tmp_path):
        """Timestamp near CLOCK_WINDOW_SECONDS should be accepted."""
        app = _make_app(tmp_path)
        client = app.test_client()
        # Timestamp just inside the window (2s buffer for processing time)
        ts = str(int(time.time()) - CLOCK_WINDOW_SECONDS + 2)
        headers = _auth_headers(BODY, ts=ts, nonce="boundary-ok")
        resp = client.post(
            "/git/exec", data=BODY, content_type="application/json", headers=headers
        )
        # Should NOT be rejected for clock skew (may fail for other reasons
        # like missing git, but should not be 401 for timestamp)
        assert resp.status_code != 401 or b"timestamp" not in resp.data.lower()

    def test_just_outside_window_rejected(self, tmp_path):
        """Timestamp just outside CLOCK_WINDOW_SECONDS should be rejected."""
        app = _make_app(tmp_path)
        client = app.test_client()
        ts = str(int(time.time()) - CLOCK_WINDOW_SECONDS - 2)
        headers = _auth_headers(BODY, ts=ts, nonce="boundary-fail")
        resp = client.post(
            "/git/exec", data=BODY, content_type="application/json", headers=headers
        )
        assert resp.status_code == 401

    def test_future_timestamp_within_window_accepted(self, tmp_path):
        """A future timestamp within the window should be accepted."""
        app = _make_app(tmp_path)
        client = app.test_client()
        ts = str(int(time.time()) + CLOCK_WINDOW_SECONDS - 10)
        headers = _auth_headers(BODY, ts=ts, nonce="future-ok")
        resp = client.post(
            "/git/exec", data=BODY, content_type="application/json", headers=headers
        )
        assert resp.status_code != 401 or b"timestamp" not in resp.data.lower()


# ---------------------------------------------------------------------------
# TestMalformedHeaders
# ---------------------------------------------------------------------------


class TestMalformedHeaders:
    """Tests for individually missing or malformed auth headers."""

    def test_missing_sandbox_id(self, tmp_path):
        """Missing X-Sandbox-Id should return 401."""
        app = _make_app(tmp_path)
        client = app.test_client()
        headers = _auth_headers(BODY)
        del headers["X-Sandbox-Id"]
        resp = client.post(
            "/git/exec", data=BODY, content_type="application/json", headers=headers
        )
        assert resp.status_code == 401

    def test_missing_signature(self, tmp_path):
        """Missing X-Request-Signature should return 401."""
        app = _make_app(tmp_path)
        client = app.test_client()
        headers = _auth_headers(BODY, nonce="miss-sig")
        del headers["X-Request-Signature"]
        resp = client.post(
            "/git/exec", data=BODY, content_type="application/json", headers=headers
        )
        assert resp.status_code == 401

    def test_missing_timestamp(self, tmp_path):
        """Missing X-Request-Timestamp should return 401."""
        app = _make_app(tmp_path)
        client = app.test_client()
        headers = _auth_headers(BODY, nonce="miss-ts")
        del headers["X-Request-Timestamp"]
        resp = client.post(
            "/git/exec", data=BODY, content_type="application/json", headers=headers
        )
        assert resp.status_code == 401

    def test_missing_nonce(self, tmp_path):
        """Missing X-Request-Nonce should return 401."""
        app = _make_app(tmp_path)
        client = app.test_client()
        headers = _auth_headers(BODY, nonce="miss-nonce")
        del headers["X-Request-Nonce"]
        resp = client.post(
            "/git/exec", data=BODY, content_type="application/json", headers=headers
        )
        assert resp.status_code == 401

    def test_non_numeric_timestamp(self, tmp_path):
        """Non-numeric timestamp should return 401."""
        app = _make_app(tmp_path)
        client = app.test_client()
        headers = _auth_headers(BODY, nonce="bad-ts")
        headers["X-Request-Timestamp"] = "not-a-number"
        resp = client.post(
            "/git/exec", data=BODY, content_type="application/json", headers=headers
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TestNonceReplayIntegration
# ---------------------------------------------------------------------------


class TestNonceReplayIntegration:
    """Integration test: same nonce used twice returns 401 on second request."""

    def test_replay_returns_401(self, tmp_path):
        """Second request with same nonce should be rejected."""
        app = _make_app(tmp_path)
        client = app.test_client()
        ts = str(int(time.time()))
        nonce = "replay-nonce-1"
        headers = _auth_headers(BODY, ts=ts, nonce=nonce)

        # First request — should succeed (or fail for non-auth reasons)
        resp1 = client.post(
            "/git/exec", data=BODY, content_type="application/json", headers=headers
        )
        # Accept any non-401 status (git binary may not be available)
        first_ok = resp1.status_code != 401

        # Second request with same nonce — must be 401
        resp2 = client.post(
            "/git/exec", data=BODY, content_type="application/json", headers=headers
        )
        assert first_ok, "First request should not fail auth"
        assert resp2.status_code == 401
        assert b"nonce" in resp2.data.lower() or b"Replayed" in resp2.data
