"""Unit tests for the git_api module.

Tests cover:
- SecretStore: file-based secret loading, caching, revocation, and clear
- NonceStore: replay protection with TTL and LRU eviction
- TokenBucket: token bucket rate limiter mechanics
- RateLimiter: per-IP throttle, per-sandbox rate, and global ceiling
- HMAC signature: compute/verify roundtrip and tamper detection
- Flask app: authentication header validation, signature checks, and health endpoint
"""

import time

from git_api import (
    NonceStore,
    RateLimiter,
    SecretStore,
    TokenBucket,
    compute_signature,
    create_git_api,
    verify_signature,
)


class TestSecretStore:
    def test_get_secret_returns_bytes(self, tmp_path):
        """Write a secret file, verify get_secret reads it."""
        secret_file = tmp_path / "sandbox-1"
        secret_file.write_bytes(b"my-secret-key\n")
        store = SecretStore(secrets_path=str(tmp_path))
        assert store.get_secret("sandbox-1") == b"my-secret-key"

    def test_get_secret_missing_returns_none(self, tmp_path):
        store = SecretStore(secrets_path=str(tmp_path))
        assert store.get_secret("nonexistent") is None

    def test_get_secret_caches(self, tmp_path):
        """Second call returns cached value even if file deleted."""
        secret_file = tmp_path / "sandbox-1"
        secret_file.write_bytes(b"secret")
        store = SecretStore(secrets_path=str(tmp_path))
        store.get_secret("sandbox-1")
        secret_file.unlink()
        assert store.get_secret("sandbox-1") == b"secret"

    def test_revoke_clears_cache(self, tmp_path):
        secret_file = tmp_path / "sandbox-1"
        secret_file.write_bytes(b"secret")
        store = SecretStore(secrets_path=str(tmp_path))
        store.get_secret("sandbox-1")
        store.revoke("sandbox-1")
        secret_file.unlink()
        assert store.get_secret("sandbox-1") is None

    def test_clear_all(self, tmp_path):
        """Write two secrets, clear_all, verify both gone from cache."""
        s1 = tmp_path / "sb1"
        s2 = tmp_path / "sb2"
        s1.write_bytes(b"secret1")
        s2.write_bytes(b"secret2")
        store = SecretStore(secrets_path=str(tmp_path))
        store.get_secret("sb1")
        store.get_secret("sb2")
        store.clear_all()
        s1.unlink()
        s2.unlink()
        assert store.get_secret("sb1") is None
        assert store.get_secret("sb2") is None


class TestNonceStore:
    def test_first_nonce_accepted(self):
        store = NonceStore()
        assert store.check_and_store("sb1", "nonce-1") is True

    def test_duplicate_nonce_rejected(self):
        store = NonceStore()
        store.check_and_store("sb1", "nonce-1")
        assert store.check_and_store("sb1", "nonce-1") is False

    def test_same_nonce_different_sandbox_accepted(self):
        store = NonceStore()
        store.check_and_store("sb1", "nonce-1")
        assert store.check_and_store("sb2", "nonce-1") is True

    def test_lru_eviction_at_max(self):
        store = NonceStore(max_per_sandbox=3)
        store.check_and_store("sb1", "n1")
        store.check_and_store("sb1", "n2")
        store.check_and_store("sb1", "n3")
        store.check_and_store("sb1", "n4")  # evicts n1
        assert store.check_and_store("sb1", "n1") is True  # n1 no longer tracked

    def test_ttl_expiry(self):
        """Expired nonces should be accepted again."""
        store = NonceStore(ttl=0)  # instant expiry
        store.check_and_store("sb1", "n1")
        time.sleep(0.01)
        assert store.check_and_store("sb1", "n1") is True


class TestTokenBucket:
    def test_initial_consume_succeeds(self):
        bucket = TokenBucket(
            tokens=10.0, last_refill=time.time(),
            capacity=10.0, refill_rate=1.0,
        )
        assert bucket.try_consume(time.time()) is True

    def test_exhausted_bucket_fails(self):
        now = time.time()
        bucket = TokenBucket(
            tokens=1.0, last_refill=now,
            capacity=10.0, refill_rate=0.0,
        )
        bucket.try_consume(now)
        assert bucket.try_consume(now) is False

    def test_refill_over_time(self):
        past = time.time() - 5.0  # 5 seconds ago
        bucket = TokenBucket(
            tokens=0.0, last_refill=past,
            capacity=10.0, refill_rate=2.0,
        )
        assert bucket.try_consume(time.time()) is True


class TestRateLimiter:
    def test_ip_throttle_allows_within_limit(self):
        rl = RateLimiter(
            burst=10, sustained=5.0, global_ceiling=100,
            ip_window=60, ip_max=10,
        )
        ok, _ = rl.check_ip_throttle("1.2.3.4")
        assert ok is True

    def test_ip_throttle_blocks_over_limit(self):
        rl = RateLimiter(
            burst=10, sustained=5.0, global_ceiling=100,
            ip_window=60, ip_max=2,
        )
        rl.check_ip_throttle("1.2.3.4")
        rl.check_ip_throttle("1.2.3.4")
        ok, retry = rl.check_ip_throttle("1.2.3.4")
        assert ok is False
        assert retry > 0

    def test_sandbox_rate_allows_burst(self):
        rl = RateLimiter(
            burst=3, sustained=1.0, global_ceiling=100,
            ip_window=60, ip_max=100,
        )
        for _ in range(3):
            ok, _ = rl.check_sandbox_rate("sb1")
            assert ok is True

    def test_global_ceiling(self):
        rl = RateLimiter(
            burst=100, sustained=100.0, global_ceiling=2,
            ip_window=60, ip_max=100,
        )
        rl.check_global_rate()
        rl.check_global_rate()
        ok, _ = rl.check_global_rate()
        assert ok is False


class TestHMACSignature:
    def test_compute_and_verify_roundtrip(self):
        secret = b"test-secret"
        sig = compute_signature(
            "POST", "/git/exec", b'{"args":["status"]}',
            "1234567890", "nonce-1", secret,
        )
        assert verify_signature(
            "POST", "/git/exec", b'{"args":["status"]}',
            "1234567890", "nonce-1", sig, secret,
        ) is True

    def test_wrong_secret_fails(self):
        sig = compute_signature(
            "POST", "/git/exec", b"body",
            "123", "n1", b"secret-a",
        )
        assert verify_signature(
            "POST", "/git/exec", b"body",
            "123", "n1", sig, b"secret-b",
        ) is False

    def test_tampered_body_fails(self):
        sig = compute_signature(
            "POST", "/git/exec", b"original",
            "123", "n1", b"secret",
        )
        assert verify_signature(
            "POST", "/git/exec", b"tampered",
            "123", "n1", sig, b"secret",
        ) is False

    def test_tampered_path_fails(self):
        sig = compute_signature(
            "POST", "/git/exec", b"body",
            "123", "n1", b"secret",
        )
        assert verify_signature(
            "POST", "/other", b"body",
            "123", "n1", sig, b"secret",
        ) is False


class TestGitApiApp:
    """Integration tests for the Flask app using test_client()."""

    def test_missing_auth_headers_returns_401(self, tmp_path):
        app = create_git_api(secret_store=SecretStore(str(tmp_path)))
        client = app.test_client()
        resp = client.post("/git/exec", json={"args": ["status"]})
        assert resp.status_code == 401

    def test_invalid_signature_returns_401(self, tmp_path):
        secret_file = tmp_path / "sb1"
        secret_file.write_bytes(b"real-secret")
        app = create_git_api(secret_store=SecretStore(str(tmp_path)))
        client = app.test_client()
        resp = client.post(
            "/git/exec",
            json={"args": ["status"]},
            headers={
                "X-Sandbox-Id": "sb1",
                "X-Request-Signature": "bad-sig",
                "X-Request-Timestamp": str(int(time.time())),
                "X-Request-Nonce": "n1",
            },
        )
        assert resp.status_code == 401

    def test_expired_timestamp_returns_401(self, tmp_path):
        """Timestamp outside CLOCK_WINDOW_SECONDS (300s) is rejected."""
        secret_file = tmp_path / "sb1"
        secret_file.write_bytes(b"real-secret")
        app = create_git_api(secret_store=SecretStore(str(tmp_path)))
        client = app.test_client()
        old_ts = str(int(time.time()) - 600)
        sig = compute_signature(
            "POST", "/git/exec", b'{"args":["status"]}',
            old_ts, "n1", b"real-secret",
        )
        resp = client.post(
            "/git/exec",
            json={"args": ["status"]},
            headers={
                "X-Sandbox-Id": "sb1",
                "X-Request-Signature": sig,
                "X-Request-Timestamp": old_ts,
                "X-Request-Nonce": "n1",
            },
        )
        assert resp.status_code == 401

    def test_health_endpoint(self, tmp_path):
        app = create_git_api(secret_store=SecretStore(str(tmp_path)))
        client = app.test_client()
        resp = client.get("/health")
        assert resp.status_code == 200
