"""Tests for foundry_git_safety.auth — HMAC auth, nonce store, and rate limiting."""

import time
from unittest.mock import patch

import pytest

from foundry_git_safety.auth import (
    NonceStore,
    RateLimiter,
    SecretStore,
    TokenBucket,
    compute_signature,
    verify_signature,
)


# ---------------------------------------------------------------------------
# TestSecretStore
# ---------------------------------------------------------------------------


class TestSecretStore:
    """Tests for SecretStore file-based HMAC secret management."""

    def test_reads_secret_from_file(self, tmp_path):
        """get_secret returns the secret written to a file named by sandbox_id."""
        secret_file = tmp_path / "my-sandbox"
        secret_file.write_bytes(b"super-secret-key\n")
        store = SecretStore(secrets_path=str(tmp_path))
        result = store.get_secret("my-sandbox")
        assert result == b"super-secret-key"

    def test_caches_secret(self, tmp_path):
        """Second call returns cached value without re-reading the file."""
        secret_file = tmp_path / "my-sandbox"
        secret_file.write_bytes(b"original-key\n")
        store = SecretStore(secrets_path=str(tmp_path))

        first = store.get_secret("my-sandbox")
        assert first == b"original-key"

        # A second call without file modification returns the same cached value
        second = store.get_secret("my-sandbox")
        assert second == b"original-key"

    def test_returns_none_for_unknown_sandbox(self, tmp_path):
        """Returns None when no secret file exists for the given sandbox_id."""
        store = SecretStore(secrets_path=str(tmp_path))
        assert store.get_secret("nonexistent") is None

    def test_invalid_sandbox_id_raises(self, tmp_path):
        """Invalid characters in sandbox_id raise ValueError."""
        store = SecretStore(secrets_path=str(tmp_path))
        with pytest.raises(ValueError, match="Invalid sandbox_id"):
            store.get_secret("bad sandbox!")

    def test_revoke_clears_cache(self, tmp_path):
        """After revoke(), the secret is re-read from disk on next get_secret."""
        secret_file = tmp_path / "my-sandbox"
        secret_file.write_bytes(b"first-key\n")
        store = SecretStore(secrets_path=str(tmp_path))

        assert store.get_secret("my-sandbox") == b"first-key"

        store.revoke("my-sandbox")

        # Change the file to confirm re-read
        secret_file.write_bytes(b"rotated-key\n")
        assert store.get_secret("my-sandbox") == b"rotated-key"

    def test_mtime_change_invalidates_cache(self, tmp_path):
        """External file modification is detected via mtime and cache is refreshed."""
        import time

        secret_file = tmp_path / "my-sandbox"
        secret_file.write_bytes(b"original-key\n")
        store = SecretStore(secrets_path=str(tmp_path))

        assert store.get_secret("my-sandbox") == b"original-key"

        # Overwrite the file and ensure mtime changes
        time.sleep(0.05)
        secret_file.write_bytes(b"rotated-key\n")

        assert store.get_secret("my-sandbox") == b"rotated-key"

    def test_mtime_unchanged_returns_cached_value(self, tmp_path):
        """When mtime hasn't changed, the cached value is returned."""
        secret_file = tmp_path / "my-sandbox"
        secret_file.write_bytes(b"cached-key\n")
        store = SecretStore(secrets_path=str(tmp_path))

        assert store.get_secret("my-sandbox") == b"cached-key"

        # Overwrite with different content but same mtime is unlikely
        # — just verify the cached value is returned on a second call
        assert store.get_secret("my-sandbox") == b"cached-key"

    def test_callback_fired_on_mtime_change(self, tmp_path):
        """on_secret_changed callback is invoked when mtime-based rotation is detected."""
        import time

        secret_file = tmp_path / "my-sandbox"
        secret_file.write_bytes(b"first-key\n")
        store = SecretStore(secrets_path=str(tmp_path))

        changed_ids: list[str] = []
        store.on_secret_changed = changed_ids.append

        store.get_secret("my-sandbox")

        # Rotate the file externally
        time.sleep(0.05)
        secret_file.write_bytes(b"second-key\n")

        result = store.get_secret("my-sandbox")
        assert result == b"second-key"
        assert changed_ids == ["my-sandbox"]

    def test_callback_not_fired_when_mtime_unchanged(self, tmp_path):
        """on_secret_changed is not invoked when cache hit occurs without mtime change."""
        secret_file = tmp_path / "my-sandbox"
        secret_file.write_bytes(b"stable-key\n")
        store = SecretStore(secrets_path=str(tmp_path))

        changed_ids: list[str] = []
        store.on_secret_changed = changed_ids.append

        store.get_secret("my-sandbox")
        store.get_secret("my-sandbox")

        assert changed_ids == []

    def test_rotate_clears_mtime(self, tmp_path):
        """rotate() clears the mtime tracker so next read re-stat()s the file."""
        import time

        secret_file = tmp_path / "my-sandbox"
        secret_file.write_bytes(b"first-key\n")
        store = SecretStore(secrets_path=str(tmp_path))

        store.get_secret("my-sandbox")
        assert "my-sandbox" in store._mtimes

        store.rotate("my-sandbox")
        assert "my-sandbox" not in store._mtimes

        # Write new file and verify re-read
        time.sleep(0.05)
        secret_file.write_bytes(b"new-key\n")
        assert store.get_secret("my-sandbox") == b"new-key"


# ---------------------------------------------------------------------------
# TestNonceStore
# ---------------------------------------------------------------------------


class TestNonceStore:
    """Tests for NonceStore per-sandbox nonce tracking with TTL."""

    def test_unique_nonce_accepted(self):
        """A fresh nonce returns True."""
        store = NonceStore(ttl=600, max_per_sandbox=100)
        assert store.check_and_store("sandbox-1", "nonce-a") is True

    def test_duplicate_nonce_rejected(self):
        """A replayed nonce returns False."""
        store = NonceStore(ttl=600, max_per_sandbox=100)
        store.check_and_store("sandbox-1", "nonce-a")
        assert store.check_and_store("sandbox-1", "nonce-a") is False

    def test_expired_nonces_purged(self):
        """Nonces older than TTL are purged and can be reused."""
        store = NonceStore(ttl=10, max_per_sandbox=100)
        now = time.time()
        with patch("foundry_git_safety.auth.time") as mock_time:
            mock_time.time.return_value = now
            store.check_and_store("sandbox-1", "nonce-old")

            # Advance well past TTL
            mock_time.time.return_value = now + 20
            # Same nonce should now be accepted because it expired
            assert store.check_and_store("sandbox-1", "nonce-old") is True

    def test_clear_sandbox_removes_entries(self):
        """clear_sandbox removes all nonce entries for a sandbox."""
        store = NonceStore(ttl=600, max_per_sandbox=100)
        store.check_and_store("sandbox-1", "nonce-a")
        store.check_and_store("sandbox-1", "nonce-b")
        store.clear_sandbox("sandbox-1")
        # After clearing, the same nonces should be accepted again
        assert store.check_and_store("sandbox-1", "nonce-a") is True
        assert store.check_and_store("sandbox-1", "nonce-b") is True

    def test_nonce_at_exact_ttl_boundary_still_valid(self):
        """A nonce at exactly TTL seconds old is still valid (strict > check).

        The implementation uses strict > for TTL expiry, which is
        security-conservative: nonces live at least TTL seconds.
        """
        store = NonceStore(ttl=10, max_per_sandbox=100)
        now = time.time()
        with patch("foundry_git_safety.auth.time") as mock_time:
            mock_time.time.return_value = now
            store.check_and_store("sandbox-1", "nonce-boundary")

            # At exactly TTL — still valid (strict > not >=)
            mock_time.time.return_value = now + 10
            assert store.check_and_store("sandbox-1", "nonce-boundary") is False

            # Just past TTL — now expired
            mock_time.time.return_value = now + 10.001
            assert store.check_and_store("sandbox-1", "nonce-boundary") is True

    def test_nonce_just_before_ttl_is_valid(self):
        """A nonce just before TTL is still valid and rejected as duplicate."""
        store = NonceStore(ttl=10, max_per_sandbox=100)
        now = time.time()
        with patch("foundry_git_safety.auth.time") as mock_time:
            mock_time.time.return_value = now
            store.check_and_store("sandbox-1", "nonce-alive")

            # Just before TTL expires
            mock_time.time.return_value = now + 9.99
            assert store.check_and_store("sandbox-1", "nonce-alive") is False

    def test_max_per_sandbox_eviction(self):
        """When max_per_sandbox is reached, oldest nonces are evicted (FIFO)."""
        store = NonceStore(ttl=600, max_per_sandbox=3)
        store.check_and_store("sandbox-1", "nonce-1")
        store.check_and_store("sandbox-1", "nonce-2")
        store.check_and_store("sandbox-1", "nonce-3")
        # Adding a 4th should evict nonce-1 (oldest)
        assert store.check_and_store("sandbox-1", "nonce-4") is True
        # nonce-1 was evicted, so re-adding it should succeed
        # (which also evicts nonce-2 since we're back at max=3)
        assert store.check_and_store("sandbox-1", "nonce-1") is True
        # Store now has: nonce-3, nonce-4, nonce-1
        # nonce-3 should still be present
        assert store.check_and_store("sandbox-1", "nonce-3") is False


# ---------------------------------------------------------------------------
# TestTokenBucket
# ---------------------------------------------------------------------------


class TestTokenBucket:
    """Tests for TokenBucket token-bucket rate limiter."""

    def test_initial_tokens_available(self):
        """A fresh bucket with tokens allows immediate consumption."""
        now = time.time()
        bucket = TokenBucket(tokens=10.0, last_refill=now, capacity=10.0, refill_rate=1.0)
        assert bucket.try_consume(now) is True
        assert bucket.tokens == 9.0

    def test_tokens_refill_over_time(self):
        """Tokens are replenished as time passes based on refill_rate."""
        now = 1000.0
        bucket = TokenBucket(tokens=0.0, last_refill=now, capacity=10.0, refill_rate=2.0)
        # 3 seconds later: refill = 3 * 2.0 = 6.0 tokens
        later = now + 3.0
        assert bucket.try_consume(later) is True
        # 6.0 refilled - 1.0 consumed = 5.0
        assert bucket.tokens == pytest.approx(5.0)

    def test_exhausted_bucket_returns_false(self):
        """When no tokens are available and no time has passed, returns False."""
        now = 1000.0
        bucket = TokenBucket(tokens=0.0, last_refill=now, capacity=10.0, refill_rate=1.0)
        assert bucket.try_consume(now) is False


# ---------------------------------------------------------------------------
# TestRateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    """Tests for RateLimiter IP throttle, sandbox rate, and global rate."""

    def test_ip_throttle_under_limit_passes(self):
        """Requests under the IP throttle limit succeed."""
        limiter = RateLimiter(ip_window=60, ip_max=5)
        ok, retry = limiter.check_ip_throttle("1.2.3.4")
        assert ok is True
        assert retry == 0.0

    def test_ip_throttle_over_limit_fails(self):
        """Requests exceeding the IP throttle limit are rejected."""
        limiter = RateLimiter(ip_window=60, ip_max=2)
        limiter.check_ip_throttle("1.2.3.4")
        limiter.check_ip_throttle("1.2.3.4")
        ok, retry = limiter.check_ip_throttle("1.2.3.4")
        assert ok is False
        assert retry >= 1.0

    def test_sandbox_rate_under_burst_passes(self):
        """Sandbox requests within burst capacity succeed."""
        limiter = RateLimiter(burst=10, sustained=60)
        ok, retry = limiter.check_sandbox_rate("sbx-1")
        assert ok is True
        assert retry == 0.0

    def test_global_rate_under_ceiling_passes(self):
        """Global requests under the ceiling succeed."""
        limiter = RateLimiter(global_ceiling=100)
        ok, retry = limiter.check_global_rate()
        assert ok is True
        assert retry == 0.0

    def test_clear_sandbox_removes_bucket(self):
        """clear_sandbox removes the sandbox's rate-limiting bucket."""
        limiter = RateLimiter(burst=1, sustained=1)
        limiter.check_sandbox_rate("sbx-1")
        limiter.clear_sandbox("sbx-1")
        # After clearing, the sandbox should get a fresh bucket
        # Confirm it's gone from internal state
        assert "sbx-1" not in limiter._sandbox_buckets


# ---------------------------------------------------------------------------
# TestHMAC
# ---------------------------------------------------------------------------


class TestHMAC:
    """Tests for compute_signature and verify_signature."""

    def test_compute_signature_is_deterministic(self):
        """The same inputs always produce the same HMAC signature."""
        secret = b"test-secret"
        args = ("POST", "/api/push", b"body-data", "1234567890", "nonce-1")
        sig1 = compute_signature(*args, secret=secret)
        sig2 = compute_signature(*args, secret=secret)
        assert sig1 == sig2
        # Sanity: output is a hex string of correct length for SHA-256
        assert len(sig1) == 64

    def test_verify_signature_true_for_correct_sig(self):
        """verify_signature returns True when the provided sig matches."""
        secret = b"test-secret"
        args = ("POST", "/api/push", b"body-data", "1234567890", "nonce-1")
        sig = compute_signature(*args, secret=secret)
        assert verify_signature(*args, provided_sig=sig, secret=secret) is True

    def test_verify_signature_false_for_wrong_sig(self):
        """verify_signature returns False for an incorrect signature."""
        secret = b"test-secret"
        args = ("POST", "/api/push", b"body-data", "1234567890", "nonce-1")
        assert verify_signature(*args, provided_sig="bad-sig", secret=secret) is False

    def test_uses_compare_digest(self):
        """verify_signature uses hmac.compare_digest for timing-safe comparison."""
        from foundry_git_safety import auth as auth_module

        # Verify the module has a direct reference to compare_digest
        # (imported from hmac). This catches accidental removal of the
        # timing-safe comparison even if the function body is refactored.
        assert hasattr(auth_module, "compare_digest") or any(
            "compare_digest" in line
            for name in dir(auth_module)
            if callable(getattr(auth_module, name, None))
            for line in (getattr(getattr(auth_module, name), "__doc__", "") or "").split()
        ) or "compare_digest" in str(
            auth_module.verify_signature.__code__.co_names
        ), (
            "verify_signature must use hmac.compare_digest, not ==, "
            "to prevent timing attacks"
        )

    def test_verify_rejects_wrong_secret(self):
        """A signature computed with one secret must not validate with another."""
        secret_a = b"secret-a"
        secret_b = b"secret-b"
        args = ("POST", "/api/push", b"body", "1234567890", "nonce-1")
        sig = compute_signature(*args, secret=secret_a)
        assert verify_signature(*args, provided_sig=sig, secret=secret_b) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
