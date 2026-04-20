"""Performance microbenchmarks for git-safety server internals.

Measures latency of HMAC operations, nonce checks, rate limiting,
metrics operations, and decision log writes. These run in pure pytest
with no sbx dependency.
"""

import json
import time

import pytest

from foundry_git_safety.auth import (
    NonceStore,
    RateLimiter,
    SecretStore,
    compute_signature,
    verify_signature,
)
from foundry_git_safety.decision_log import DecisionLogWriter
from foundry_git_safety.metrics import _MetricsRegistry


pytestmark = pytest.mark.slow


# ---------------------------------------------------------------------------
# Auth performance
# ---------------------------------------------------------------------------


class TestAuthPerformance:
    """HMAC and auth-related operations should be sub-millisecond."""

    def test_hmac_compute_under_1ms(self):
        """HMAC signature computation averages under 1ms."""
        body = b'{"args": ["status"]}'
        secret = b"test-secret-for-performance-benchmark"
        samples = 100

        start = time.perf_counter()
        for _ in range(samples):
            compute_signature("POST", "/git/exec", body, str(time.time()), "nonce", secret)
        elapsed = time.perf_counter() - start

        mean_ms = (elapsed / samples) * 1000
        assert mean_ms < 1.0, f"HMAC compute mean: {mean_ms:.3f}ms (expected < 1ms)"

    def test_hmac_verify_under_1ms(self):
        """HMAC signature verification averages under 1ms."""
        body = b'{"args": ["status"]}'
        secret = b"test-secret-for-performance-benchmark"
        ts = str(time.time())
        nonce = "verify-perf-nonce"
        sig = compute_signature("POST", "/git/exec", body, ts, nonce, secret)

        samples = 100
        start = time.perf_counter()
        for _ in range(samples):
            verify_signature("POST", "/git/exec", body, ts, nonce, sig, secret)
        elapsed = time.perf_counter() - start

        mean_ms = (elapsed / samples) * 1000
        assert mean_ms < 1.0, f"HMAC verify mean: {mean_ms:.3f}ms (expected < 1ms)"

    def test_nonce_store_check_under_100us(self):
        """Nonce store check averages under 100 microseconds."""
        store = NonceStore()
        # Warm up
        for i in range(10):
            store.check_and_store("warmup-sb", f"nonce-{i}")

        samples = 200
        start = time.perf_counter()
        for i in range(samples):
            store.check_and_store("perf-sb", f"perf-nonce-{i}")
        elapsed = time.perf_counter() - start

        mean_us = (elapsed / samples) * 1_000_000
        assert mean_us < 100, f"Nonce check mean: {mean_us:.1f}us (expected < 100us)"

    def test_rate_limiter_check_under_50us(self):
        """Rate limiter check averages under 50 microseconds."""
        limiter = RateLimiter()

        samples = 200
        start = time.perf_counter()
        for i in range(samples):
            limiter.check_sandbox_rate(f"perf-sb-{i % 5}")
        elapsed = time.perf_counter() - start

        mean_us = (elapsed / samples) * 1_000_000
        assert mean_us < 50, f"Rate limit check mean: {mean_us:.1f}us (expected < 50us)"


# ---------------------------------------------------------------------------
# Metrics performance
# ---------------------------------------------------------------------------


class TestMetricsPerformance:
    """Metrics operations should be fast even with many series."""

    def test_counter_increment_under_10us(self):
        """Counter increment averages under 10 microseconds."""
        reg = _MetricsRegistry()
        reg.register_counter("perf_counter", "Performance counter")

        samples = 1000
        start = time.perf_counter()
        for i in range(samples):
            reg.inc_counter("perf_counter", {"label": str(i % 10)})
        elapsed = time.perf_counter() - start

        mean_us = (elapsed / samples) * 1_000_000
        assert mean_us < 10, f"Counter increment mean: {mean_us:.1f}us (expected < 10us)"

    def test_prometheus_render_100_series_under_100ms(self):
        """Rendering 100 counter series takes under 100ms."""
        reg = _MetricsRegistry()
        reg.register_counter("perf_render_counter", "Render perf counter")

        # Create 100 series
        for i in range(100):
            reg.inc_counter("perf_render_counter", {"series": str(i)}, amount=i + 1)

        start = time.perf_counter()
        output = reg.render_prometheus()
        elapsed = time.perf_counter() - start

        assert elapsed < 0.1, f"Prometheus render: {elapsed:.3f}s (expected < 0.1s)"
        assert "perf_render_counter" in output


# ---------------------------------------------------------------------------
# Decision log performance
# ---------------------------------------------------------------------------


class TestDecisionLogPerformance:
    """Decision log writes must sustain at least 1000 writes/second."""

    def test_write_throughput_10000_per_second(self, tmp_path):
        """Decision log sustains at least 1000 writes/second."""
        log_dir = tmp_path / "logs"
        writer = DecisionLogWriter(log_dir=str(log_dir))

        count = 10_000
        start = time.perf_counter()
        for i in range(count):
            writer.write({
                "sandbox": f"perf-sb-{i % 10}",
                "branch": "main",
                "rule": "command_validation",
                "verb": "status",
                "outcome": "allow",
            })
        elapsed = time.perf_counter() - start

        wps = count / elapsed
        assert wps >= 1000, f"Write throughput: {wps:.0f} writes/sec (expected >= 1000)"

        writer.close()

    def test_rotation_under_100ms(self, tmp_path):
        """Log rotation completes in under 100ms."""
        log_dir = tmp_path / "logs"
        writer = DecisionLogWriter(
            log_dir=str(log_dir),
            max_bytes=1024,  # Very small to trigger rotation quickly
        )

        # Fill past the rotation threshold
        for i in range(200):
            writer.write({
                "sandbox": "rotation-perf",
                "rule": "test",
                "verb": "test",
                "outcome": "allow",
                "padding": "x" * 100,
            })

        # Measure a single rotation
        start = time.perf_counter()
        writer._rotate()
        elapsed = time.perf_counter() - start

        assert elapsed < 0.1, f"Rotation took {elapsed:.3f}s (expected < 0.1s)"

        writer.close()


# ---------------------------------------------------------------------------
# Server throughput
# ---------------------------------------------------------------------------


class TestServerThroughput:
    """Authenticated request throughput should exceed 50 req/s."""

    def test_authenticated_request_throughput(self, tmp_path):
        """Flask test client handles >50 authenticated requests per second."""
        from foundry_git_safety.server import create_git_api

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        data_dir = tmp_path / "data"

        sandbox_id = "throughput-test"
        secret = b"throughput-secret\n"
        (secrets_dir / sandbox_id).write_bytes(secret)

        # Write metadata so requests reach auth layer
        metadata_dir = data_dir / "sandboxes"
        metadata_dir.mkdir(parents=True)
        (metadata_dir / f"{sandbox_id}.json").write_text(json.dumps({
            "sandbox_branch": "feature",
            "from_branch": "main",
            "repos": ["test/repo"],
        }))

        app = create_git_api(
            secret_store=SecretStore(secrets_path=str(secrets_dir)),
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
            data_dir=str(data_dir),
        )
        client = app.test_client()

        count = 100
        start = time.perf_counter()
        for i in range(count):
            body = json.dumps({"args": ["version"], "cwd": "."}).encode()
            ts = str(time.time())
            nonce = f"tp-nonce-{i}"
            sig = compute_signature("POST", "/git/exec", body, ts, nonce, secret.strip())

            client.post(
                "/git/exec",
                data=body,
                headers={
                    "X-Sandbox-Id": sandbox_id,
                    "X-Request-Signature": sig,
                    "X-Request-Timestamp": ts,
                    "X-Request-Nonce": nonce,
                },
                content_type="application/json",
            )
        elapsed = time.perf_counter() - start

        rps = count / elapsed
        assert rps >= 50, f"Throughput: {rps:.0f} req/s (expected >= 50)"
