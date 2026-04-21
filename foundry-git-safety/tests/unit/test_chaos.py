"""Chaos tests: server-side failure simulations for thread safety and fault tolerance.

Validates that internal data structures (nonce store, rate limiter, metrics
registry, decision log) behave correctly under concurrent access and fault
conditions. These tests run without sbx infrastructure.
"""

import json
import subprocess
import threading
import time
from unittest.mock import patch

import pytest

from foundry_git_safety.auth import (
    NonceStore,
    RateLimiter,
    SecretStore,
)
from foundry_git_safety.decision_log import DecisionLogWriter
from foundry_git_safety.metrics import _MetricsRegistry


pytestmark = pytest.mark.slow


# ---------------------------------------------------------------------------
# GitExec chaos (subprocess failure during execution)
# ---------------------------------------------------------------------------


class TestGitExecChaos:
    """Simulate subprocess failures during git command execution."""

    def test_returns_error_when_git_subprocess_killed(self, tmp_path):
        """subprocess.TimeoutExpired produces a 422 with 'timed out' message."""
        from foundry_git_safety.server import create_git_api

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        sandbox_id = "chaos-test"
        (secrets_dir / sandbox_id).write_bytes(b"test-secret\n")

        app = create_git_api(
            secret_store=SecretStore(secrets_path=str(secrets_dir)),
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
            data_dir=str(tmp_path / "data"),
        )
        client = app.test_client()

        # Write sandbox metadata so execute_git proceeds past validation
        metadata_dir = tmp_path / "data" / "sandboxes"
        metadata_dir.mkdir(parents=True)
        (metadata_dir / f"{sandbox_id}.json").write_text(json.dumps({
            "sandbox_branch": "feature",
            "from_branch": "main",
            "repos": ["test/repo"],
            "repo_root": str(tmp_path / "repos" / "test--repo"),
        }))

        with patch("foundry_git_safety.operations.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=["git"], timeout=120)
            from foundry_git_safety.auth import compute_signature

            body = json.dumps({"args": ["status"], "cwd": "."}).encode()
            ts = str(time.time())
            nonce = "chaos-nonce-1"
            sig = compute_signature("POST", "/git/exec", body, ts, nonce, b"test-secret")

            resp = client.post(
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
            assert resp.status_code == 422
            assert "timed out" in resp.json["error"].lower()

    def test_returns_error_when_git_subprocess_oserror(self, tmp_path):
        """OSError during subprocess.run produces a 422 with execution error."""
        from foundry_git_safety.server import create_git_api

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        sandbox_id = "chaos-test"
        (secrets_dir / sandbox_id).write_bytes(b"test-secret\n")

        app = create_git_api(
            secret_store=SecretStore(secrets_path=str(secrets_dir)),
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
            data_dir=str(tmp_path / "data"),
        )
        client = app.test_client()

        metadata_dir = tmp_path / "data" / "sandboxes"
        metadata_dir.mkdir(parents=True)
        (metadata_dir / f"{sandbox_id}.json").write_text(json.dumps({
            "sandbox_branch": "feature",
            "from_branch": "main",
            "repos": ["test/repo"],
            "repo_root": str(tmp_path / "repos" / "test--repo"),
        }))

        with patch("foundry_git_safety.operations.subprocess.run") as mock_run:
            mock_run.side_effect = OSError(12, "Cannot allocate memory")
            from foundry_git_safety.auth import compute_signature

            body = json.dumps({"args": ["status"], "cwd": "."}).encode()
            ts = str(time.time())
            nonce = "chaos-nonce-2"
            sig = compute_signature("POST", "/git/exec", body, ts, nonce, b"test-secret")

            resp = client.post(
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
            assert resp.status_code == 422
            assert "execution error" in resp.json["error"].lower()

    def test_in_flight_counter_drains_on_shutdown(self):
        """_InFlightCounter.wait_for_zero returns True when count reaches 0."""
        from foundry_git_safety.server import _InFlightCounter

        counter = _InFlightCounter()
        counter.increment()
        assert not counter._zero.is_set()

        # Decrement in another thread after a short delay
        def delayed_decrement():
            time.sleep(0.05)
            counter.decrement()

        t = threading.Thread(target=delayed_decrement)
        t.start()
        assert counter.wait_for_zero(timeout=5.0)
        t.join()

    def test_in_flight_counter_timeout(self):
        """_InFlightCounter.wait_for_zero returns False when count stays > 0."""
        from foundry_git_safety.server import _InFlightCounter

        counter = _InFlightCounter()
        counter.increment()
        assert not counter.wait_for_zero(timeout=0.1)

    def test_decision_log_survives_concurrent_writes(self, tmp_path):
        """Concurrent writes to DecisionLogWriter produce no partial lines."""
        log_dir = tmp_path / "logs"
        writer = DecisionLogWriter(log_dir=str(log_dir))

        errors: list[Exception] = []

        def write_entries(thread_id, count):
            try:
                for i in range(count):
                    writer.write({
                        "thread": thread_id,
                        "index": i,
                        "outcome": "allow",
                    })
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=write_entries, args=(tid, 100))
            for tid in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

        log_path = log_dir / "decisions.jsonl"
        assert log_path.exists()
        lines = log_path.read_text().splitlines()
        assert len(lines) == 1000
        for line in lines:
            parsed = json.loads(line)
            assert "thread" in parsed
            assert "index" in parsed


# ---------------------------------------------------------------------------
# NonceStore chaos
# ---------------------------------------------------------------------------


class TestNonceStoreChaos:
    """Concurrent nonce insertion must not produce false rejects."""

    def test_concurrent_nonce_insertion_no_false_rejects(self):
        """20 threads × 100 unique nonces — all 2000 inserts must succeed."""
        store = NonceStore()
        results: list[bool] = []
        lock = threading.Lock()

        def insert_nonces(thread_id):
            for i in range(100):
                nonce = f"t{thread_id}-n{i}"
                ok = store.check_and_store("sandbox-1", nonce)
                with lock:
                    results.append(ok)

        threads = [
            threading.Thread(target=insert_nonces, args=(tid,))
            for tid in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(results), f"{results.count(False)} false rejects out of {len(results)}"

    def test_ttl_expiry_allows_reuse(self):
        """A nonce is accepted again after TTL expires."""
        store = NonceStore(ttl=1)
        assert store.check_and_store("sandbox-1", "reuse-nonce")
        assert not store.check_and_store("sandbox-1", "reuse-nonce")

        # Advance past TTL
        with patch("foundry_git_safety.auth.time.time", return_value=time.time() + 2):
            assert store.check_and_store("sandbox-1", "reuse-nonce")


# ---------------------------------------------------------------------------
# RateLimiter chaos
# ---------------------------------------------------------------------------


class TestRateLimiterChaos:
    """Token bucket must not overdraft under concurrent access."""

    def test_concurrent_rate_limit_checks_no_overdraft(self):
        """50 threads competing for burst=10 tokens — at most 10 succeed."""
        limiter = RateLimiter(burst=10, sustained=0.001)
        accepted = []
        lock = threading.Lock()

        def try_consume():
            ok, _ = limiter.check_sandbox_rate("sandbox-1")
            with lock:
                accepted.append(ok)

        threads = [threading.Thread(target=try_consume) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(accepted) <= 10, f"Expected ≤10 accepts, got {sum(accepted)}"

    def test_global_ceiling_enforced_under_contention(self):
        """100 threads from different sandboxes, global ceiling 20."""
        limiter = RateLimiter(burst=300, sustained=120, global_ceiling=20, ip_max=200)
        accepted = []
        lock = threading.Lock()

        def try_consume(idx):
            # Simulate server pipeline: check sandbox rate then global rate
            ok1, _ = limiter.check_sandbox_rate(f"sb-{idx}")
            ok2, _ = limiter.check_global_rate()
            with lock:
                accepted.append(ok1 and ok2)

        threads = [
            threading.Thread(target=try_consume, args=(i,))
            for i in range(100)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(accepted) <= 20, f"Expected ≤20 accepts, got {sum(accepted)}"


# ---------------------------------------------------------------------------
# MetricsRegistry chaos
# ---------------------------------------------------------------------------


class TestMetricsRegistryChaos:
    """Counter increments must not be lost under concurrent access."""

    def test_concurrent_counter_increments_no_lost_updates(self):
        """100 threads × 1 increment each → final count must be exactly 100."""
        reg = _MetricsRegistry()
        reg.register_counter("test_counter", "Test counter")

        def increment():
            reg.inc_counter("test_counter", {"label": "value"})

        threads = [threading.Thread(target=increment) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        output = reg.render_prometheus()
        # Parse the counter value from Prometheus output
        for line in output.splitlines():
            if line.startswith("test_counter{") and "label" in line:
                value = int(line.split()[-1])
                assert value == 100, f"Expected 100, got {value}"
                break
        else:
            pytest.fail("Counter not found in Prometheus output")

    def test_render_prometheus_under_mutation(self):
        """Rendering while mutating must not raise exceptions."""
        reg = _MetricsRegistry()
        reg.register_counter("chaos_counter", "Chaos counter")
        reg.register_histogram("chaos_hist", "Chaos histogram")

        errors: list[Exception] = []

        def mutate():
            try:
                for i in range(200):
                    reg.inc_counter("chaos_counter", {"i": str(i % 5)})
                    reg.observe_histogram("chaos_hist", float(i) / 100, {"verb": "push"})
            except Exception as e:
                errors.append(e)

        def render():
            try:
                for _ in range(50):
                    reg.render_prometheus()
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=mutate),
            threading.Thread(target=render),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent render: {errors}"
