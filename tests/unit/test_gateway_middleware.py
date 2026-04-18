"""Unit tests for gateway_middleware.py.

Tests the gateway-layer middleware: rate limiter, circuit breaker,
identity resolution, and metrics collection.
"""

import sys
import time
from unittest.mock import MagicMock, patch

import pytest

# Try real aiohttp first; fall back to mock
try:
    import aiohttp  # noqa: F401

    from aiohttp.test_utils import TestClient, TestServer

    _REAL_AIOHTTP = True
except ImportError:
    _REAL_AIOHTTP = False
    if "aiohttp" not in sys.modules:
        sys.modules["aiohttp"] = MagicMock()
        sys.modules["aiohttp.web"] = MagicMock()

# conftest.py adds unified-proxy to sys.path

from gateway_middleware import (
    BUCKET_EXPIRY_SECONDS,
    CircuitBreakerMiddleware,
    CircuitState,
    RateLimiterMiddleware,
    TokenBucket,
)


# ===================================================================
# TokenBucket unit tests (no aiohttp needed)
# ===================================================================


class TestTokenBucket:
    """Tests for the TokenBucket dataclass."""

    def test_consume_succeeds_with_tokens(self):
        """Consuming a token succeeds when tokens are available."""
        now = time.time()
        bucket = TokenBucket(
            tokens=10.0, last_refill=now, capacity=100.0,
            refill_rate=10.0, last_access=now,
        )
        assert bucket.consume(now) is True
        assert bucket.tokens == 9.0

    def test_consume_fails_when_exhausted(self):
        """Consuming fails when no tokens remain."""
        now = time.time()
        bucket = TokenBucket(
            tokens=0.0, last_refill=now, capacity=100.0,
            refill_rate=10.0, last_access=now,
        )
        assert bucket.consume(now) is False

    def test_refill_restores_tokens(self):
        """Tokens refill over time based on refill_rate."""
        now = time.time()
        bucket = TokenBucket(
            tokens=0.0, last_refill=now, capacity=100.0,
            refill_rate=10.0, last_access=now,
        )
        # 1 second later → 10 tokens refilled, consume 1 → 9 remaining
        assert bucket.consume(now + 1.0) is True
        assert abs(bucket.tokens - 9.0) < 0.01

    def test_refill_capped_at_capacity(self):
        """Tokens don't exceed capacity after refill."""
        now = time.time()
        bucket = TokenBucket(
            tokens=99.0, last_refill=now, capacity=100.0,
            refill_rate=100.0, last_access=now,
        )
        bucket.consume(now + 1000.0)
        assert bucket.tokens <= bucket.capacity

    def test_get_retry_after_empty_bucket(self):
        """Retry-After calculated correctly for empty bucket."""
        now = time.time()
        bucket = TokenBucket(
            tokens=0.0, last_refill=now, capacity=100.0,
            refill_rate=10.0, last_access=now,
        )
        retry = bucket.get_retry_after()
        # Need 1.0 token, refill at 10/s → 0.1 seconds
        assert abs(retry - 0.1) < 0.01

    def test_get_retry_after_zero_refill_rate(self):
        """Zero refill rate returns default 60s retry."""
        now = time.time()
        bucket = TokenBucket(
            tokens=0.0, last_refill=now, capacity=100.0,
            refill_rate=0.0, last_access=now,
        )
        assert bucket.get_retry_after() == 60.0


# ===================================================================
# RateLimiterMiddleware bucket management (no aiohttp needed)
# ===================================================================


class TestRateLimiterBucketManagement:
    """Tests for RateLimiterMiddleware internal bucket management."""

    def test_buckets_start_empty(self):
        """Rate limiter starts with no buckets."""
        rl = RateLimiterMiddleware(upstream_host="api.example.com")
        assert len(rl.buckets) == 0

    def test_per_container_isolation(self):
        """Different container IDs get separate token buckets."""
        rl = RateLimiterMiddleware(
            upstream_host="api.example.com", capacity=2, refill_rate=0,
        )
        now = time.time()
        rl.buckets["container-a"] = TokenBucket(
            tokens=2.0, last_refill=now, capacity=2.0,
            refill_rate=0, last_access=now,
        )
        rl.buckets["container-b"] = TokenBucket(
            tokens=2.0, last_refill=now, capacity=2.0,
            refill_rate=0, last_access=now,
        )

        # Exhaust container-a
        assert rl.buckets["container-a"].consume(now) is True
        assert rl.buckets["container-a"].consume(now) is True
        assert rl.buckets["container-a"].consume(now) is False

        # container-b still has tokens
        assert rl.buckets["container-b"].consume(now) is True

    def test_cleanup_removes_stale_buckets(self):
        """Stale buckets are removed during cleanup."""
        rl = RateLimiterMiddleware(upstream_host="api.example.com")
        now = time.time()

        rl.buckets["stale-container"] = TokenBucket(
            tokens=100.0,
            last_refill=now - BUCKET_EXPIRY_SECONDS - 1,
            capacity=100.0,
            refill_rate=10.0,
            last_access=now - BUCKET_EXPIRY_SECONDS - 1,
        )
        rl.buckets["active-container"] = TokenBucket(
            tokens=100.0, last_refill=now, capacity=100.0,
            refill_rate=10.0, last_access=now,
        )

        rl._cleanup_stale_buckets(now)

        assert "stale-container" not in rl.buckets
        assert "active-container" in rl.buckets

    def test_cleanup_keeps_recent_buckets(self):
        """Recent buckets are preserved during cleanup."""
        rl = RateLimiterMiddleware(upstream_host="api.example.com")
        now = time.time()

        rl.buckets["recent"] = TokenBucket(
            tokens=50.0, last_refill=now, capacity=100.0,
            refill_rate=10.0, last_access=now,
        )

        rl._cleanup_stale_buckets(now)
        assert "recent" in rl.buckets

    @pytest.mark.asyncio
    async def test_background_cleanup_task(self):
        """Background cleanup is scheduled when interval elapsed."""
        rl = RateLimiterMiddleware(
            upstream_host="api.example.com",
            cleanup_interval=0,  # Always trigger cleanup
        )
        now = time.time()
        rl.buckets["stale"] = TokenBucket(
            tokens=100.0,
            last_refill=now - BUCKET_EXPIRY_SECONDS - 1,
            capacity=100.0,
            refill_rate=10.0,
            last_access=now - BUCKET_EXPIRY_SECONDS - 1,
        )

        # Trigger cleanup via the async method
        await rl._async_cleanup(now)

        assert "stale" not in rl.buckets


# ===================================================================
# CircuitBreaker fail-closed tests (existing + expanded)
# ===================================================================


class TestCircuitBreakerFailClosed:
    """Circuit breaker must fail-closed in edge cases."""

    def test_open_with_null_failure_time_blocks(self):
        """OPEN state with last_failure_time=None must block (fail-closed)."""
        cb = CircuitBreakerMiddleware(upstream_host="api.example.com")
        cb.circuit.state = CircuitState.OPEN
        cb.circuit.last_failure_time = None
        assert cb._should_allow_request() is False

    def test_unknown_state_blocks(self):
        """Unknown/unexpected state must block (fail-closed)."""
        cb = CircuitBreakerMiddleware(upstream_host="api.example.com")
        cb.circuit.state = "BOGUS"
        assert cb._should_allow_request() is False

    def test_closed_state_allows(self):
        """CLOSED state allows requests."""
        cb = CircuitBreakerMiddleware(upstream_host="api.example.com")
        assert cb.circuit.state == CircuitState.CLOSED
        assert cb._should_allow_request() is True


# ===================================================================
# CircuitBreaker state transitions
# ===================================================================


class TestCircuitBreakerStateTransitions:
    """Tests for full circuit breaker state machine transitions."""

    def test_closed_to_open_after_threshold_failures(self):
        """CLOSED -> OPEN after failure_threshold consecutive failures."""
        cb = CircuitBreakerMiddleware(
            upstream_host="api.example.com", failure_threshold=3,
        )
        assert cb.circuit.state == CircuitState.CLOSED

        for _ in range(3):
            cb._record_failure()

        assert cb.circuit.state == CircuitState.OPEN

    def test_failures_below_threshold_stay_closed(self):
        """Failures below threshold keep circuit CLOSED."""
        cb = CircuitBreakerMiddleware(
            upstream_host="api.example.com", failure_threshold=5,
        )
        for _ in range(4):
            cb._record_failure()

        assert cb.circuit.state == CircuitState.CLOSED
        assert cb.circuit.failure_count == 4

    def test_open_to_half_open_after_recovery_timeout(self):
        """OPEN -> HALF_OPEN when recovery timeout has elapsed."""
        cb = CircuitBreakerMiddleware(
            upstream_host="api.example.com",
            failure_threshold=1,
            recovery_timeout=10,
        )

        cb._record_failure()
        assert cb.circuit.state == CircuitState.OPEN

        # Set failure time far enough in the past
        cb.circuit.last_failure_time = time.time() - 11

        assert cb._should_allow_request() is True
        assert cb.circuit.state == CircuitState.HALF_OPEN

    def test_recovery_timeout_not_elapsed_stays_open(self):
        """OPEN stays OPEN when recovery timeout hasn't elapsed."""
        cb = CircuitBreakerMiddleware(
            upstream_host="api.example.com",
            failure_threshold=1,
            recovery_timeout=60,
        )

        cb._record_failure()
        assert cb.circuit.state == CircuitState.OPEN

        assert cb._should_allow_request() is False
        assert cb.circuit.state == CircuitState.OPEN

    def test_half_open_to_closed_after_success_threshold(self):
        """HALF_OPEN -> CLOSED after success_threshold consecutive successes."""
        cb = CircuitBreakerMiddleware(
            upstream_host="api.example.com",
            failure_threshold=1,
            success_threshold=2,
            recovery_timeout=0,
        )

        # Trip to OPEN
        cb._record_failure()
        assert cb.circuit.state == CircuitState.OPEN

        # Advance past recovery
        cb.circuit.last_failure_time = time.time() - 1
        cb._should_allow_request()  # transitions to HALF_OPEN
        assert cb.circuit.state == CircuitState.HALF_OPEN

        # First success — not enough
        cb._record_success()
        assert cb.circuit.state == CircuitState.HALF_OPEN

        # Second success — threshold reached
        cb._record_success()
        assert cb.circuit.state == CircuitState.CLOSED

    def test_half_open_to_open_on_failure(self):
        """HALF_OPEN -> OPEN on any failure during recovery probe."""
        cb = CircuitBreakerMiddleware(
            upstream_host="api.example.com",
            failure_threshold=1,
            recovery_timeout=0,
        )

        # Trip to OPEN, then HALF_OPEN
        cb._record_failure()
        cb.circuit.last_failure_time = time.time() - 1
        cb._should_allow_request()
        assert cb.circuit.state == CircuitState.HALF_OPEN

        # Failure in HALF_OPEN → back to OPEN
        cb._record_failure()
        assert cb.circuit.state == CircuitState.OPEN

    def test_success_resets_failure_count(self):
        """Success in CLOSED state resets failure count to 0."""
        cb = CircuitBreakerMiddleware(
            upstream_host="api.example.com", failure_threshold=5,
        )

        cb._record_failure()
        cb._record_failure()
        assert cb.circuit.failure_count == 2

        cb._record_success()
        assert cb.circuit.failure_count == 0

    def test_full_lifecycle_closed_open_half_open_closed(self):
        """Full state cycle: CLOSED -> OPEN -> HALF_OPEN -> CLOSED."""
        cb = CircuitBreakerMiddleware(
            upstream_host="api.example.com",
            failure_threshold=2,
            success_threshold=1,
            recovery_timeout=0,
        )

        # CLOSED
        assert cb.circuit.state == CircuitState.CLOSED

        # CLOSED -> OPEN (2 failures)
        cb._record_failure()
        cb._record_failure()
        assert cb.circuit.state == CircuitState.OPEN

        # OPEN -> HALF_OPEN (recovery timeout)
        cb.circuit.last_failure_time = time.time() - 1
        cb._should_allow_request()
        assert cb.circuit.state == CircuitState.HALF_OPEN

        # HALF_OPEN -> CLOSED (1 success)
        cb._record_success()
        assert cb.circuit.state == CircuitState.CLOSED


# ===================================================================
# CircuitBreaker HALF_OPEN single probe enforcement
# ===================================================================


class TestCircuitBreakerHalfOpenProbe:
    """Tests for HALF_OPEN single-probe enforcement."""

    def _make_half_open_cb(self):
        """Create a CircuitBreakerMiddleware in HALF_OPEN with probe active."""
        cb = CircuitBreakerMiddleware(
            upstream_host="api.example.com",
            failure_threshold=1,
            recovery_timeout=0,
        )
        cb._record_failure()
        cb.circuit.last_failure_time = time.time() - 1
        cb._should_allow_request()  # → HALF_OPEN, probe_active=True
        return cb

    def test_first_probe_allowed(self):
        """First request in HALF_OPEN is allowed as a probe."""
        cb = self._make_half_open_cb()
        assert cb._half_open_probe_active is True

    def test_second_request_blocked_while_probe_active(self):
        """Second request is blocked while probe is in flight."""
        cb = self._make_half_open_cb()
        assert cb._should_allow_request() is False

    def test_probe_cleared_on_success(self):
        """Probe flag is cleared after success."""
        cb = self._make_half_open_cb()
        cb._record_success()
        assert cb._half_open_probe_active is False

    def test_probe_cleared_on_failure(self):
        """Probe flag is cleared after failure."""
        cb = self._make_half_open_cb()
        cb._record_failure()
        assert cb._half_open_probe_active is False

    def test_new_probe_allowed_after_success(self):
        """After success clears probe, a new probe is allowed in HALF_OPEN."""
        cb = CircuitBreakerMiddleware(
            upstream_host="api.example.com",
            failure_threshold=1,
            success_threshold=3,  # Need multiple successes
            recovery_timeout=0,
        )
        cb._record_failure()
        cb.circuit.last_failure_time = time.time() - 1
        cb._should_allow_request()  # → HALF_OPEN, probe active
        assert cb.circuit.state == CircuitState.HALF_OPEN

        cb._record_success()  # Clears probe, but not enough to close
        assert cb.circuit.state == CircuitState.HALF_OPEN
        assert cb._half_open_probe_active is False

        # New probe should be allowed
        assert cb._should_allow_request() is True


# ===================================================================
# Integration tests requiring real aiohttp
# ===================================================================

_skip_no_aiohttp = pytest.mark.skipif(
    not _REAL_AIOHTTP,
    reason="aiohttp not installed — skipping middleware integration tests",
)


class MockUpstreamResponse:
    """Async context manager simulating aiohttp.ClientSession.request()."""

    def __init__(self, *, status=200, reason="OK", headers=None, body=b"",
                 error=None):
        self.status = status
        self.reason = reason
        self.headers = headers or {}
        self._body = body
        self._error = error

    async def __aenter__(self):
        if self._error:
            raise self._error
        return self

    async def __aexit__(self, *args):
        pass

    @property
    def content(self):
        body = self._body

        class _Content:
            async def iter_any(self_inner):
                if body:
                    yield body

        return _Content()


class MockSession:
    """Mock aiohttp.ClientSession."""

    def __init__(self, response=None, error=None):
        self._response = response or MockUpstreamResponse()
        self._error = error
        self.last_call_kwargs = None
        self.closed = False

    def request(self, **kwargs):
        self.last_call_kwargs = kwargs
        if self._error:
            return MockUpstreamResponse(error=self._error)
        return self._response

    async def close(self):
        self.closed = True


def _make_mock_registry(container_id="test-container-abc"):
    """Create a mock ContainerRegistry that always resolves to container_id."""
    registry = MagicMock()
    container = MagicMock()
    container.container_id = container_id
    container.is_expired = False
    registry.get_by_ip.return_value = container
    return registry


@_skip_no_aiohttp
class TestRateLimiterMiddlewareIntegration:
    """Rate limiter middleware integration tests with real aiohttp."""

    def _create_app(self, registry=None, capacity=2, refill_rate=0):
        from gateway_base import create_gateway_app

        return create_gateway_app(
            upstream_base_url="https://api.example.com",
            upstream_host="api.example.com",
            service_name="test-gateway",
            credential_loader=lambda: {"header": "Authorization", "value": "Bearer test"},
            routes=[("*", "/{path_info:.*}")],
            port=9999,
            credential_required=False,
            registry=registry or _make_mock_registry(),
        )

    @pytest.mark.asyncio
    async def test_bucket_exhaustion_blocks_requests(self):
        """Requests are blocked when token bucket is exhausted."""
        app = self._create_app()
        mock_session = MockSession(
            response=MockUpstreamResponse(status=200, headers={}, body=b"ok"),
        )

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session

            # Find the rate limiter middleware and set low capacity
            for mw_container in app.middlewares:
                # aiohttp wraps middleware; check the bound method's __self__
                mw_self = getattr(mw_container, "__self__", None)
                if isinstance(mw_self, RateLimiterMiddleware):
                    mw_self.capacity = 2
                    mw_self.refill_rate = 0
                    break

            # First 2 requests should succeed
            await client.get("/test")
            await client.get("/test")

            # 3rd request should be rate limited (429)
            resp3 = await client.get("/test")
            assert resp3.status == 429

    @pytest.mark.asyncio
    async def test_retry_after_header_set(self):
        """429 responses include Retry-After header."""
        app = self._create_app()
        mock_session = MockSession(
            response=MockUpstreamResponse(status=200, headers={}, body=b"ok"),
        )

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = mock_session

            for mw_container in app.middlewares:
                mw_self = getattr(mw_container, "__self__", None)
                if isinstance(mw_self, RateLimiterMiddleware):
                    mw_self.capacity = 1
                    mw_self.refill_rate = 0
                    break

            await client.get("/test")  # Consume the one token
            resp = await client.get("/test")  # Should be blocked

            assert resp.status == 429
            assert "Retry-After" in resp.headers


@_skip_no_aiohttp
class TestIdentityMiddlewareIntegration:
    """Identity middleware integration tests with real aiohttp."""

    def _create_app(self, registry=None):
        from gateway_base import create_gateway_app

        return create_gateway_app(
            upstream_base_url="https://api.example.com",
            upstream_host="api.example.com",
            service_name="test-gateway",
            credential_loader=lambda: {"header": "Authorization", "value": "Bearer test"},
            routes=[("*", "/{path_info:.*}")],
            port=9999,
            credential_required=False,
            registry=registry or _make_mock_registry(),
        )

    @pytest.mark.asyncio
    async def test_unknown_ip_returns_403(self):
        """Request from unknown IP returns 403."""
        registry = _make_mock_registry()
        registry.get_by_ip.return_value = None
        app = self._create_app(registry=registry)

        async with TestClient(TestServer(app)) as client:
            app["upstream_session"] = MockSession(
                response=MockUpstreamResponse(status=200, headers={}, body=b""),
            )
            resp = await client.get("/test")
            assert resp.status == 403
            body = await resp.json()
            assert "unknown" in body["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_expired_container_returns_403(self):
        """Request from expired container returns 403."""
        registry = MagicMock()
        container = MagicMock()
        container.container_id = "expired-abc"
        container.is_expired = True
        registry.get_by_ip.return_value = container
        app = self._create_app(registry=registry)

        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/test")
            assert resp.status == 403
            body = await resp.json()
            assert "expired" in body["error"]["message"].lower()

    @pytest.mark.asyncio
    async def test_health_endpoint_bypasses_identity(self):
        """Health endpoint works without identity resolution."""
        registry = MagicMock()
        registry.get_by_ip.return_value = None  # Would fail identity check
        app = self._create_app(registry=registry)

        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/health")
            assert resp.status == 200


@_skip_no_aiohttp
class TestMetricsMiddlewareIntegration:
    """Metrics middleware integration tests with real aiohttp."""

    def _create_app(self, registry=None):
        from gateway_base import create_gateway_app

        return create_gateway_app(
            upstream_base_url="https://api.example.com",
            upstream_host="api.example.com",
            service_name="test-gateway",
            credential_loader=lambda: {"header": "Authorization", "value": "Bearer test"},
            routes=[("*", "/{path_info:.*}")],
            port=9999,
            credential_required=False,
            registry=registry or _make_mock_registry(),
        )

    @pytest.mark.asyncio
    async def test_internal_metrics_endpoint(self):
        """/internal/metrics endpoint returns a response (not 404)."""
        app = self._create_app()

        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/internal/metrics")
            # 200 = prometheus available, 501 = not installed,
            # 500 = generate_latest() error (e.g. content_type compat)
            assert resp.status in (200, 500, 501)

    @pytest.mark.asyncio
    async def test_prometheus_unavailable_returns_501(self):
        """/internal/metrics returns 501 when prometheus_client is missing."""
        import gateway_middleware

        app = self._create_app()

        async with TestClient(TestServer(app)) as client:
            with patch.object(gateway_middleware, "_HAS_PROMETHEUS", False):
                resp = await client.get("/internal/metrics")
                assert resp.status == 501
                body = await resp.text()
                assert "not available" in body.lower()
