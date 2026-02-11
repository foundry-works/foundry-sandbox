"""Unit tests for rate_limiter addon.

Tests the TokenBucket class and RateLimiterAddon including:
- Token bucket refill mechanics
- Burst handling
- 429 responses on limit exceeded
- Per-container isolation
- Cleanup of stale buckets

Note: These tests use mock objects for mitmproxy types since mitmproxy_rs
cannot be loaded in sandboxed environments. The mocking approach ensures
we test the actual business logic without requiring the full mitmproxy runtime.
"""

import os
import sys
import time
import threading
from unittest.mock import Mock, MagicMock, patch

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))


# Mock mitmproxy before importing rate_limiter
from tests.mocks import MockHeaders, MockResponse, MockCtxLog, MockCtx


class MockRequest:
    """Mock mitmproxy Request class."""

    def __init__(self, pretty_host="api.example.com"):
        self.pretty_host = pretty_host
        self.headers = MockHeaders()


class MockHTTPFlow:
    """Mock mitmproxy HTTPFlow class."""

    def __init__(self, pretty_host="api.example.com"):
        self.request = MockRequest(pretty_host)
        self.response = None
        self.metadata = {}


# Create test-specific mock objects for rate_limiter tests.
# NOTE: We do NOT overwrite sys.modules["mitmproxy"] here because conftest.py
# already installs proper mitmproxy mocks. Overwriting the top-level module
# entry would pollute the global module cache and break other test files
# that import mitmproxy-based addons later in the session.
mock_http = MagicMock()
mock_http.Response = MockResponse
mock_http.HTTPFlow = MockHTTPFlow

mock_ctx_instance = MockCtx()

from addons.rate_limiter import TokenBucket, RateLimiterAddon, BUCKET_EXPIRY_SECONDS
from registry import ContainerConfig


@pytest.fixture
def mock_flow():
    """Create a mock mitmproxy HTTPFlow."""
    return MockHTTPFlow(pretty_host="api.example.com")


@pytest.fixture
def mock_container_config():
    """Create a mock ContainerConfig."""
    return ContainerConfig(
        container_id="test-container",
        ip_address="172.17.0.2",
        registered_at=time.time(),
        last_seen=time.time(),
        ttl_seconds=86400,
        metadata=None,
    )


@pytest.fixture
def addon():
    """Create a RateLimiterAddon with test-friendly parameters."""
    return RateLimiterAddon(
        capacity=10.0,
        refill_rate=2.0,  # 2 tokens per second
        cleanup_interval=60.0,
    )


class TestTokenBucket:
    """Tests for TokenBucket class."""

    def test_initial_state(self):
        """Test token bucket starts with full capacity."""
        now = time.time()
        bucket = TokenBucket(
            tokens=10.0,
            last_refill=now,
            capacity=10.0,
            refill_rate=2.0,
            last_access=now,
        )
        assert bucket.tokens == 10.0
        assert bucket.capacity == 10.0
        assert bucket.refill_rate == 2.0

    def test_consume_success(self):
        """Test consuming a token when available."""
        now = time.time()
        bucket = TokenBucket(
            tokens=5.0,
            last_refill=now,
            capacity=10.0,
            refill_rate=2.0,
            last_access=now,
        )
        result = bucket.consume(now)
        assert result is True
        assert bucket.tokens == 4.0

    def test_consume_failure_no_tokens(self):
        """Test consuming fails when no tokens available."""
        now = time.time()
        bucket = TokenBucket(
            tokens=0.5,
            last_refill=now,
            capacity=10.0,
            refill_rate=2.0,
            last_access=now,
        )
        result = bucket.consume(now)
        assert result is False
        assert bucket.tokens < 1.0

    def test_refill_over_time(self):
        """Test tokens refill based on elapsed time."""
        now = time.time()
        bucket = TokenBucket(
            tokens=2.0,
            last_refill=now,
            capacity=10.0,
            refill_rate=2.0,
            last_access=now,
        )
        # Simulate 3 seconds passing (should add 6 tokens: 3s * 2 tokens/s)
        future = now + 3.0
        result = bucket.consume(future)
        assert result is True
        # Started with 2, added 6, consumed 1 = 7 remaining
        assert bucket.tokens == 7.0
        assert bucket.last_refill == future

    def test_refill_caps_at_capacity(self):
        """Test refill doesn't exceed capacity."""
        now = time.time()
        bucket = TokenBucket(
            tokens=8.0,
            last_refill=now,
            capacity=10.0,
            refill_rate=2.0,
            last_access=now,
        )
        # Simulate 10 seconds passing (would add 20 tokens, but capped at capacity)
        future = now + 10.0
        result = bucket.consume(future)
        assert result is True
        # Should cap at 10, then consume 1 = 9 remaining
        assert bucket.tokens == 9.0

    def test_burst_handling(self):
        """Test burst: new bucket starts full and allows immediate burst."""
        now = time.time()
        bucket = TokenBucket(
            tokens=10.0,
            last_refill=now,
            capacity=10.0,
            refill_rate=2.0,
            last_access=now,
        )
        # Consume 10 tokens rapidly
        for i in range(10):
            result = bucket.consume(now)
            assert result is True, f"Token {i+1} should succeed"

        # 11th attempt should fail
        result = bucket.consume(now)
        assert result is False

    def test_get_retry_after_zero_tokens(self):
        """Test retry_after calculation when no tokens available."""
        now = time.time()
        bucket = TokenBucket(
            tokens=0.0,
            last_refill=now,
            capacity=10.0,
            refill_rate=2.0,
            last_access=now,
        )
        retry_after = bucket.get_retry_after(now)
        # Need 1 token, refill rate is 2/s, so 0.5 seconds
        assert retry_after == 0.5

    def test_get_retry_after_partial_tokens(self):
        """Test retry_after with partial tokens."""
        now = time.time()
        bucket = TokenBucket(
            tokens=0.4,
            last_refill=now,
            capacity=10.0,
            refill_rate=2.0,
            last_access=now,
        )
        retry_after = bucket.get_retry_after(now)
        # Need 0.6 more tokens, refill rate is 2/s, so 0.3 seconds
        assert abs(retry_after - 0.3) < 0.01

    def test_get_retry_after_zero_refill_rate(self):
        """Test retry_after with zero refill rate returns fallback."""
        now = time.time()
        bucket = TokenBucket(
            tokens=0.0,
            last_refill=now,
            capacity=10.0,
            refill_rate=0.0,
            last_access=now,
        )
        retry_after = bucket.get_retry_after(now)
        assert retry_after == 60.0  # Default fallback

    def test_last_access_updated(self):
        """Test last_access is updated on consume."""
        now = time.time()
        bucket = TokenBucket(
            tokens=5.0,
            last_refill=now,
            capacity=10.0,
            refill_rate=2.0,
            last_access=now,
        )
        future = now + 5.0
        bucket.consume(future)
        assert bucket.last_access == future


class TestRateLimiterBasic:
    """Tests for basic RateLimiterAddon functionality."""

    def test_initialization(self):
        """Test addon initializes with correct parameters."""
        addon = RateLimiterAddon(capacity=50.0, refill_rate=5.0, cleanup_interval=120.0)
        assert addon.capacity == 50.0
        assert addon.refill_rate == 5.0
        assert addon.cleanup_interval == 120.0
        assert len(addon.buckets) == 0

    @patch("addons.rate_limiter.get_container_config")
    def test_request_no_container_config(self, mock_get_config, addon, mock_flow):
        """Test request skips rate limiting when no container config."""
        mock_get_config.return_value = None

        addon.request(mock_flow)

        # Should not create response (request allowed)
        assert mock_flow.response is None
        assert len(addon.buckets) == 0

    @patch("addons.rate_limiter.get_container_config")
    def test_request_creates_bucket_on_first_access(
        self, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test first request creates a new bucket."""
        mock_get_config.return_value = mock_container_config

        addon.request(mock_flow)

        # Bucket should be created
        bucket_key = ("test-container", "api.example.com")
        assert bucket_key in addon.buckets
        assert mock_flow.response is None  # Request allowed

    @patch("addons.rate_limiter.get_container_config")
    def test_request_allowed_with_tokens(
        self, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test request is allowed when tokens available."""
        mock_get_config.return_value = mock_container_config

        addon.request(mock_flow)

        assert mock_flow.response is None  # Request allowed

    @patch("addons.rate_limiter.get_container_config")
    def test_request_denied_without_tokens(
        self, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test request denied when no tokens available."""
        mock_get_config.return_value = mock_container_config

        # Consume all tokens
        for _ in range(10):
            addon.request(mock_flow)
            mock_flow.response = None  # Reset for next iteration

        # Next request should be denied
        addon.request(mock_flow)

        assert mock_flow.response is not None
        assert mock_flow.response.status_code == 429
        assert b"Too Many Requests" in mock_flow.response.content
        assert "Retry-After" in mock_flow.response.headers


class TestRateLimiter429Response:
    """Tests for 429 response generation."""

    @patch("addons.rate_limiter.get_container_config")
    def test_429_includes_retry_after_header(
        self, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test 429 response includes Retry-After header."""
        mock_get_config.return_value = mock_container_config

        # Exhaust tokens
        for _ in range(10):
            addon.request(mock_flow)
            mock_flow.response = None

        # Trigger 429
        addon.request(mock_flow)

        assert mock_flow.response.status_code == 429
        retry_after = mock_flow.response.headers.get("Retry-After")
        assert retry_after is not None
        assert int(retry_after) >= 1  # Should be at least 1 second

    @patch("addons.rate_limiter.get_container_config")
    def test_429_includes_content_type(
        self, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test 429 response includes Content-Type header."""
        mock_get_config.return_value = mock_container_config

        # Exhaust tokens
        for _ in range(10):
            addon.request(mock_flow)
            mock_flow.response = None

        # Trigger 429
        addon.request(mock_flow)

        assert mock_flow.response.headers.get("Content-Type") == "text/plain"

    @patch("addons.rate_limiter.get_container_config")
    def test_429_response_body(
        self, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test 429 response has correct body."""
        mock_get_config.return_value = mock_container_config

        # Exhaust tokens
        for _ in range(10):
            addon.request(mock_flow)
            mock_flow.response = None

        # Trigger 429
        addon.request(mock_flow)

        assert mock_flow.response.content == b"Too Many Requests: Rate limit exceeded"


class TestPerContainerIsolation:
    """Tests for per-container rate limit isolation."""

    @patch("addons.rate_limiter.get_container_config")
    def test_different_containers_isolated(self, mock_get_config, addon, mock_flow):
        """Test different containers have separate rate limits."""
        # Container 1
        config1 = ContainerConfig(
            container_id="container-1",
            ip_address="172.17.0.2",
            registered_at=time.time(),
            last_seen=time.time(),
            ttl_seconds=86400,
            metadata=None,
        )

        # Container 2
        config2 = ContainerConfig(
            container_id="container-2",
            ip_address="172.17.0.3",
            registered_at=time.time(),
            last_seen=time.time(),
            ttl_seconds=86400,
            metadata=None,
        )

        # Exhaust container-1's tokens
        mock_get_config.return_value = config1
        for _ in range(10):
            addon.request(mock_flow)
            mock_flow.response = None

        # Container-1 should be rate limited
        addon.request(mock_flow)
        assert mock_flow.response is not None
        assert mock_flow.response.status_code == 429

        # Container-2 should still have tokens
        mock_flow.response = None
        mock_get_config.return_value = config2
        addon.request(mock_flow)
        assert mock_flow.response is None  # Request allowed

        # Verify two buckets exist
        assert len(addon.buckets) == 2

    @patch("addons.rate_limiter.get_container_config")
    def test_same_container_different_upstreams_isolated(
        self, mock_get_config, addon, mock_container_config
    ):
        """Test same container has separate limits per upstream."""
        mock_get_config.return_value = mock_container_config

        # Create flow for upstream 1
        flow1 = MockHTTPFlow(pretty_host="api1.example.com")

        # Create flow for upstream 2
        flow2 = MockHTTPFlow(pretty_host="api2.example.com")

        # Exhaust tokens for upstream 1
        for _ in range(10):
            addon.request(flow1)
            flow1.response = None

        # Upstream 1 should be rate limited
        addon.request(flow1)
        assert flow1.response is not None
        assert flow1.response.status_code == 429

        # Upstream 2 should still have tokens
        addon.request(flow2)
        assert flow2.response is None  # Request allowed

        # Verify two buckets exist
        assert len(addon.buckets) == 2

    @patch("addons.rate_limiter.get_container_config")
    def test_bucket_key_format(self, mock_get_config, addon, mock_flow, mock_container_config):
        """Test bucket keys are (container_id, upstream_host) tuples."""
        mock_get_config.return_value = mock_container_config

        addon.request(mock_flow)

        expected_key = ("test-container", "api.example.com")
        assert expected_key in addon.buckets


class TestRefillBehavior:
    """Tests for token refill over time."""

    @patch("addons.rate_limiter.get_container_config")
    @patch("addons.rate_limiter.time")
    def test_tokens_refill_over_time(
        self, mock_time, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test tokens refill based on elapsed time."""
        mock_get_config.return_value = mock_container_config

        # Start at t=0
        mock_time.time.return_value = 100.0

        # Consume all tokens
        for _ in range(10):
            addon.request(mock_flow)
            mock_flow.response = None

        # Should be rate limited now
        addon.request(mock_flow)
        assert mock_flow.response.status_code == 429
        mock_flow.response = None

        # Advance time by 1 second (refill_rate=2, so +2 tokens)
        mock_time.time.return_value = 101.0

        # Should allow 2 more requests
        addon.request(mock_flow)
        assert mock_flow.response is None
        mock_flow.response = None

        addon.request(mock_flow)
        assert mock_flow.response is None
        mock_flow.response = None

        # Third request should fail
        addon.request(mock_flow)
        assert mock_flow.response.status_code == 429

    @patch("addons.rate_limiter.get_container_config")
    @patch("addons.rate_limiter.time")
    def test_full_refill_after_waiting(
        self, mock_time, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test bucket fully refills after sufficient time."""
        mock_get_config.return_value = mock_container_config

        # Start at t=0
        mock_time.time.return_value = 100.0

        # Consume all tokens
        for _ in range(10):
            addon.request(mock_flow)
            mock_flow.response = None

        # Wait long enough to fully refill (10 tokens / 2 tokens per second = 5 seconds)
        mock_time.time.return_value = 106.0  # Extra buffer

        # Should be able to consume full capacity again
        for _ in range(10):
            addon.request(mock_flow)
            assert mock_flow.response is None
            mock_flow.response = None


class TestCleanup:
    """Tests for cleanup of stale buckets."""

    @patch("addons.rate_limiter.get_container_config")
    @patch("addons.rate_limiter.time")
    def test_cleanup_triggered_after_interval(
        self, mock_time, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test cleanup is triggered after cleanup_interval."""
        mock_get_config.return_value = mock_container_config

        # Start at t=0
        mock_time.time.return_value = 100.0
        addon.last_cleanup = 100.0

        # Make a request
        addon.request(mock_flow)

        # Advance time beyond cleanup_interval (60s)
        mock_time.time.return_value = 200.0

        # Next request should trigger cleanup
        with patch.object(addon, "_cleanup_stale_buckets") as mock_cleanup:
            addon.request(mock_flow)
            mock_cleanup.assert_called_once()

    @patch("addons.rate_limiter.get_container_config")
    def test_cleanup_removes_stale_buckets(
        self, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test cleanup removes buckets not accessed recently."""
        mock_get_config.return_value = mock_container_config

        # Create a bucket
        addon.request(mock_flow)
        bucket_key = ("test-container", "api.example.com")
        assert bucket_key in addon.buckets

        # Manually set last_access to old time
        old_time = time.time() - BUCKET_EXPIRY_SECONDS - 100
        addon.buckets[bucket_key].last_access = old_time

        # Run cleanup
        addon._cleanup_stale_buckets(time.time())

        # Bucket should be removed
        assert bucket_key not in addon.buckets

    @patch("addons.rate_limiter.get_container_config")
    def test_cleanup_keeps_active_buckets(
        self, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test cleanup preserves recently accessed buckets."""
        mock_get_config.return_value = mock_container_config

        # Create a bucket
        addon.request(mock_flow)
        bucket_key = ("test-container", "api.example.com")

        # Run cleanup (bucket was just accessed)
        addon._cleanup_stale_buckets(time.time())

        # Bucket should still exist
        assert bucket_key in addon.buckets

    @patch("addons.rate_limiter.get_container_config")
    def test_cleanup_updates_last_cleanup(
        self, mock_get_config, addon, mock_flow, mock_container_config
    ):
        """Test cleanup updates last_cleanup timestamp."""
        now = time.time()
        addon.last_cleanup = now - 100

        addon._cleanup_stale_buckets(now)

        assert addon.last_cleanup == now


class TestConcurrency:
    """Tests for thread safety."""

    @patch("addons.rate_limiter.get_container_config")
    def test_concurrent_requests_same_container(
        self, mock_get_config, addon, mock_container_config
    ):
        """Test concurrent requests from same container are thread-safe."""
        mock_get_config.return_value = mock_container_config

        results = {"allowed": 0, "denied": 0}
        errors = []

        def make_request():
            try:
                flow = MockHTTPFlow(pretty_host="api.example.com")

                addon.request(flow)

                if flow.response is None:
                    results["allowed"] += 1
                else:
                    results["denied"] += 1
            except Exception as e:
                errors.append(e)

        # Launch 20 concurrent requests (capacity is 10)
        threads = [threading.Thread(target=make_request) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have no errors
        assert not errors

        # Should allow exactly 10, deny exactly 10
        assert results["allowed"] == 10
        assert results["denied"] == 10

    @patch("addons.rate_limiter.get_container_config")
    def test_concurrent_requests_different_containers(self, mock_get_config, addon):
        """Test concurrent requests from different containers are isolated."""
        results = []
        errors = []

        def make_request(container_num):
            try:
                config = ContainerConfig(
                    container_id=f"container-{container_num}",
                    ip_address=f"172.17.0.{container_num}",
                    registered_at=time.time(),
                    last_seen=time.time(),
                    ttl_seconds=86400,
                    metadata=None,
                )

                flow = MockHTTPFlow(pretty_host="api.example.com")

                # Temporarily override mock for this thread
                with patch("addons.rate_limiter.get_container_config", return_value=config):
                    addon.request(flow)

                if flow.response is None:
                    results.append((container_num, "allowed"))
                else:
                    results.append((container_num, "denied"))
            except Exception as e:
                errors.append(e)

        # Launch requests from 5 different containers, 3 requests each
        threads = []
        for i in range(5):
            for _ in range(3):
                threads.append(threading.Thread(target=make_request, args=(i,)))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have no errors
        assert not errors

        # All requests should be allowed (each container has separate bucket)
        assert len(results) == 15
        assert all(status == "allowed" for _, status in results)

        # Should have 5 buckets
        assert len(addon.buckets) == 5


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_zero_capacity(self):
        """Test addon with zero capacity denies all requests."""
        addon = RateLimiterAddon(capacity=0.0, refill_rate=1.0)

        config = ContainerConfig(
            container_id="test",
            ip_address="172.17.0.2",
            registered_at=time.time(),
            last_seen=time.time(),
            ttl_seconds=86400,
            metadata=None,
        )

        flow = MockHTTPFlow(pretty_host="api.example.com")

        with patch("addons.rate_limiter.get_container_config", return_value=config):
            addon.request(flow)

        # Should be denied immediately
        assert flow.response is not None
        assert flow.response.status_code == 429

    def test_very_high_refill_rate(self):
        """Test addon with very high refill rate."""
        addon = RateLimiterAddon(capacity=10.0, refill_rate=1000.0)

        config = ContainerConfig(
            container_id="test",
            ip_address="172.17.0.2",
            registered_at=time.time(),
            last_seen=time.time(),
            ttl_seconds=86400,
            metadata=None,
        )

        flow = MockHTTPFlow(pretty_host="api.example.com")

        with patch("addons.rate_limiter.get_container_config", return_value=config):
            # Should be able to make many requests
            for _ in range(100):
                addon.request(flow)
                flow.response = None

        # Last request should still be allowed (tokens refill instantly)
        assert flow.response is None

    @patch("addons.rate_limiter.get_container_config")
    def test_cleanup_with_no_buckets(self, mock_get_config, addon):
        """Test cleanup handles empty bucket dict gracefully."""
        now = time.time()

        # Should not raise exception
        addon._cleanup_stale_buckets(now)

        assert len(addon.buckets) == 0
        assert addon.last_cleanup == now

    @patch("addons.rate_limiter.get_container_config")
    def test_multiple_cleanups_in_succession(self, mock_get_config, addon, mock_flow, mock_container_config):
        """Test multiple cleanups don't cause issues."""
        mock_get_config.return_value = mock_container_config

        addon.request(mock_flow)
        now = time.time()

        # Run cleanup multiple times
        for _ in range(5):
            addon._cleanup_stale_buckets(now)

        # Bucket should still exist
        assert len(addon.buckets) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
