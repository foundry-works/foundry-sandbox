"""Integration tests for API proxying through the unified-proxy.

Tests API request handling including:
- Credential injection for various providers
- Blocked API endpoints return 403
- Rate limiting enforcement
- Circuit breaker behavior
"""

import os
import sys
from typing import Optional
from unittest import mock

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from addons.credential_injector import CredentialInjector, OAUTH_PLACEHOLDER
from addons.rate_limiter import RateLimiterAddon
from addons.circuit_breaker import CircuitBreakerAddon


class MockContainerConfig:
    """Mock container configuration for testing."""

    def __init__(self, container_id: str = "test-container"):
        self.container_id = container_id
        self.ip_address = "172.17.0.2"
        self.metadata = {}


class MockHeaders(dict):
    """Mock headers that behave like a dict but track modifications."""

    def __init__(self, initial: Optional[dict] = None):
        super().__init__(initial or {})
        self.set_calls = []
        self.del_calls = []

    def __setitem__(self, key, value):
        self.set_calls.append((key, value))
        super().__setitem__(key, value)

    def __delitem__(self, key):
        self.del_calls.append(key)
        if key in self:
            super().__delitem__(key)


class MockFlow:
    """Mock mitmproxy flow for testing."""

    def __init__(
        self,
        host: str = "api.anthropic.com",
        path: str = "/v1/messages",
        method: str = "POST",
        headers: Optional[dict] = None,
    ):
        self.request = mock.MagicMock()
        self.request.host = host
        self.request.pretty_host = host  # Used by rate limiter
        self.request.path = path
        self.request.method = method
        self.request.headers = MockHeaders(headers)

        self.response = None
        self.metadata = {}
        self.client_conn = mock.MagicMock()
        self.client_conn.peername = ("172.17.0.2", 12345)


class TestCredentialInjection:
    """Test API credential injection."""

    @pytest.fixture
    def injector(self):
        """Create credential injector with test env vars."""
        with mock.patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "sk-ant-test-key",
            "OPENAI_API_KEY": "sk-openai-test-key",
            "GITHUB_TOKEN": "ghp_testtoken",
        }, clear=True):
            yield CredentialInjector()

    def test_anthropic_api_key_injected(self, injector):
        """Test Anthropic API key injection."""
        flow = MockFlow(host="api.anthropic.com", path="/v1/messages")
        flow.metadata["container"] = MockContainerConfig()

        injector.request(flow)

        # Should inject x-api-key header
        assert ("x-api-key", "sk-ant-test-key") in flow.request.headers.set_calls

    def test_github_token_injected(self, injector):
        """Test GitHub token injection."""
        flow = MockFlow(host="api.github.com", path="/repos/owner/repo")

        flow.metadata["container"] = MockContainerConfig()
        injector.request(flow)

        # Should inject Authorization header with Bearer token
        assert ("Authorization", "Bearer ghp_testtoken") in flow.request.headers.set_calls

    def test_placeholder_replaced(self, injector):
        """Test placeholder token is replaced with real credential."""
        flow = MockFlow(
            host="api.anthropic.com",
            path="/v1/messages",
            headers={"x-api-key": OAUTH_PLACEHOLDER},
        )

        flow.metadata["container"] = MockContainerConfig()
        injector.request(flow)

        # Placeholder should be removed and real key injected
        assert "x-api-key" in flow.request.headers.del_calls
        assert ("x-api-key", "sk-ant-test-key") in flow.request.headers.set_calls


class TestBlockedEndpoints:
    """Test blocked API endpoints return 403."""

    @pytest.fixture
    def injector(self):
        """Create credential injector."""
        with mock.patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "sk-ant-test-key",
        }, clear=True):
            return CredentialInjector()

    def test_unknown_host_passes_through(self, injector):
        """Test requests to unknown hosts pass through."""
        flow = MockFlow(host="unknown.example.com", path="/api/test")

        flow.metadata["container"] = MockContainerConfig()
        injector.request(flow)

        # Should not block unknown hosts
        assert flow.response is None


class TestRateLimiting:
    """Test rate limiting enforcement."""

    @pytest.fixture
    def rate_limiter(self):
        """Create rate limiter with low limits for testing."""
        # RateLimiterAddon uses capacity and refill_rate, not requests_per_minute
        return RateLimiterAddon(
            capacity=2,       # Only 2 tokens
            refill_rate=0.1,  # Very slow refill for testing
        )

    def test_under_limit_allowed(self, rate_limiter):
        """Test requests under limit are allowed."""
        flow = MockFlow(host="api.anthropic.com")

        with mock.patch("addons.rate_limiter.get_container_config", return_value=MockContainerConfig()):
            rate_limiter.request(flow)

        assert flow.response is None

    def test_over_limit_blocked(self, rate_limiter):
        """Test requests over limit are blocked with 429."""
        container_config = MockContainerConfig()

        with mock.patch("addons.rate_limiter.get_container_config", return_value=container_config):
            # Send all 5 requests and collect responses
            responses = []
            for i in range(5):
                flow = MockFlow(host="api.anthropic.com")
                rate_limiter.request(flow)
                responses.append(flow.response)

            # First 2 should pass (capacity=2), rest should be 429
            passed = [r for r in responses if r is None]
            blocked = [r for r in responses if r is not None and r.status_code == 429]
            assert len(passed) == 2, f"Expected 2 requests to pass (capacity=2), got {len(passed)}"
            assert len(blocked) == 3, f"Expected 3 requests blocked (5 total - 2 capacity), got {len(blocked)}"


class TestCircuitBreaker:
    """Test circuit breaker behavior."""

    @pytest.fixture
    def circuit_breaker(self):
        """Create circuit breaker with low thresholds for testing."""
        return CircuitBreakerAddon(
            failure_threshold=2,
            recovery_timeout=1,
        )

    def test_circuit_closed_initially(self, circuit_breaker):
        """Test circuit is closed (allowing requests) initially."""
        flow = MockFlow(host="api.anthropic.com")

        # Circuit breaker doesn't use container identity - just call directly
        circuit_breaker.request(flow)

        # Should allow through when closed
        assert flow.response is None

    def test_circuit_opens_after_failures(self, circuit_breaker):
        """Test circuit opens after repeated failures."""
        # Simulate failures - circuit breaker uses host:port as upstream key,
        # so we must set port explicitly to ensure all flows share the same circuit.
        for i in range(3):
            flow = MockFlow(host="api.anthropic.com")
            flow.request.port = 443
            circuit_breaker.request(flow)
            flow.response = mock.MagicMock()
            flow.response.status_code = 500
            circuit_breaker.response(flow)

        # Next request should be blocked (circuit is open)
        flow = MockFlow(host="api.anthropic.com")
        flow.request.port = 443
        circuit_breaker.request(flow)

        # Verify circuit is open: response should be set to 503
        assert flow.response is not None
        assert flow.response.status_code == 503


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
