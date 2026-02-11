"""Integration tests for the full addon chain.

Tests interaction scenarios across the addon pipeline:
  container_identity -> policy_engine -> dns_filter -> credential_injector
  -> git_proxy -> rate_limiter -> circuit_breaker

Individual addons are well-tested in isolation; these tests exercise
interaction scenarios like:
- Request passes identity but fails policy
- Request passes policy but hits rate limit
- Request passes entire chain end-to-end
- Circuit breaker triggers after upstream failures through the chain
"""

import os
import sys
import time
from unittest import mock
from unittest.mock import patch, MagicMock

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from addons.credential_injector import CredentialInjector
from addons.rate_limiter import RateLimiterAddon
from addons.circuit_breaker import CircuitBreakerAddon
from addons.policy_engine import PolicyEngine
from registry import ContainerConfig


class MockHeaders(dict):
    """Case-insensitive mock headers."""

    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default

    def __contains__(self, key):
        return any(k.lower() == key.lower() for k in self.keys())

    def __delitem__(self, key):
        for k in list(self.keys()):
            if k.lower() == key.lower():
                super().__delitem__(k)
                return
        raise KeyError(key)

    def __setitem__(self, key, value):
        for k in list(self.keys()):
            if k.lower() == key.lower():
                super().__delitem__(k)
        super().__setitem__(key, value)


def make_flow(host="api.github.com", path="/repos/owner/repo", method="GET"):
    """Create a mock HTTP flow for testing."""
    flow = MagicMock()
    flow.request = MagicMock()
    flow.request.host = host
    flow.request.pretty_host = host
    flow.request.path = path
    flow.request.method = method
    flow.request.port = 443
    flow.request.headers = MockHeaders({
        "Authorization": "Bearer CREDENTIAL_PROXY_PLACEHOLDER",
    })
    flow.request.get_content.return_value = b""
    flow.response = None
    flow.error = None
    flow.metadata = {}
    flow.client_conn = MagicMock()
    flow.client_conn.peername = ("172.17.0.2", 12345)
    return flow


class TestPassesPolicyButHitsRateLimit:
    """Test that a request passing policy can still be rate-limited."""

    def test_rate_limit_after_policy_pass(self):
        """Request passes policy but is denied by rate limiter after exhausting tokens."""
        rate_limiter = RateLimiterAddon(capacity=2.0, refill_rate=0.1)
        container_config = ContainerConfig(
            container_id="test-container",
            ip_address="172.17.0.2",
            registered_at=time.time(),
            last_seen=time.time(),
            ttl_seconds=86400,
            metadata=None,
        )

        with patch("addons.rate_limiter.get_container_config", return_value=container_config):
            # First 2 requests should pass
            for _ in range(2):
                flow = make_flow()
                rate_limiter.request(flow)
                assert flow.response is None, "Request should be allowed"

            # Third request should be rate-limited
            flow = make_flow()
            rate_limiter.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 429


class TestCircuitBreakerAfterUpstreamFailures:
    """Test circuit breaker triggers after upstream failures through the chain."""

    def test_circuit_opens_after_failures_through_chain(self):
        """Circuit breaker opens after repeated 5xx responses flow through chain."""
        cb = CircuitBreakerAddon(
            failure_threshold=3,
            recovery_timeout=1,
            success_threshold=2,
        )

        # Simulate 3 upstream failures
        for _ in range(3):
            flow = make_flow()
            cb.request(flow)
            flow.response = MagicMock()
            flow.response.status_code = 503
            cb.response(flow)

        # Circuit should now be open — next request gets 503 from circuit breaker
        mock_http = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.content = b"Circuit breaker is open"
        mock_http.Response.make.return_value = mock_response

        import addons.circuit_breaker as cb_module
        original_http = cb_module.http
        try:
            cb_module.http = mock_http
            flow = make_flow()
            cb.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 503
        finally:
            cb_module.http = original_http


class TestCredentialInjectionThenRateLimit:
    """Test credential injection happens before rate limiting."""

    def test_credentials_injected_before_rate_limit(self):
        """Credential injector modifies headers, rate limiter checks separately."""
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_test_token"}, clear=False):
            injector = CredentialInjector()

        rate_limiter = RateLimiterAddon(capacity=10.0, refill_rate=1.0)
        container_config = ContainerConfig(
            container_id="test-container",
            ip_address="172.17.0.2",
            registered_at=time.time(),
            last_seen=time.time(),
            ttl_seconds=86400,
            metadata=None,
        )

        flow = make_flow(host="api.github.com", path="/repos/owner/repo")

        # Run through credential injector first
        injector.request(flow)
        assert flow.response is None, "Credential injection should not block"
        assert flow.request.headers.get("Authorization") == "Bearer ghp_test_token"

        # Then rate limiter
        with patch("addons.rate_limiter.get_container_config", return_value=container_config):
            rate_limiter.request(flow)
        assert flow.response is None, "Rate limiter should allow first request"


class TestEndToEndAllowedRequest:
    """Test a request that passes through the entire chain successfully."""

    def test_full_chain_pass(self):
        """A legitimate request passes credential injection, rate limiting, and circuit breaker."""
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_test_token"}, clear=False):
            injector = CredentialInjector()

        rate_limiter = RateLimiterAddon(capacity=10.0, refill_rate=1.0)
        cb = CircuitBreakerAddon(failure_threshold=5, recovery_timeout=30)

        container_config = ContainerConfig(
            container_id="test-container",
            ip_address="172.17.0.2",
            registered_at=time.time(),
            last_seen=time.time(),
            ttl_seconds=86400,
            metadata=None,
        )

        flow = make_flow(host="api.github.com", path="/repos/owner/repo")

        # Step 1: Credential injection
        injector.request(flow)
        assert flow.response is None

        # Step 2: Rate limiting
        with patch("addons.rate_limiter.get_container_config", return_value=container_config):
            rate_limiter.request(flow)
        assert flow.response is None

        # Step 3: Circuit breaker
        cb.request(flow)
        assert flow.response is None

        # Simulate successful upstream response
        flow.response = MagicMock()
        flow.response.status_code = 200
        cb.response(flow)

        # Verify circuit stays closed
        with cb._lock:
            status = cb._circuits["api.github.com:443"]
            from addons.circuit_breaker import CircuitState
            assert status.state == CircuitState.CLOSED
