"""Unit tests for gateway_middleware.py.

Tests the gateway-layer circuit breaker and rate limiter middleware.
"""

import os
import sys
from unittest.mock import MagicMock

# Ensure aiohttp is mocked before import
if "aiohttp" not in sys.modules:
    sys.modules["aiohttp"] = MagicMock()
    sys.modules["aiohttp.web"] = MagicMock()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from gateway_middleware import CircuitBreakerMiddleware, CircuitState


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
