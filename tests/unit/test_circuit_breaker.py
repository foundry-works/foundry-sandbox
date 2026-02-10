"""Unit tests for CircuitBreakerAddon.

Tests the circuit breaker pattern implementation including state transitions,
per-upstream isolation, recovery behavior, and cleanup.
"""

import os
import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

# NOTE: We do NOT overwrite sys.modules["mitmproxy"] here because conftest.py
# already installs proper mitmproxy mocks. Overwriting the top-level module
# entry would pollute the global module cache and break other test files
# (test_github_api_filter, test_dual_layer_consistency) that import
# mitmproxy-based addons later in the session.

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

import addons.circuit_breaker as _cb_module
from addons.circuit_breaker import (
    CircuitBreakerAddon,
    CircuitState,
    CircuitStatus,
)


@pytest.fixture
def time_control():
    """Controllable time mock for circuit breaker tests.

    Replaces time.time() in the circuit breaker module so tests can
    advance time instantly instead of sleeping.
    """
    _now = [1000.0]
    _original = _cb_module.time.time

    def _fake_time():
        return _now[0]

    def _advance(seconds):
        _now[0] += seconds

    _cb_module.time.time = _fake_time
    try:
        yield _advance
    finally:
        _cb_module.time.time = _original


@pytest.fixture
def addon(time_control):
    """Create a circuit breaker addon with short timeouts for testing."""
    return CircuitBreakerAddon(
        failure_threshold=3,
        recovery_timeout=1,  # 1 second for fast tests
        success_threshold=2,
        cleanup_interval=10,
        stale_timeout=20,
    )


@pytest.fixture
def mock_flow():
    """Create a mock HTTP flow."""
    flow = MagicMock()
    flow.request = MagicMock()
    flow.request.pretty_host = "example.com"
    flow.request.port = 443
    flow.response = None
    flow.error = None
    return flow


class TestCircuitStatus:
    """Tests for CircuitStatus dataclass."""

    def test_initial_state(self):
        """Test CircuitStatus initializes in CLOSED state."""
        status = CircuitStatus()
        assert status.state == CircuitState.CLOSED
        assert status.failure_count == 0
        assert status.success_count == 0
        assert status.last_failure_time is None
        assert status.last_success_time is None
        assert status.last_state_change_time > 0
        assert status.last_access_time > 0

    def test_update_access_time(self, time_control):
        """Test update_access_time updates timestamp."""
        status = CircuitStatus()
        original_time = status.last_access_time
        time_control(0.01)
        status.update_access_time()
        assert status.last_access_time > original_time


class TestCircuitOpensOnFailures:
    """Tests that circuit opens after consecutive failures."""

    def test_circuit_opens_after_threshold_failures(self, addon, mock_flow):
        """Test circuit opens after failure_threshold consecutive failures."""
        upstream = "example.com:443"

        # Send failure_threshold failures (3 in our fixture)
        for i in range(3):
            addon.request(mock_flow)
            mock_flow.response = MagicMock()
            mock_flow.response.status_code = 503
            addon.response(mock_flow)
            mock_flow.response = None

        # Check circuit is now OPEN
        with addon._lock:
            status = addon._circuits[upstream]
            assert status.state == CircuitState.OPEN
            assert status.failure_count == 3

    def test_circuit_stays_closed_below_threshold(self, addon, mock_flow):
        """Test circuit stays CLOSED below failure threshold."""
        upstream = "example.com:443"

        # Send threshold - 1 failures (2 in our fixture)
        for i in range(2):
            addon.request(mock_flow)
            mock_flow.response = MagicMock()
            mock_flow.response.status_code = 500
            addon.response(mock_flow)
            mock_flow.response = None

        # Check circuit is still CLOSED
        with addon._lock:
            status = addon._circuits[upstream]
            assert status.state == CircuitState.CLOSED
            assert status.failure_count == 2

    def test_circuit_blocks_requests_when_open(self, addon, mock_flow):
        """Test circuit returns 503 when OPEN."""
        # Mock http.Response.make to return a proper mock response
        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.content = b"Service Unavailable: Circuit breaker is open"

        with patch('addons.circuit_breaker.http') as mock_http:
            mock_http.Response.make.return_value = mock_response

            # Trigger circuit opening
            for i in range(3):
                addon.request(mock_flow)
                mock_flow.response = MagicMock()
                mock_flow.response.status_code = 503
                addon.response(mock_flow)
                mock_flow.response = None

            # Next request should be blocked
            addon.request(mock_flow)
            assert mock_flow.response is not None
            assert mock_flow.response.status_code == 503
            assert b"Circuit breaker is open" in mock_flow.response.content

    def test_connection_errors_count_as_failures(self, addon, mock_flow):
        """Test connection errors trigger circuit breaker."""
        mock_flow.error = MagicMock()
        mock_flow.error.__str__ = lambda self: "Connection refused"

        # Send connection errors
        for i in range(3):
            addon.request(mock_flow)
            addon.error(mock_flow)

        # Check circuit is OPEN
        with addon._lock:
            status = addon._circuits["example.com:443"]
            assert status.state == CircuitState.OPEN

    def test_5xx_responses_count_as_failures(self, addon, mock_flow):
        """Test 5xx status codes count as failures."""
        status_codes = [500, 502, 503, 504]

        for code in status_codes:
            addon.request(mock_flow)
            mock_flow.response = MagicMock()
            mock_flow.response.status_code = code
            addon.response(mock_flow)
            mock_flow.response = None

        # Should have 4 failures (exceeds threshold of 3)
        with addon._lock:
            status = addon._circuits["example.com:443"]
            assert status.state == CircuitState.OPEN


class TestHalfOpenState:
    """Tests for HALF_OPEN state behavior."""

    def test_circuit_transitions_to_half_open_after_timeout(self, addon, mock_flow, time_control):
        """Test circuit transitions from OPEN to HALF_OPEN after recovery_timeout."""
        # Open the circuit
        for i in range(3):
            addon.request(mock_flow)
            mock_flow.response = MagicMock()
            mock_flow.response.status_code = 503
            addon.response(mock_flow)
            mock_flow.response = None

        # Verify it's OPEN
        with addon._lock:
            status = addon._circuits["example.com:443"]
            assert status.state == CircuitState.OPEN

        # Advance past recovery timeout (1 second in our fixture)
        time_control(1.1)

        # Next request should transition to HALF_OPEN
        addon.request(mock_flow)
        with addon._lock:
            status = addon._circuits["example.com:443"]
            assert status.state == CircuitState.HALF_OPEN

    def test_half_open_allows_requests(self, addon, mock_flow, time_control):
        """Test HALF_OPEN state allows requests through."""
        # Open the circuit and transition to HALF_OPEN
        for i in range(3):
            addon.request(mock_flow)
            mock_flow.response = MagicMock()
            mock_flow.response.status_code = 503
            addon.response(mock_flow)
            mock_flow.response = None

        time_control(1.1)
        addon.request(mock_flow)

        # Request should not be blocked
        assert mock_flow.response is None or mock_flow.response.status_code != 503

    def test_half_open_reopens_on_failure(self, addon, mock_flow, time_control):
        """Test HALF_OPEN transitions back to OPEN on any failure."""
        # Open the circuit
        for i in range(3):
            addon.request(mock_flow)
            mock_flow.response = MagicMock()
            mock_flow.response.status_code = 503
            addon.response(mock_flow)
            mock_flow.response = None

        # Advance past recovery timeout and transition to HALF_OPEN
        time_control(1.1)
        addon.request(mock_flow)

        # Send a failure in HALF_OPEN state
        mock_flow.response = MagicMock()
        mock_flow.response.status_code = 500
        addon.response(mock_flow)

        # Should be back to OPEN
        with addon._lock:
            status = addon._circuits["example.com:443"]
            assert status.state == CircuitState.OPEN


class TestCircuitClosesOnSuccess:
    """Tests that circuit closes after successful requests."""

    def test_circuit_closes_after_threshold_successes(self, addon, mock_flow, time_control):
        """Test circuit transitions from HALF_OPEN to CLOSED after success_threshold successes."""
        # Open the circuit
        for i in range(3):
            addon.request(mock_flow)
            mock_flow.response = MagicMock()
            mock_flow.response.status_code = 503
            addon.response(mock_flow)
            mock_flow.response = None

        # Advance past recovery timeout and transition to HALF_OPEN
        time_control(1.1)
        addon.request(mock_flow)

        # Send success_threshold successful requests (2 in our fixture)
        for i in range(2):
            addon.request(mock_flow)
            mock_flow.response = MagicMock()
            mock_flow.response.status_code = 200
            addon.response(mock_flow)
            mock_flow.response = None

        # Circuit should be CLOSED
        with addon._lock:
            status = addon._circuits["example.com:443"]
            assert status.state == CircuitState.CLOSED
            assert status.success_count == 0  # Reset on state transition

    def test_success_resets_failure_count(self, addon, mock_flow):
        """Test successful request resets failure count in CLOSED state."""
        # Send some failures
        for i in range(2):
            addon.request(mock_flow)
            mock_flow.response = MagicMock()
            mock_flow.response.status_code = 500
            addon.response(mock_flow)
            mock_flow.response = None

        # Send a success
        addon.request(mock_flow)
        mock_flow.response = MagicMock()
        mock_flow.response.status_code = 200
        addon.response(mock_flow)

        # Failure count should be reset
        with addon._lock:
            status = addon._circuits["example.com:443"]
            assert status.failure_count == 0
            assert status.state == CircuitState.CLOSED

    def test_2xx_responses_count_as_success(self, addon, mock_flow):
        """Test 2xx status codes count as success."""
        status_codes = [200, 201, 204, 206]

        for code in status_codes:
            addon.request(mock_flow)
            mock_flow.response = MagicMock()
            mock_flow.response.status_code = code
            addon.response(mock_flow)
            mock_flow.response = None

        # Should have no failures
        with addon._lock:
            status = addon._circuits["example.com:443"]
            assert status.failure_count == 0
            assert status.last_success_time is not None

    def test_4xx_responses_count_as_success(self, addon, mock_flow):
        """Test 4xx status codes count as success (client errors, not upstream failures)."""
        status_codes = [400, 404, 429]

        for code in status_codes:
            addon.request(mock_flow)
            mock_flow.response = MagicMock()
            mock_flow.response.status_code = code
            addon.response(mock_flow)
            mock_flow.response = None

        # Should have no failures (4xx is not an upstream failure)
        with addon._lock:
            status = addon._circuits["example.com:443"]
            assert status.failure_count == 0


class TestPerUpstreamIsolation:
    """Tests that circuits are isolated per upstream."""

    def test_different_upstreams_have_separate_circuits(self, addon):
        """Test different upstreams maintain separate circuit states."""
        # Create flows for different upstreams
        flow1 = MagicMock()
        flow1.request = MagicMock()
        flow1.request.pretty_host = "service1.com"
        flow1.request.port = 443
        flow1.response = None
        flow1.error = None

        flow2 = MagicMock()
        flow2.request = MagicMock()
        flow2.request.pretty_host = "service2.com"
        flow2.request.port = 443
        flow2.response = None
        flow2.error = None

        # Open circuit for service1
        for i in range(3):
            addon.request(flow1)
            flow1.response = MagicMock()
            flow1.response.status_code = 503
            addon.response(flow1)
            flow1.response = None

        # service2 should still be CLOSED
        addon.request(flow2)
        flow2.response = MagicMock()
        flow2.response.status_code = 200
        addon.response(flow2)

        # Check states
        with addon._lock:
            status1 = addon._circuits["service1.com:443"]
            status2 = addon._circuits["service2.com:443"]
            assert status1.state == CircuitState.OPEN
            assert status2.state == CircuitState.CLOSED

    def test_same_host_different_ports_isolated(self, addon):
        """Test same host with different ports have separate circuits."""
        flow_http = MagicMock()
        flow_http.request = MagicMock()
        flow_http.request.pretty_host = "example.com"
        flow_http.request.port = 80
        flow_http.response = None
        flow_http.error = None

        flow_https = MagicMock()
        flow_https.request = MagicMock()
        flow_https.request.pretty_host = "example.com"
        flow_https.request.port = 443
        flow_https.response = None
        flow_https.error = None

        # Open circuit for HTTP
        for i in range(3):
            addon.request(flow_http)
            flow_http.response = MagicMock()
            flow_http.response.status_code = 503
            addon.response(flow_http)
            flow_http.response = None

        # HTTPS should still be CLOSED
        addon.request(flow_https)
        flow_https.response = MagicMock()
        flow_https.response.status_code = 200
        addon.response(flow_https)

        # Check states
        with addon._lock:
            status_http = addon._circuits["example.com:80"]
            status_https = addon._circuits["example.com:443"]
            assert status_http.state == CircuitState.OPEN
            assert status_https.state == CircuitState.CLOSED

    def test_circuit_count_matches_upstream_count(self, addon):
        """Test circuit registry grows with unique upstreams."""
        upstreams = [
            ("service1.com", 443),
            ("service2.com", 443),
            ("service3.com", 80),
        ]

        for host, port in upstreams:
            flow = MagicMock()
            flow.request = MagicMock()
            flow.request.pretty_host = host
            flow.request.port = port
            flow.response = None
            addon.request(flow)
            flow.response = MagicMock()
            flow.response.status_code = 200
            addon.response(flow)

        # Should have 3 circuits
        with addon._lock:
            assert len(addon._circuits) == 3


class TestStaleCircuitCleanup:
    """Tests for stale circuit cleanup."""

    def test_cleanup_removes_stale_circuits(self, addon, mock_flow):
        """Test stale circuits are removed after stale_timeout."""
        # Create a circuit
        addon.request(mock_flow)
        mock_flow.response = MagicMock()
        mock_flow.response.status_code = 200
        addon.response(mock_flow)

        # Manually set last_access_time to past
        with addon._lock:
            status = addon._circuits["example.com:443"]
            status.last_access_time = _cb_module.time.time() - 25  # 25 seconds ago (stale_timeout=20)

        # Trigger cleanup
        with addon._lock:
            addon._cleanup_stale_circuits()

        # Circuit should be removed
        with addon._lock:
            assert "example.com:443" not in addon._circuits

    def test_cleanup_preserves_active_circuits(self, addon, mock_flow):
        """Test active circuits are not removed during cleanup."""
        # Create a circuit and keep it active
        addon.request(mock_flow)
        mock_flow.response = MagicMock()
        mock_flow.response.status_code = 200
        addon.response(mock_flow)

        # Trigger cleanup
        with addon._lock:
            addon._cleanup_stale_circuits()

        # Circuit should still exist
        with addon._lock:
            assert "example.com:443" in addon._circuits

    def test_periodic_cleanup_triggered(self, addon, mock_flow):
        """Test cleanup is triggered periodically via request."""
        # Create a stale circuit
        addon.request(mock_flow)
        mock_flow.response = MagicMock()
        mock_flow.response.status_code = 200
        addon.response(mock_flow)

        with addon._lock:
            status = addon._circuits["example.com:443"]
            status.last_access_time = _cb_module.time.time() - 25
            # Set last_cleanup_time to trigger cleanup
            addon._last_cleanup_time = _cb_module.time.time() - 15  # cleanup_interval=10

        # Next request should trigger cleanup
        flow2 = MagicMock()
        flow2.request = MagicMock()
        flow2.request.pretty_host = "other.com"
        flow2.request.port = 443
        flow2.response = None
        addon.request(flow2)

        # Old circuit should be cleaned up
        with addon._lock:
            assert "example.com:443" not in addon._circuits


class TestConfiguration:
    """Tests for configuration and initialization."""

    def test_default_configuration(self):
        """Test addon uses default configuration values."""
        addon = CircuitBreakerAddon()
        assert addon.failure_threshold == 5
        assert addon.recovery_timeout == 30
        assert addon.success_threshold == 2
        assert addon.cleanup_interval == 300
        assert addon.stale_timeout == 600

    def test_custom_configuration(self):
        """Test addon accepts custom configuration."""
        addon = CircuitBreakerAddon(
            failure_threshold=10,
            recovery_timeout=60,
            success_threshold=3,
            cleanup_interval=600,
            stale_timeout=1200,
        )
        assert addon.failure_threshold == 10
        assert addon.recovery_timeout == 60
        assert addon.success_threshold == 3
        assert addon.cleanup_interval == 600
        assert addon.stale_timeout == 1200

    def test_environment_variable_configuration(self):
        """Test addon reads from environment variables."""
        env_vars = {
            "CIRCUIT_BREAKER_FAILURE_THRESHOLD": "7",
            "CIRCUIT_BREAKER_RECOVERY_TIMEOUT": "45",
            "CIRCUIT_BREAKER_SUCCESS_THRESHOLD": "3",
            "CIRCUIT_BREAKER_CLEANUP_INTERVAL": "400",
            "CIRCUIT_BREAKER_STALE_TIMEOUT": "800",
        }

        with patch.dict(os.environ, env_vars):
            addon = CircuitBreakerAddon()
            assert addon.failure_threshold == 7
            assert addon.recovery_timeout == 45
            assert addon.success_threshold == 3
            assert addon.cleanup_interval == 400
            assert addon.stale_timeout == 800


class TestCompleteWorkflow:
    """Tests for complete circuit breaker workflows."""

    def test_complete_failure_recovery_cycle(self, addon, mock_flow, time_control):
        """Test complete cycle: CLOSED -> OPEN -> HALF_OPEN -> CLOSED."""
        # Mock http.Response.make to return a proper mock response
        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.content = b"Service Unavailable: Circuit breaker is open"

        with patch('addons.circuit_breaker.http') as mock_http:
            mock_http.Response.make.return_value = mock_response

            # Start in CLOSED
            with addon._lock:
                assert "example.com:443" not in addon._circuits

            # Trigger failures to open circuit
            for i in range(3):
                addon.request(mock_flow)
                mock_flow.response = MagicMock()
                mock_flow.response.status_code = 503
                addon.response(mock_flow)
                mock_flow.response = None

            # Verify OPEN
            with addon._lock:
                status = addon._circuits["example.com:443"]
                assert status.state == CircuitState.OPEN

            # Verify requests are blocked
            addon.request(mock_flow)
            assert mock_flow.response.status_code == 503
            mock_flow.response = None

            # Advance past recovery timeout
            time_control(1.1)

            # Request should transition to HALF_OPEN
            addon.request(mock_flow)
            with addon._lock:
                status = addon._circuits["example.com:443"]
                assert status.state == CircuitState.HALF_OPEN

            # Send successful requests
            for i in range(2):
                addon.request(mock_flow)
                mock_flow.response = MagicMock()
                mock_flow.response.status_code = 200
                addon.response(mock_flow)
                mock_flow.response = None

            # Verify CLOSED
            with addon._lock:
                status = addon._circuits["example.com:443"]
                assert status.state == CircuitState.CLOSED

    def test_multiple_open_close_cycles(self, addon, mock_flow, time_control):
        """Test circuit can open and close multiple times."""
        for cycle in range(3):
            # Open circuit
            for i in range(3):
                addon.request(mock_flow)
                mock_flow.response = MagicMock()
                mock_flow.response.status_code = 500
                addon.response(mock_flow)
                mock_flow.response = None

            # Verify OPEN
            with addon._lock:
                status = addon._circuits["example.com:443"]
                assert status.state == CircuitState.OPEN

            # Advance past recovery timeout and transition to HALF_OPEN
            time_control(1.1)
            addon.request(mock_flow)

            # Send successes to close
            for i in range(2):
                addon.request(mock_flow)
                mock_flow.response = MagicMock()
                mock_flow.response.status_code = 200
                addon.response(mock_flow)
                mock_flow.response = None

            # Verify CLOSED
            with addon._lock:
                status = addon._circuits["example.com:443"]
                assert status.state == CircuitState.CLOSED


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_no_response_flow_handled(self, addon, mock_flow):
        """Test response handler handles flows without response."""
        addon.request(mock_flow)
        mock_flow.response = None
        addon.response(mock_flow)  # Should not raise

    def test_upstream_key_format(self, addon, mock_flow):
        """Test upstream key is correctly formatted as host:port."""
        addon.request(mock_flow)
        with addon._lock:
            assert "example.com:443" in addon._circuits

    def test_concurrent_requests_to_same_upstream(self, addon):
        """Test thread safety with concurrent requests."""
        import threading

        flow = MagicMock()
        flow.request = MagicMock()
        flow.request.pretty_host = "concurrent.com"
        flow.request.port = 443
        flow.response = None
        flow.error = None

        def make_request():
            addon.request(flow)
            mock_response = MagicMock()
            mock_response.status_code = 200
            flow.response = mock_response
            addon.response(flow)
            flow.response = None

        threads = [threading.Thread(target=make_request) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have one circuit with no errors
        with addon._lock:
            assert "concurrent.com:443" in addon._circuits
            status = addon._circuits["concurrent.com:443"]
            assert status.state == CircuitState.CLOSED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
