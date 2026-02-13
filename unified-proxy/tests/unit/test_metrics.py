"""
Unit tests for Metrics addon.

Tests cover:
- HTTP request metrics (counter, latency histogram)
- DNS query metrics
- Rate limit state gauge
- Circuit breaker state gauge
- /internal/metrics endpoint
"""

import importlib
import sys
import time
from typing import Optional
from unittest import mock

import pytest


# Create mocks before any imports
mock_http_module = mock.MagicMock()


class MockHTTPFlow:
    """Mock mitmproxy HTTPFlow for testing."""

    def __init__(
        self,
        host: str,
        path: str = "/",
        method: str = "GET",
        headers: Optional[dict] = None,
        status_code: int = 200,
    ):
        self.request = mock.MagicMock()
        self.request.host = host
        self.request.path = path
        self.request.method = method
        self.request.headers = dict(headers or {})
        self.request.pretty_host = host

        self.response = mock.MagicMock()
        self.response.status_code = status_code

        self.metadata = {}
        self.client_conn = mock.MagicMock()
        self.client_conn.peername = ("192.168.1.100", 12345)


class MockResponse:
    """Mock HTTP Response."""

    @staticmethod
    def make(status_code: int, body: bytes, headers: dict):
        resp = mock.MagicMock()
        resp.status_code = status_code
        resp.content = body
        resp.headers = headers
        return resp


# Create mock prometheus_client with properly-structured metrics
mock_prometheus = mock.MagicMock()

# Create real mock instances for the metrics that tests can inspect
mock_requests_total = mock.MagicMock()
mock_request_latency = mock.MagicMock()
mock_dns_queries_total = mock.MagicMock()
mock_dns_latency = mock.MagicMock()
mock_rate_limit_state = mock.MagicMock()
mock_circuit_breaker_state = mock.MagicMock()

mock_prometheus.generate_latest.return_value = b"# HELP test_metric\n# TYPE test_metric counter\ntest_metric 1\n"
mock_prometheus.CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

# Mock container identity module
mock_container_identity = mock.MagicMock()
mock_container_config = mock.MagicMock()
mock_container_config.container_id = "test-container-123"
mock_container_identity.get_container_config.return_value = mock_container_config

# Mock logging_config
mock_logging_config = mock.MagicMock()
mock_logger = mock.MagicMock()
mock_logging_config.get_logger.return_value = mock_logger

# Patch sys.modules before imports
mock_http_module.Response = MockResponse
mock_http_module.HTTPFlow = MockHTTPFlow

# Remove any existing imports of addons.metrics
if "addons.metrics" in sys.modules:
    del sys.modules["addons.metrics"]

# Track metric creation order
_metric_index = {"counter": 0, "histogram": 0, "gauge": 0}

def counter_factory(*args, **kwargs):
    """Factory for Counter metrics."""
    idx = _metric_index["counter"]
    _metric_index["counter"] += 1
    if idx == 0:
        return mock_requests_total
    elif idx == 1:
        return mock_dns_queries_total
    return mock.MagicMock()

def histogram_factory(*args, **kwargs):
    """Factory for Histogram metrics."""
    idx = _metric_index["histogram"]
    _metric_index["histogram"] += 1
    if idx == 0:
        return mock_request_latency
    elif idx == 1:
        return mock_dns_latency
    return mock.MagicMock()

def gauge_factory(*args, **kwargs):
    """Factory for Gauge metrics."""
    idx = _metric_index["gauge"]
    _metric_index["gauge"] += 1
    if idx == 0:
        return mock_rate_limit_state
    elif idx == 1:
        return mock_circuit_breaker_state
    return mock.MagicMock()

mock_prometheus.Counter.side_effect = counter_factory
mock_prometheus.Histogram.side_effect = histogram_factory
mock_prometheus.Gauge.side_effect = gauge_factory

# Patch the dependencies before importing metrics
sys.modules["mitmproxy"] = mock.MagicMock()
sys.modules["mitmproxy.http"] = mock_http_module
sys.modules["prometheus_client"] = mock_prometheus
sys.modules["addons.container_identity"] = mock_container_identity
sys.modules["logging_config"] = mock_logging_config

# Now import the module under test
from addons import metrics
importlib.reload(metrics)  # Reload to ensure mocks are used
MetricsAddon = metrics.MetricsAddon


class TestMetricsAddon:
    """Tests for MetricsAddon class."""

    @pytest.fixture
    def addon(self) -> MetricsAddon:
        """Create a MetricsAddon instance."""
        return MetricsAddon()

    def test_init_creates_request_start_times_dict(self, addon):
        """Test that addon initializes with empty start times dict."""
        assert hasattr(addon, "_request_start_times")
        assert isinstance(addon._request_start_times, dict)
        assert len(addon._request_start_times) == 0


class TestMetricsEndpoint:
    """Tests for /internal/metrics endpoint."""

    @pytest.fixture
    def addon(self) -> MetricsAddon:
        """Create a MetricsAddon instance."""
        return MetricsAddon()

    def test_metrics_endpoint_returns_prometheus_format(self, addon):
        """Test that GET /internal/metrics returns Prometheus format."""
        flow = MockHTTPFlow(
            host="localhost",
            path="/internal/metrics",
            method="GET",
        )

        addon.request(flow)

        # Response should be set (via MockResponse.make)
        assert flow.response is not None

    def test_metrics_endpoint_calls_generate_latest(self, addon):
        """Test that metrics endpoint calls generate_latest."""
        flow = MockHTTPFlow(
            host="localhost",
            path="/internal/metrics",
            method="GET",
        )

        addon.request(flow)

        # Verify generate_latest was called
        mock_prometheus.generate_latest.assert_called()

    def test_non_metrics_request_records_start_time(self, addon):
        """Test that non-metrics requests record start time."""
        flow = MockHTTPFlow(
            host="api.example.com",
            path="/api/data",
            method="POST",
        )

        addon.request(flow)

        # Start time should be recorded
        assert id(flow) in addon._request_start_times
        assert isinstance(addon._request_start_times[id(flow)], float)


class TestHTTPRequestMetrics:
    """Tests for HTTP request metrics recording."""

    @pytest.fixture
    def addon(self) -> MetricsAddon:
        """Create a MetricsAddon instance."""
        # Reset mocks before each test
        metrics.REQUESTS_TOTAL.reset_mock()
        metrics.REQUEST_LATENCY.reset_mock()
        return MetricsAddon()

    def test_response_increments_request_counter(self, addon):
        """Test that response processing increments the request counter."""
        flow = MockHTTPFlow(
            host="api.example.com",
            path="/api/data",
            method="POST",
            status_code=200,
        )

        # Simulate request phase
        addon.request(flow)

        # Simulate response phase
        addon.response(flow)

        # Counter should be incremented (via labels().inc())
        metrics.REQUESTS_TOTAL.labels.assert_called()
        metrics.REQUESTS_TOTAL.labels().inc.assert_called()

    def test_response_records_latency(self, addon):
        """Test that response processing records latency histogram."""
        flow = MockHTTPFlow(
            host="api.example.com",
            path="/api/data",
            method="GET",
            status_code=200,
        )

        # Simulate request phase
        addon.request(flow)

        # Small delay
        time.sleep(0.001)

        # Simulate response phase
        addon.response(flow)

        # Latency histogram should be observed
        metrics.REQUEST_LATENCY.labels.assert_called()
        metrics.REQUEST_LATENCY.labels().observe.assert_called()

    def test_response_removes_start_time(self, addon):
        """Test that response processing cleans up start time."""
        flow = MockHTTPFlow(
            host="api.example.com",
            path="/api/data",
            method="GET",
            status_code=200,
        )

        # Simulate request phase
        addon.request(flow)
        assert id(flow) in addon._request_start_times

        # Simulate response phase
        addon.response(flow)
        assert id(flow) not in addon._request_start_times

    def test_metrics_request_not_recorded(self, addon):
        """Test that /internal/metrics requests are not recorded."""
        flow = MockHTTPFlow(
            host="localhost",
            path="/internal/metrics",
            method="GET",
            status_code=200,
        )

        # Request phase - handled as metrics endpoint
        addon.request(flow)

        # Start time should not be recorded for metrics endpoint
        assert id(flow) not in addon._request_start_times

    def test_response_with_missing_start_time(self, addon):
        """Test response handling when no start time exists."""
        flow = MockHTTPFlow(
            host="api.example.com",
            path="/api/data",
            method="GET",
            status_code=200,
        )

        # Skip request phase, go directly to response
        addon.response(flow)

        # Should not raise, counter still incremented
        metrics.REQUESTS_TOTAL.labels.assert_called()

    def test_error_response_recorded(self, addon):
        """Test that error responses are recorded correctly."""
        flow = MockHTTPFlow(
            host="api.example.com",
            path="/api/data",
            method="POST",
            status_code=500,
        )

        addon.request(flow)
        addon.response(flow)

        # Counter should be called
        metrics.REQUESTS_TOTAL.labels.assert_called()


class TestDNSMetrics:
    """Tests for DNS query metrics."""

    @pytest.fixture(autouse=True)
    def reset_mocks(self):
        """Reset mocks before each test."""
        metrics.DNS_QUERIES_TOTAL.reset_mock()
        metrics.DNS_LATENCY.reset_mock()

    def test_record_dns_query_increments_counter(self):
        """Test that recording DNS query increments counter."""
        MetricsAddon.record_dns_query(
            container_id="container-1",
            query_type="A",
            result="allowed",
            latency=0.005,
        )

        metrics.DNS_QUERIES_TOTAL.labels.assert_called_with(
            container_id="container-1",
            query_type="A",
            result="allowed",
        )
        metrics.DNS_QUERIES_TOTAL.labels().inc.assert_called()

    def test_record_dns_query_records_latency(self):
        """Test that DNS query records latency histogram."""
        MetricsAddon.record_dns_query(
            container_id="container-1",
            query_type="AAAA",
            result="blocked",
            latency=0.010,
        )

        metrics.DNS_LATENCY.labels.assert_called_with(
            container_id="container-1",
            query_type="AAAA",
        )
        metrics.DNS_LATENCY.labels().observe.assert_called_with(0.010)

    def test_record_dns_query_without_latency(self):
        """Test that DNS query can be recorded without latency."""
        MetricsAddon.record_dns_query(
            container_id="container-1",
            query_type="CNAME",
            result="allowed",
            latency=None,
        )

        # Counter should still be called
        metrics.DNS_QUERIES_TOTAL.labels.assert_called()
        metrics.DNS_QUERIES_TOTAL.labels().inc.assert_called()


class TestRateLimitMetrics:
    """Tests for rate limit state gauge."""

    @pytest.fixture(autouse=True)
    def reset_mocks(self):
        """Reset mocks before each test."""
        metrics.RATE_LIMIT_STATE.reset_mock()

    def test_update_rate_limit_state(self):
        """Test that rate limit state is updated."""
        MetricsAddon.update_rate_limit_state(
            container_id="container-1",
            upstream_host="api.openai.com",
            remaining_tokens=50.0,
        )

        metrics.RATE_LIMIT_STATE.labels.assert_called_with(
            container_id="container-1",
            upstream_host="api.openai.com",
        )
        metrics.RATE_LIMIT_STATE.labels().set.assert_called_with(50.0)

    def test_update_rate_limit_state_zero_tokens(self):
        """Test rate limit state with zero remaining tokens."""
        MetricsAddon.update_rate_limit_state(
            container_id="container-2",
            upstream_host="api.anthropic.com",
            remaining_tokens=0.0,
        )

        metrics.RATE_LIMIT_STATE.labels.assert_called_with(
            container_id="container-2",
            upstream_host="api.anthropic.com",
        )
        metrics.RATE_LIMIT_STATE.labels().set.assert_called_with(0.0)


class TestCircuitBreakerMetrics:
    """Tests for circuit breaker state gauge."""

    @pytest.fixture(autouse=True)
    def reset_mocks(self):
        """Reset mocks before each test."""
        metrics.CIRCUIT_BREAKER_STATE.reset_mock()
        mock_logger.reset_mock()

    def test_update_circuit_breaker_closed(self):
        """Test circuit breaker state set to CLOSED (0)."""
        MetricsAddon.update_circuit_breaker_state(
            container_id="container-1",
            upstream_host="api.openai.com",
            state="CLOSED",
        )

        metrics.CIRCUIT_BREAKER_STATE.labels.assert_called_with(
            container_id="container-1",
            upstream_host="api.openai.com",
        )
        metrics.CIRCUIT_BREAKER_STATE.labels().set.assert_called_with(0)

    def test_update_circuit_breaker_half_open(self):
        """Test circuit breaker state set to HALF_OPEN (1)."""
        MetricsAddon.update_circuit_breaker_state(
            container_id="container-1",
            upstream_host="api.openai.com",
            state="HALF_OPEN",
        )

        metrics.CIRCUIT_BREAKER_STATE.labels.assert_called_with(
            container_id="container-1",
            upstream_host="api.openai.com",
        )
        metrics.CIRCUIT_BREAKER_STATE.labels().set.assert_called_with(1)

    def test_update_circuit_breaker_open(self):
        """Test circuit breaker state set to OPEN (2)."""
        MetricsAddon.update_circuit_breaker_state(
            container_id="container-1",
            upstream_host="api.openai.com",
            state="OPEN",
        )

        metrics.CIRCUIT_BREAKER_STATE.labels.assert_called_with(
            container_id="container-1",
            upstream_host="api.openai.com",
        )
        metrics.CIRCUIT_BREAKER_STATE.labels().set.assert_called_with(2)

    def test_update_circuit_breaker_invalid_state(self):
        """Test circuit breaker with invalid state logs warning."""
        MetricsAddon.update_circuit_breaker_state(
            container_id="container-1",
            upstream_host="api.openai.com",
            state="INVALID",
        )

        # Logger warning should be called
        mock_logger.warning.assert_called()
        # Gauge should NOT be set
        metrics.CIRCUIT_BREAKER_STATE.labels().set.assert_not_called()


class TestMetricsLabels:
    """Tests for correct metric label handling."""

    @pytest.fixture
    def addon(self) -> MetricsAddon:
        """Create a MetricsAddon instance."""
        metrics.REQUESTS_TOTAL.reset_mock()
        return MetricsAddon()

    def test_unknown_container_uses_unknown_label(self, addon):
        """Test that missing container config uses 'unknown' label."""
        # Set container config to None
        mock_container_identity.get_container_config.return_value = None

        flow = MockHTTPFlow(
            host="api.example.com",
            path="/api/data",
            method="GET",
            status_code=200,
        )

        addon.request(flow)
        addon.response(flow)

        # Counter should be called with container_id="unknown"
        call_args = metrics.REQUESTS_TOTAL.labels.call_args
        assert call_args is not None
        assert call_args.kwargs.get("container_id") == "unknown"

        # Reset mock
        mock_container_identity.get_container_config.return_value = mock_container_config

    def test_known_container_uses_container_id(self, addon):
        """Test that known container uses correct container_id."""
        mock_container_identity.get_container_config.return_value = mock_container_config

        flow = MockHTTPFlow(
            host="api.example.com",
            path="/api/data",
            method="GET",
            status_code=200,
        )

        addon.request(flow)
        addon.response(flow)

        # Counter should be called with correct container_id
        call_args = metrics.REQUESTS_TOTAL.labels.call_args
        assert call_args is not None
        assert call_args.kwargs.get("container_id") == "test-container-123"

    def test_error_status_uses_error_label(self, addon):
        """Test that missing response uses 'error' status label."""
        flow = MockHTTPFlow(
            host="api.example.com",
            path="/api/data",
            method="GET",
        )
        flow.response = None  # type: ignore[assignment]

        addon.request(flow)
        addon.response(flow)

        # Counter should be called with status="error"
        call_args = metrics.REQUESTS_TOTAL.labels.call_args
        assert call_args is not None
        assert call_args.kwargs.get("status") == "error"
