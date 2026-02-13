"""
Metrics mitmproxy Addon

Prometheus metrics collection addon that tracks HTTP request metrics,
DNS query metrics, and state of rate limiting/circuit breaker systems.

Metrics Collected:
- proxy_requests_total: Counter of HTTP requests by container, upstream, method, status
- proxy_request_duration_seconds: Histogram of HTTP request latency
- proxy_dns_queries_total: Counter of DNS queries by container, query type, result
- proxy_dns_duration_seconds: Histogram of DNS query latency
- proxy_rate_limit_remaining: Gauge of remaining rate limit tokens per container/bucket
- proxy_circuit_breaker_state: Gauge of circuit breaker state (0=closed, 1=half-open, 2=open)

Endpoint:
- GET /internal/metrics returns Prometheus format metrics

Thread Safety:
- All metric operations are thread-safe via prometheus_client
- DNS and circuit breaker state updates should be synchronized externally
"""

import os
import sys
import time
from typing import Optional, Dict

from mitmproxy import http

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from addons.container_identity import get_container_config  # noqa: E402
from logging_config import get_logger  # noqa: E402

# Try to import prometheus_client - provide helpful error if missing
try:
    from prometheus_client import (
        Counter,
        Histogram,
        Gauge,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )
except ImportError as e:
    raise ImportError(
        "prometheus_client not installed. "
        "Install with: pip install prometheus-client"
    ) from e

# Logger for this module
logger = get_logger(__name__)

# HTTP Request Metrics
REQUESTS_TOTAL = Counter(
    "proxy_requests_total",
    "Total HTTP requests processed by the proxy",
    ["container_id", "upstream_host", "method", "status"],
    registry=None,  # Use default registry
)

REQUEST_LATENCY = Histogram(
    "proxy_request_duration_seconds",
    "HTTP request latency in seconds",
    ["container_id", "upstream_host"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    registry=None,
)

# DNS Metrics
DNS_QUERIES_TOTAL = Counter(
    "proxy_dns_queries_total",
    "Total DNS queries processed by the proxy",
    ["container_id", "query_type", "result"],
    registry=None,
)

DNS_LATENCY = Histogram(
    "proxy_dns_duration_seconds",
    "DNS query latency in seconds",
    ["container_id", "query_type"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
    registry=None,
)

# Rate Limiter State Gauge
RATE_LIMIT_STATE = Gauge(
    "proxy_rate_limit_remaining",
    "Remaining rate limit tokens for a container/upstream",
    ["container_id", "upstream_host"],
    registry=None,
)

# Circuit Breaker State Gauge
# State values: 0=CLOSED, 1=HALF_OPEN, 2=OPEN
CIRCUIT_BREAKER_STATE = Gauge(
    "proxy_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=half-open, 2=open)",
    ["container_id", "upstream_host"],
    registry=None,
)


class MetricsAddon:
    """Mitmproxy addon for Prometheus metrics collection.

    This addon collects metrics on HTTP requests, DNS queries, and
    the state of rate limiting and circuit breaker systems. Metrics
    are exposed via a GET /internal/metrics endpoint in Prometheus
    text format.

    All metric labels are set conservatively to prevent cardinality
    explosion (e.g., containers, upstreams, HTTP methods/statuses).
    """

    def __init__(self):
        """Initialize the metrics addon.

        Stores request start times for latency calculation.
        """
        # Track request start times: id(flow) -> timestamp
        self._request_start_times: Dict[int, float] = {}

    def load(self, loader):
        """Called when addon is loaded."""
        logger.info("Metrics addon loaded - metrics available at /internal/metrics")

    def request(self, flow: http.HTTPFlow) -> None:
        """Process incoming request.

        Intercepts /internal/metrics requests and serves them directly.
        For all other requests, records the start time for latency measurement.

        Args:
            flow: The mitmproxy HTTP flow.
        """
        # Check if this is a metrics request
        if flow.request.method == "GET" and flow.request.path == "/internal/metrics":
            self._serve_metrics(flow)
            return

        # Record request start time for latency calculation
        self._request_start_times[id(flow)] = time.time()

    def response(self, flow: http.HTTPFlow) -> None:
        """Process response to record metrics.

        Records HTTP request metrics: request count, latency.
        Metrics are labeled by container ID, upstream host, method, and status.

        Args:
            flow: The mitmproxy HTTP flow.
        """
        # Skip if this was a metrics request (already handled)
        if flow.request.path == "/internal/metrics":
            return

        # Get container config
        container_config = get_container_config(flow)
        container_id = container_config.container_id if container_config else "unknown"

        # Extract request/response details
        upstream_host = flow.request.pretty_host
        method = flow.request.method
        status = str(flow.response.status_code) if flow.response else "error"

        # Increment request counter
        try:
            REQUESTS_TOTAL.labels(
                container_id=container_id,
                upstream_host=upstream_host,
                method=method,
                status=status,
            ).inc()
        except Exception as e:
            logger.warning(f"Failed to increment request counter: {e}")

        # Record latency
        start_time = self._request_start_times.pop(id(flow), None)
        if start_time is not None:
            latency = time.time() - start_time
            try:
                REQUEST_LATENCY.labels(
                    container_id=container_id,
                    upstream_host=upstream_host,
                ).observe(latency)
            except Exception as e:
                logger.warning(f"Failed to record request latency: {e}")
        else:
            logger.debug(
                f"No start time found for flow {id(flow)} - "
                f"latency not recorded"
            )

    def _serve_metrics(self, flow: http.HTTPFlow) -> None:
        """Serve Prometheus metrics.

        Generates and returns all collected metrics in Prometheus
        text exposition format.

        Args:
            flow: The mitmproxy HTTP flow.
        """
        try:
            metrics_output = generate_latest()
            flow.response = http.Response.make(
                200,
                metrics_output,
                {"Content-Type": CONTENT_TYPE_LATEST},
            )
            logger.debug("Served metrics endpoint")
        except Exception as e:
            logger.error(f"Failed to generate metrics: {e}")
            flow.response = http.Response.make(
                500,
                b"Internal Server Error: Failed to generate metrics",
                {"Content-Type": "text/plain"},
            )

    @staticmethod
    def record_dns_query(
        container_id: str,
        query_type: str,
        result: str,
        latency: Optional[float] = None,
    ) -> None:
        """Record a DNS query metric.

        This is a static method for use by DNS filter addon or other
        components that need to record DNS metrics.

        Args:
            container_id: Container making the DNS query.
            query_type: DNS query type (A, AAAA, CNAME, etc.).
            result: Query result (allowed/blocked).
            latency: Optional query latency in seconds.
        """
        try:
            DNS_QUERIES_TOTAL.labels(
                container_id=container_id,
                query_type=query_type,
                result=result,
            ).inc()
        except Exception as e:
            logger.warning(f"Failed to record DNS query counter: {e}")

        if latency is not None:
            try:
                DNS_LATENCY.labels(
                    container_id=container_id,
                    query_type=query_type,
                ).observe(latency)
            except Exception as e:
                logger.warning(f"Failed to record DNS latency: {e}")

    @staticmethod
    def update_rate_limit_state(
        container_id: str,
        upstream_host: str,
        remaining_tokens: float,
    ) -> None:
        """Update rate limit state gauge.

        This is a static method for use by the rate limiter addon to
        report current state of rate limit buckets.

        Args:
            container_id: Container ID.
            upstream_host: Upstream host.
            remaining_tokens: Current number of remaining tokens.
        """
        try:
            RATE_LIMIT_STATE.labels(
                container_id=container_id,
                upstream_host=upstream_host,
            ).set(remaining_tokens)
        except Exception as e:
            logger.warning(f"Failed to update rate limit state: {e}")

    @staticmethod
    def update_circuit_breaker_state(
        container_id: str,
        upstream_host: str,
        state: str,
    ) -> None:
        """Update circuit breaker state gauge.

        This is a static method for use by the circuit breaker addon to
        report current circuit state.

        Args:
            container_id: Container ID.
            upstream_host: Upstream host.
            state: Circuit state as string ("CLOSED", "HALF_OPEN", "OPEN").
        """
        # Map circuit state to numeric value
        state_map = {
            "CLOSED": 0,
            "HALF_OPEN": 1,
            "OPEN": 2,
        }

        state_value = state_map.get(state, -1)
        if state_value == -1:
            logger.warning(f"Unknown circuit breaker state: {state}")
            return

        try:
            CIRCUIT_BREAKER_STATE.labels(
                container_id=container_id,
                upstream_host=upstream_host,
            ).set(state_value)
        except Exception as e:
            logger.warning(f"Failed to update circuit breaker state: {e}")


# Export addon instance for mitmproxy
addons = [MetricsAddon()]
