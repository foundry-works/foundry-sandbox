"""Shared gateway middleware — rate limiting, circuit breaking, and metrics.

Ported from mitmproxy addons (rate_limiter.py, circuit_breaker.py, metrics.py)
into aiohttp middleware for use by all three API gateways (Anthropic, OpenAI,
GitHub).

These run in the asyncio event loop, so they use asyncio.Lock instead of
threading.Lock.

Middleware stack order (outermost first):
  1. IdentityMiddleware — resolves container_id from source IP
  2. MetricsMiddleware — records request count and latency
  3. CircuitBreakerMiddleware — fails fast when upstream is unhealthy
  4. RateLimiterMiddleware — per-container, per-upstream token bucket
"""

import asyncio
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

from aiohttp import web

# Try to import prometheus_client — metrics are optional
try:
    from prometheus_client import (
        Counter,
        Histogram,
        Gauge,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )

    _HAS_PROMETHEUS = True
except ImportError:
    _HAS_PROMETHEUS = False

import sys

_PROXY_DIR = "/opt/proxy"
if _PROXY_DIR not in sys.path:
    sys.path.insert(0, _PROXY_DIR)

from logging_config import get_logger  # noqa: E402
from registry import ContainerRegistry  # noqa: E402

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Request key: container_id is stashed on the request by IdentityMiddleware
# before other middleware runs, so rate limiting / metrics / circuit breaker
# can use the real container identity.
# ---------------------------------------------------------------------------

_CONTAINER_ID_KEY = web.AppKey("container_id", str)


def set_container_id(request: web.Request, container_id: str) -> None:
    """Store container_id on the request for middleware to read."""
    request[_CONTAINER_ID_KEY] = container_id


def get_container_id(request: web.Request) -> str:
    """Read container_id from the request (set by IdentityMiddleware)."""
    return request.get(_CONTAINER_ID_KEY, "unknown")


# ===================================================================
# IdentityMiddleware — resolves container identity before other middleware
# ===================================================================


def _identity_error(status: int, message: str) -> web.Response:
    """Return a JSON error response for identity failures."""
    import json
    body = json.dumps({"error": {"type": "gateway_error", "message": message}})
    return web.Response(
        status=status,
        body=body.encode(),
        content_type="application/json",
    )


class IdentityMiddleware:
    """Resolve container identity from source IP before other middleware.

    Must run as the first middleware so that rate limiting, circuit breaking,
    and metrics all have access to the real container_id.
    """

    def __init__(self, service_name: str):
        self.service_name = service_name

    @web.middleware
    async def middleware(
        self,
        request: web.Request,
        handler: web.RequestHandler,
    ) -> web.StreamResponse:
        # Skip identity resolution for health/metrics endpoints
        if request.path in ("/health", "/internal/metrics"):
            return await handler(request)

        registry: Optional[ContainerRegistry] = request.app.get("registry")
        if registry is None:
            return await handler(request)

        peername = request.remote
        if not peername:
            logger.warning(f"{self.service_name}: request with no remote address")
            return _identity_error(403, "Unable to determine request source")

        container = registry.get_by_ip(peername)
        if container is None:
            logger.warning(f"{self.service_name}: unknown source IP: {peername}")
            return _identity_error(403, "Unknown container — not registered")
        if container.is_expired:
            logger.warning(
                f"{self.service_name}: expired container: "
                f"{container.container_id} (IP {peername})"
            )
            return _identity_error(403, "Container registration expired")

        set_container_id(request, container.container_id)
        return await handler(request)


# ===================================================================
# Token Bucket (transport-independent, reused from rate_limiter.py)
# ===================================================================

# Configuration from environment
RATE_LIMIT_CAPACITY = float(os.environ.get("RATE_LIMIT_CAPACITY", "100"))
RATE_LIMIT_REFILL_RATE = float(os.environ.get("RATE_LIMIT_REFILL_RATE", "10"))
RATE_LIMIT_CLEANUP_INTERVAL = float(
    os.environ.get("RATE_LIMIT_CLEANUP_INTERVAL", "300")
)
BUCKET_EXPIRY_SECONDS = 3600  # 1 hour


@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""

    tokens: float
    last_refill: float
    capacity: float
    refill_rate: float
    last_access: float

    def consume(self, now: float) -> bool:
        """Attempt to consume one token. Returns True if allowed."""
        time_passed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + time_passed * self.refill_rate)
        self.last_refill = now
        self.last_access = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def get_retry_after(self) -> float:
        """Calculate seconds until next token is available."""
        tokens_needed = 1.0 - self.tokens
        if self.refill_rate > 0:
            return max(0, tokens_needed / self.refill_rate)
        return 60.0


# ===================================================================
# Circuit Breaker (transport-independent, reused from circuit_breaker.py)
# ===================================================================

CIRCUIT_FAILURE_THRESHOLD = int(
    os.environ.get("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5")
)
CIRCUIT_RECOVERY_TIMEOUT = int(
    os.environ.get("CIRCUIT_BREAKER_RECOVERY_TIMEOUT", "30")
)
CIRCUIT_SUCCESS_THRESHOLD = int(
    os.environ.get("CIRCUIT_BREAKER_SUCCESS_THRESHOLD", "2")
)
CIRCUIT_CLEANUP_INTERVAL = int(
    os.environ.get("CIRCUIT_BREAKER_CLEANUP_INTERVAL", "300")
)
CIRCUIT_STALE_TIMEOUT = int(
    os.environ.get("CIRCUIT_BREAKER_STALE_TIMEOUT", "600")
)


class CircuitState(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass
class CircuitStatus:
    state: CircuitState
    failure_count: int
    success_count: int
    last_failure_time: Optional[float]
    last_success_time: Optional[float]
    last_state_change_time: float
    last_access_time: float

    def __init__(self) -> None:
        now = time.time()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.last_success_time = None
        self.last_state_change_time = now
        self.last_access_time = now

    def update_access_time(self) -> None:
        self.last_access_time = time.time()


# ===================================================================
# Prometheus Metrics (reused definitions from metrics.py)
# ===================================================================

if _HAS_PROMETHEUS:
    GW_REQUESTS_TOTAL = Counter(
        "gateway_requests_total",
        "Total HTTP requests processed by API gateways",
        ["container_id", "upstream_host", "method", "status"],
    )

    GW_REQUEST_LATENCY = Histogram(
        "gateway_request_duration_seconds",
        "Gateway HTTP request latency in seconds",
        ["container_id", "upstream_host"],
        buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )

    GW_RATE_LIMIT_STATE = Gauge(
        "gateway_rate_limit_remaining",
        "Remaining rate limit tokens for a container/upstream",
        ["container_id", "upstream_host"],
    )

    GW_CIRCUIT_BREAKER_STATE = Gauge(
        "gateway_circuit_breaker_state",
        "Circuit breaker state (0=closed, 1=half-open, 2=open)",
        ["container_id", "upstream_host"],
    )


# ===================================================================
# RateLimiterMiddleware
# ===================================================================


class RateLimiterMiddleware:
    """Per-container, per-upstream rate limiting using token bucket algorithm."""

    def __init__(
        self,
        upstream_host: str,
        capacity: float = RATE_LIMIT_CAPACITY,
        refill_rate: float = RATE_LIMIT_REFILL_RATE,
        cleanup_interval: float = RATE_LIMIT_CLEANUP_INTERVAL,
    ):
        self.upstream_host = upstream_host
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.cleanup_interval = cleanup_interval
        self.buckets: Dict[str, TokenBucket] = {}
        self.lock = asyncio.Lock()
        self.last_cleanup = time.time()

    @web.middleware
    async def middleware(
        self,
        request: web.Request,
        handler: web.RequestHandler,
    ) -> web.StreamResponse:
        """aiohttp middleware that enforces rate limits."""
        # Skip rate limiting for health/metrics endpoints
        if request.path in ("/health", "/internal/metrics"):
            return await handler(request)

        container_id = get_container_id(request)
        now = time.time()

        async with self.lock:
            bucket = self.buckets.get(container_id)
            if bucket is None:
                bucket = TokenBucket(
                    tokens=self.capacity,
                    last_refill=now,
                    capacity=self.capacity,
                    refill_rate=self.refill_rate,
                    last_access=now,
                )
                self.buckets[container_id] = bucket

            allowed = bucket.consume(now)
            retry_after = 0.0 if allowed else bucket.get_retry_after()

            # Periodic cleanup of stale buckets
            if now - self.last_cleanup > self.cleanup_interval:
                self._cleanup_stale_buckets(now)

        if not allowed:
            retry_after_header = str(int(retry_after) + 1)
            logger.info(
                f"Rate limiter: denying request from container={container_id} "
                f"to upstream={self.upstream_host}, retry_after={retry_after_header}s"
            )
            return web.Response(
                status=429,
                text="Too Many Requests: Rate limit exceeded",
                content_type="text/plain",
                headers={"Retry-After": retry_after_header},
            )

        return await handler(request)

    def _cleanup_stale_buckets(self, now: float) -> None:
        """Remove buckets that haven't been accessed recently. Must hold lock."""
        stale_keys = [
            key
            for key, bucket in self.buckets.items()
            if now - bucket.last_access > BUCKET_EXPIRY_SECONDS
        ]
        for key in stale_keys:
            del self.buckets[key]
        if stale_keys:
            logger.info(
                f"Rate limiter: cleaned up {len(stale_keys)} stale buckets, "
                f"{len(self.buckets)} remaining"
            )
        self.last_cleanup = now


# ===================================================================
# CircuitBreakerMiddleware
# ===================================================================


class CircuitBreakerMiddleware:
    """Circuit breaker per upstream host. Fails fast when upstream is unhealthy."""

    def __init__(
        self,
        upstream_host: str,
        failure_threshold: int = CIRCUIT_FAILURE_THRESHOLD,
        recovery_timeout: int = CIRCUIT_RECOVERY_TIMEOUT,
        success_threshold: int = CIRCUIT_SUCCESS_THRESHOLD,
        cleanup_interval: int = CIRCUIT_CLEANUP_INTERVAL,
        stale_timeout: int = CIRCUIT_STALE_TIMEOUT,
    ):
        self.upstream_host = upstream_host
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold
        self.cleanup_interval = cleanup_interval
        self.stale_timeout = stale_timeout
        self.circuit = CircuitStatus()
        self.lock = asyncio.Lock()
        self.last_cleanup_time = time.time()

    @web.middleware
    async def middleware(
        self,
        request: web.Request,
        handler: web.RequestHandler,
    ) -> web.StreamResponse:
        """aiohttp middleware implementing circuit breaker pattern."""
        # Skip for health/metrics endpoints
        if request.path in ("/health", "/internal/metrics"):
            return await handler(request)

        async with self.lock:
            self.circuit.update_access_time()
            if not self._should_allow_request():
                logger.warning(
                    f"Circuit breaker: blocking request to {self.upstream_host} "
                    f"(circuit OPEN)"
                )
                return web.Response(
                    status=503,
                    text="Service Unavailable: Circuit breaker is open",
                    content_type="text/plain",
                )

        # Request allowed — forward to handler
        try:
            response = await handler(request)
        except Exception:
            async with self.lock:
                self._record_failure()
            raise

        # Record success/failure based on status code
        async with self.lock:
            if isinstance(response, web.StreamResponse) and hasattr(
                response, "status"
            ):
                if response.status >= 500:
                    self._record_failure()
                else:
                    self._record_success()
            else:
                self._record_success()

        return response

    def _should_allow_request(self) -> bool:
        """Check if request should be allowed. Must hold lock."""
        now = time.time()
        status = self.circuit

        if status.state == CircuitState.CLOSED:
            return True

        if status.state == CircuitState.OPEN:
            if status.last_failure_time is None:
                return False  # Fail-closed: OPEN state must block
            if now - status.last_failure_time >= self.recovery_timeout:
                self._transition_state(
                    CircuitState.HALF_OPEN,
                    f"recovery timeout ({self.recovery_timeout}s) elapsed",
                )
                return True
            return False

        if status.state == CircuitState.HALF_OPEN:
            return True

        return False  # Unknown state: fail-closed

    def _record_success(self) -> None:
        """Record a successful request. Must hold lock."""
        status = self.circuit
        status.last_success_time = time.time()
        status.failure_count = 0

        if status.state == CircuitState.HALF_OPEN:
            status.success_count += 1
            if status.success_count >= self.success_threshold:
                self._transition_state(
                    CircuitState.CLOSED,
                    f"success threshold ({self.success_threshold}) reached",
                )

    def _record_failure(self) -> None:
        """Record a failed request. Must hold lock."""
        status = self.circuit
        status.last_failure_time = time.time()
        status.success_count = 0

        if status.state == CircuitState.CLOSED:
            status.failure_count += 1
            if status.failure_count >= self.failure_threshold:
                self._transition_state(
                    CircuitState.OPEN,
                    f"failure threshold ({self.failure_threshold}) reached",
                )

        elif status.state == CircuitState.HALF_OPEN:
            self._transition_state(
                CircuitState.OPEN,
                "failure during recovery probe",
            )
            status.failure_count = 1

    def _transition_state(self, new_state: CircuitState, reason: str) -> None:
        """Transition circuit to new state. Must hold lock."""
        old_state = self.circuit.state
        if old_state == new_state:
            return

        self.circuit.state = new_state
        self.circuit.last_state_change_time = time.time()

        if new_state == CircuitState.OPEN:
            self.circuit.success_count = 0
        elif new_state in (CircuitState.HALF_OPEN, CircuitState.CLOSED):
            self.circuit.failure_count = 0
            self.circuit.success_count = 0

        logger.info(
            f"Circuit breaker [{self.upstream_host}]: "
            f"{old_state.value} -> {new_state.value} (reason: {reason})"
        )


# ===================================================================
# MetricsMiddleware
# ===================================================================


class MetricsMiddleware:
    """Prometheus metrics collection for gateway requests."""

    def __init__(self, upstream_host: str):
        self.upstream_host = upstream_host

    @web.middleware
    async def middleware(
        self,
        request: web.Request,
        handler: web.RequestHandler,
    ) -> web.StreamResponse:
        """aiohttp middleware that records request metrics."""
        # Serve /internal/metrics endpoint
        if request.method == "GET" and request.path == "/internal/metrics":
            return self._serve_metrics()

        start_time = time.time()
        container_id = get_container_id(request)

        try:
            response = await handler(request)
            status = str(response.status) if hasattr(response, "status") else "error"
        except Exception:
            status = "error"
            raise
        finally:
            latency = time.time() - start_time
            if _HAS_PROMETHEUS:
                try:
                    GW_REQUESTS_TOTAL.labels(
                        container_id=container_id,
                        upstream_host=self.upstream_host,
                        method=request.method,
                        status=status,
                    ).inc()
                except Exception as e:
                    logger.warning(f"Failed to increment request counter: {e}")

                try:
                    GW_REQUEST_LATENCY.labels(
                        container_id=container_id,
                        upstream_host=self.upstream_host,
                    ).observe(latency)
                except Exception as e:
                    logger.warning(f"Failed to record request latency: {e}")

        return response

    def _serve_metrics(self) -> web.Response:
        """Serve Prometheus metrics endpoint."""
        if not _HAS_PROMETHEUS:
            return web.Response(
                status=501,
                text="Metrics not available: prometheus_client not installed",
                content_type="text/plain",
            )
        try:
            metrics_output = generate_latest()
            return web.Response(
                status=200,
                body=metrics_output,
                content_type=CONTENT_TYPE_LATEST,
            )
        except Exception as e:
            logger.error(f"Failed to generate metrics: {e}")
            return web.Response(
                status=500,
                text="Internal Server Error: Failed to generate metrics",
                content_type="text/plain",
            )


# ===================================================================
# Factory function for creating middleware stack
# ===================================================================


def create_gateway_middlewares(
    upstream_host: str,
    service_name: str = "gateway",
) -> list:
    """Create the standard middleware stack for a gateway.

    Returns a list of aiohttp middleware callables in the correct order.
    Outermost middleware runs first — aiohttp applies them in list order,
    so the first middleware in the list wraps all subsequent ones.

    Middleware order: identity → metrics → circuit_breaker → rate_limiter → handler.

    Args:
        upstream_host: The upstream host this gateway forwards to
                       (e.g., "api.anthropic.com").
        service_name: Gateway service name for logging (e.g., "anthropic-gateway").

    Returns:
        List of middleware callables.
    """
    identity = IdentityMiddleware(service_name)
    metrics = MetricsMiddleware(upstream_host)
    circuit_breaker = CircuitBreakerMiddleware(upstream_host)
    rate_limiter = RateLimiterMiddleware(upstream_host)

    return [
        identity.middleware,
        metrics.middleware,
        circuit_breaker.middleware,
        rate_limiter.middleware,
    ]
