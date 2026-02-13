"""
Circuit Breaker mitmproxy Addon

Implements the Circuit Breaker pattern for upstream services to prevent cascading
failures and allow failing services time to recover. Tracks circuit state per
upstream (host:port combination).

Circuit States:
- CLOSED: Normal operation, all requests pass through
- OPEN: Failing fast, returning 503 Service Unavailable without forwarding
- HALF_OPEN: Testing recovery, allowing limited probe requests

State Transitions:
- CLOSED -> OPEN: When consecutive failures >= failure_threshold
- OPEN -> HALF_OPEN: After recovery_timeout seconds have elapsed
- HALF_OPEN -> CLOSED: When consecutive successes >= success_threshold
- HALF_OPEN -> OPEN: On any failure (resets recovery timeout)

Configuration (via environment variables):
- CIRCUIT_BREAKER_FAILURE_THRESHOLD: Consecutive failures to open circuit (default: 5)
- CIRCUIT_BREAKER_RECOVERY_TIMEOUT: Seconds before attempting recovery (default: 30)
- CIRCUIT_BREAKER_SUCCESS_THRESHOLD: Successes in half-open to close circuit (default: 2)
- CIRCUIT_BREAKER_CLEANUP_INTERVAL: Seconds between stale state cleanup (default: 300)
- CIRCUIT_BREAKER_STALE_TIMEOUT: Seconds before circuit state is stale (default: 600)

Thread Safety:
- Uses threading.Lock for concurrent request handling
- All state mutations are protected by locks

Logging:
- Logs all circuit state transitions with upstream, old_state, new_state, reason
- Uses structured logging from logging_config
"""

import os
import sys
import time
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import Dict, Optional

from mitmproxy import http

# Add parent directory to path for logging import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logging_config import get_logger  # noqa: E402

# Get logger for this module
logger = get_logger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "CLOSED"       # Normal operation
    OPEN = "OPEN"           # Failing fast
    HALF_OPEN = "HALF_OPEN" # Testing recovery


@dataclass
class CircuitStatus:
    """Tracks the state of a circuit for a specific upstream."""
    state: CircuitState
    failure_count: int
    success_count: int
    last_failure_time: Optional[float]
    last_success_time: Optional[float]
    last_state_change_time: float
    last_access_time: float

    def __init__(self):
        """Initialize a new circuit in CLOSED state."""
        now = time.time()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.last_success_time = None
        self.last_state_change_time = now
        self.last_access_time = now

    def update_access_time(self) -> None:
        """Update the last access time for staleness tracking."""
        self.last_access_time = time.time()


class CircuitBreakerAddon:
    """Mitmproxy addon implementing the Circuit Breaker pattern.

    This addon prevents cascading failures by tracking per-upstream
    failure rates and opening circuits (failing fast) when upstreams
    become unhealthy.
    """

    def __init__(
        self,
        failure_threshold: Optional[int] = None,
        recovery_timeout: Optional[int] = None,
        success_threshold: Optional[int] = None,
        cleanup_interval: Optional[int] = None,
        stale_timeout: Optional[int] = None,
    ):
        """Initialize the circuit breaker addon.

        Args:
            failure_threshold: Consecutive failures to open circuit.
            recovery_timeout: Seconds before attempting recovery.
            success_threshold: Successes in half-open to close circuit.
            cleanup_interval: Seconds between stale state cleanup.
            stale_timeout: Seconds before circuit state is considered stale.
        """
        # Configuration from environment or defaults
        self.failure_threshold = failure_threshold or int(
            os.environ.get("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5")
        )
        self.recovery_timeout = recovery_timeout or int(
            os.environ.get("CIRCUIT_BREAKER_RECOVERY_TIMEOUT", "30")
        )
        self.success_threshold = success_threshold or int(
            os.environ.get("CIRCUIT_BREAKER_SUCCESS_THRESHOLD", "2")
        )
        self.cleanup_interval = cleanup_interval or int(
            os.environ.get("CIRCUIT_BREAKER_CLEANUP_INTERVAL", "300")
        )
        self.stale_timeout = stale_timeout or int(
            os.environ.get("CIRCUIT_BREAKER_STALE_TIMEOUT", "600")
        )

        # Per-upstream circuit state tracking
        self._circuits: Dict[str, CircuitStatus] = {}
        self._lock = Lock()
        self._last_cleanup_time = time.time()

        logger.info(
            "Circuit breaker initialized",
            extra={
                "failure_threshold": self.failure_threshold,
                "recovery_timeout": self.recovery_timeout,
                "success_threshold": self.success_threshold,
                "cleanup_interval": self.cleanup_interval,
                "stale_timeout": self.stale_timeout,
            },
        )

    def load(self, loader):
        """Called when addon is loaded."""
        logger.info(
            f"Circuit breaker addon loaded: "
            f"failure_threshold={self.failure_threshold}, "
            f"recovery_timeout={self.recovery_timeout}s, "
            f"success_threshold={self.success_threshold}"
        )

    def _get_upstream_key(self, flow: http.HTTPFlow) -> str:
        """Get the upstream identifier (host:port) for a flow.

        Args:
            flow: The mitmproxy HTTP flow.

        Returns:
            Upstream key string in format "host:port".
        """
        host = flow.request.pretty_host
        port = flow.request.port
        return f"{host}:{port}"

    def _get_circuit_status(self, upstream: str) -> CircuitStatus:
        """Get or create circuit status for an upstream.

        Must be called with self._lock held.

        Args:
            upstream: The upstream identifier.

        Returns:
            CircuitStatus for the upstream.
        """
        if upstream not in self._circuits:
            self._circuits[upstream] = CircuitStatus()
            logger.debug(f"Created new circuit for upstream: {upstream}")

        status = self._circuits[upstream]
        status.update_access_time()
        return status

    def _transition_state(
        self,
        upstream: str,
        status: CircuitStatus,
        new_state: CircuitState,
        reason: str,
    ) -> None:
        """Transition circuit to a new state.

        Must be called with self._lock held.

        Args:
            upstream: The upstream identifier.
            status: The circuit status to update.
            new_state: The new circuit state.
            reason: Human-readable reason for transition.
        """
        old_state = status.state
        if old_state == new_state:
            return

        status.state = new_state
        status.last_state_change_time = time.time()

        # Reset counters on state change
        if new_state == CircuitState.OPEN:
            status.success_count = 0
        elif new_state == CircuitState.HALF_OPEN:
            status.failure_count = 0
            status.success_count = 0
        elif new_state == CircuitState.CLOSED:
            status.failure_count = 0
            status.success_count = 0

        logger.info(
            f"Circuit state transition: {old_state.value} -> {new_state.value}",
            extra={
                "upstream": upstream,
                "old_state": old_state.value,
                "new_state": new_state.value,
                "reason": reason,
                "failure_count": status.failure_count,
                "success_count": status.success_count,
            },
        )

        logger.info(
            f"Circuit breaker [{upstream}]: {old_state.value} -> {new_state.value} "
            f"(reason: {reason})"
        )

    def _should_allow_request(self, upstream: str, status: CircuitStatus) -> bool:
        """Check if a request should be allowed through the circuit.

        Must be called with self._lock held.

        Args:
            upstream: The upstream identifier.
            status: The circuit status.

        Returns:
            True if request should be allowed, False otherwise.
        """
        now = time.time()

        if status.state == CircuitState.CLOSED:
            # Normal operation - allow all requests
            return True

        elif status.state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if status.last_failure_time is None:
                # Should not happen, but be defensive
                logger.warning(
                    f"Circuit in OPEN state but no last_failure_time: {upstream}"
                )
                return True

            time_since_failure = now - status.last_failure_time
            if time_since_failure >= self.recovery_timeout:
                # Transition to HALF_OPEN to test recovery
                self._transition_state(
                    upstream,
                    status,
                    CircuitState.HALF_OPEN,
                    f"recovery timeout ({self.recovery_timeout}s) elapsed",
                )
                return True
            else:
                # Still in failure window - fail fast
                return False

        elif status.state == CircuitState.HALF_OPEN:
            # In half-open state, allow limited probe requests
            # We allow all requests but track them carefully
            # Alternative: could implement rate limiting here
            return True

        # Should never reach here
        logger.error(f"Unknown circuit state: {status.state}")
        return True

    def _record_success(self, upstream: str, status: CircuitStatus) -> None:
        """Record a successful request.

        Must be called with self._lock held.

        Args:
            upstream: The upstream identifier.
            status: The circuit status.
        """
        now = time.time()
        status.last_success_time = now
        status.failure_count = 0  # Reset failure count on success

        if status.state == CircuitState.HALF_OPEN:
            # In half-open, count successes towards closing circuit
            status.success_count += 1
            logger.debug(
                f"Circuit success in HALF_OPEN state: {upstream} "
                f"({status.success_count}/{self.success_threshold})"
            )

            if status.success_count >= self.success_threshold:
                # Enough successes - close the circuit
                self._transition_state(
                    upstream,
                    status,
                    CircuitState.CLOSED,
                    f"success threshold ({self.success_threshold}) reached",
                )

    def _record_failure(self, upstream: str, status: CircuitStatus) -> None:
        """Record a failed request.

        Must be called with self._lock held.

        Args:
            upstream: The upstream identifier.
            status: The circuit status.
        """
        now = time.time()
        status.last_failure_time = now
        status.success_count = 0  # Reset success count on failure

        if status.state == CircuitState.CLOSED:
            # In closed state, count failures towards opening circuit
            status.failure_count += 1
            logger.debug(
                f"Circuit failure in CLOSED state: {upstream} "
                f"({status.failure_count}/{self.failure_threshold})"
            )

            if status.failure_count >= self.failure_threshold:
                # Enough failures - open the circuit
                self._transition_state(
                    upstream,
                    status,
                    CircuitState.OPEN,
                    f"failure threshold ({self.failure_threshold}) reached",
                )

        elif status.state == CircuitState.HALF_OPEN:
            # In half-open, any failure reopens the circuit
            self._transition_state(
                upstream,
                status,
                CircuitState.OPEN,
                "failure during recovery probe",
            )
            # Reset failure count to 1 (this failure)
            status.failure_count = 1

    def _cleanup_stale_circuits(self) -> None:
        """Remove stale circuit states that haven't been accessed recently.

        This prevents unbounded memory growth for ephemeral upstreams.
        Must be called with self._lock held.
        """
        now = time.time()
        stale_upstreams = []

        for upstream, status in self._circuits.items():
            time_since_access = now - status.last_access_time
            if time_since_access >= self.stale_timeout:
                stale_upstreams.append(upstream)

        for upstream in stale_upstreams:
            logger.info(
                f"Cleaning up stale circuit state: {upstream}",
                extra={
                    "upstream": upstream,
                    "state": self._circuits[upstream].state.value,
                    "idle_seconds": now - self._circuits[upstream].last_access_time,
                },
            )
            del self._circuits[upstream]

        if stale_upstreams:
            logger.info(
                f"Circuit breaker: cleaned up {len(stale_upstreams)} stale circuits"
            )

    def _maybe_cleanup(self) -> None:
        """Periodically cleanup stale circuits.

        Must be called with self._lock held.
        """
        now = time.time()
        time_since_cleanup = now - self._last_cleanup_time

        if time_since_cleanup >= self.cleanup_interval:
            self._cleanup_stale_circuits()
            self._last_cleanup_time = now

    def request(self, flow: http.HTTPFlow) -> None:
        """Process incoming request through circuit breaker.

        Args:
            flow: The mitmproxy HTTP flow.
        """
        upstream = self._get_upstream_key(flow)

        with self._lock:
            # Periodic cleanup
            self._maybe_cleanup()

            # Get or create circuit status
            status = self._get_circuit_status(upstream)

            # Check if request should be allowed
            if not self._should_allow_request(upstream, status):
                # Circuit is open - fail fast
                logger.info(
                    f"Circuit breaker blocking request (circuit OPEN): {upstream}",
                    extra={
                        "upstream": upstream,
                        "state": status.state.value,
                        "failure_count": status.failure_count,
                    },
                )

                logger.warning(
                    f"Circuit breaker: blocking request to {upstream} (circuit OPEN)"
                )

                # Return 503 Service Unavailable
                flow.response = http.Response.make(
                    503,
                    b"Service Unavailable: Circuit breaker is open",
                    {"Content-Type": "text/plain"},
                )

    def response(self, flow: http.HTTPFlow) -> None:
        """Process response to track success/failure.

        Args:
            flow: The mitmproxy HTTP flow.
        """
        # Skip if we already created a response (circuit breaker block)
        if flow.response is None:
            return

        upstream = self._get_upstream_key(flow)

        # Determine if response indicates success or failure
        # 5xx errors and connection failures are considered failures
        is_success = True

        if flow.response.status_code >= 500:
            is_success = False

        # Check for connection errors (no response from upstream)
        if hasattr(flow, 'error') and flow.error is not None:
            is_success = False

        with self._lock:
            status = self._get_circuit_status(upstream)

            if is_success:
                self._record_success(upstream, status)
                logger.debug(
                    f"Circuit breaker: success for {upstream}",
                    extra={
                        "upstream": upstream,
                        "state": status.state.value,
                        "status_code": flow.response.status_code,
                    },
                )
            else:
                self._record_failure(upstream, status)
                logger.warning(
                    f"Circuit breaker: failure for {upstream}",
                    extra={
                        "upstream": upstream,
                        "state": status.state.value,
                        "status_code": flow.response.status_code,
                        "failure_count": status.failure_count,
                    },
                )

                logger.warning(
                    f"Circuit breaker: failure for {upstream} "
                    f"(status={flow.response.status_code}, "
                    f"failures={status.failure_count}/{self.failure_threshold})"
                )

    def error(self, flow: http.HTTPFlow) -> None:
        """Handle connection/protocol errors.

        These are treated as failures for circuit breaker purposes.

        Args:
            flow: The mitmproxy HTTP flow.
        """
        upstream = self._get_upstream_key(flow)

        with self._lock:
            status = self._get_circuit_status(upstream)
            self._record_failure(upstream, status)

            logger.error(
                f"Circuit breaker: connection error for {upstream}",
                extra={
                    "upstream": upstream,
                    "state": status.state.value,
                    "error": str(flow.error) if flow.error else "unknown",
                    "failure_count": status.failure_count,
                },
            )

            logger.error(
                f"Circuit breaker: connection error for {upstream} "
                f"(failures={status.failure_count}/{self.failure_threshold})"
            )


# Export addon instance for mitmproxy
addons = [CircuitBreakerAddon()]
