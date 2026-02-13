"""
Rate Limiting mitmproxy Addon

Per-container, per-upstream rate limiting using token bucket algorithm.
Prevents individual containers from overwhelming specific upstream services.

Algorithm:
- Each (container_id, upstream_host) pair has its own token bucket
- Buckets have configurable capacity and refill rate
- Each request consumes 1 token
- Requests without sufficient tokens are denied with 429 Too Many Requests

Configuration (via environment variables):
- RATE_LIMIT_CAPACITY: Maximum tokens per bucket (default: 100)
- RATE_LIMIT_REFILL_RATE: Tokens added per second (default: 10)
- RATE_LIMIT_CLEANUP_INTERVAL: Seconds between cleanup of stale buckets (default: 300)

Error Responses:
- 429 Too Many Requests: Rate limit exceeded (includes Retry-After header)
"""

import os
import threading
import time
from dataclasses import dataclass
from typing import Dict, Tuple

from mitmproxy import http

# Add parent directory to path for imports
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from addons.container_identity import get_container_config  # noqa: E402
from logging_config import get_logger  # noqa: E402

# Configuration from environment
RATE_LIMIT_CAPACITY = float(os.environ.get("RATE_LIMIT_CAPACITY", "100"))
RATE_LIMIT_REFILL_RATE = float(os.environ.get("RATE_LIMIT_REFILL_RATE", "10"))
RATE_LIMIT_CLEANUP_INTERVAL = float(os.environ.get("RATE_LIMIT_CLEANUP_INTERVAL", "300"))

# Bucket expiry threshold (remove buckets unused for this long)
BUCKET_EXPIRY_SECONDS = 3600  # 1 hour

# Logger for this module
logger = get_logger(__name__)


@dataclass
class TokenBucket:
    """Token bucket for rate limiting.

    Attributes:
        tokens: Current number of tokens (float for precision)
        last_refill: Timestamp of last refill operation
        capacity: Maximum number of tokens
        refill_rate: Tokens added per second
        last_access: Timestamp of last access (for cleanup)
    """
    tokens: float
    last_refill: float
    capacity: float
    refill_rate: float
    last_access: float

    def consume(self, now: float) -> bool:
        """Attempt to consume one token.

        Args:
            now: Current timestamp

        Returns:
            True if token was consumed, False if rate limited
        """
        # Refill tokens based on time elapsed
        time_passed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + time_passed * self.refill_rate)
        self.last_refill = now
        self.last_access = now

        # Try to consume one token
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True

        return False

    def get_retry_after(self, now: float) -> float:
        """Calculate seconds until next token is available.

        Args:
            now: Current timestamp

        Returns:
            Estimated seconds to wait for a token
        """
        # How many tokens needed to reach 1.0?
        tokens_needed = 1.0 - self.tokens

        # Time to accumulate those tokens
        if self.refill_rate > 0:
            return max(0, tokens_needed / self.refill_rate)

        return 60.0  # Default fallback


class RateLimiterAddon:
    """Mitmproxy addon for per-container, per-upstream rate limiting.

    This addon enforces rate limits on a per-container, per-upstream basis
    using the token bucket algorithm. Each (container_id, upstream_host)
    pair gets its own bucket with configurable capacity and refill rate.
    """

    def __init__(
        self,
        capacity: float = RATE_LIMIT_CAPACITY,
        refill_rate: float = RATE_LIMIT_REFILL_RATE,
        cleanup_interval: float = RATE_LIMIT_CLEANUP_INTERVAL,
    ):
        """Initialize the rate limiter addon.

        Args:
            capacity: Maximum tokens per bucket
            refill_rate: Tokens added per second
            cleanup_interval: Seconds between cleanup operations
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.cleanup_interval = cleanup_interval

        # Buckets: (container_id, upstream_host) -> TokenBucket
        self.buckets: Dict[Tuple[str, str], TokenBucket] = {}

        # Thread lock for bucket access
        self.lock = threading.Lock()

        # Cleanup tracking
        self.last_cleanup = time.time()

    def load(self, loader):
        """Called when addon is loaded."""
        logger.info(
            f"Rate limiter addon loaded: capacity={self.capacity}, "
            f"refill_rate={self.refill_rate}/s, "
            f"cleanup_interval={self.cleanup_interval}s"
        )

    def request(self, flow: http.HTTPFlow) -> None:
        """Process incoming request to enforce rate limits.

        Args:
            flow: The mitmproxy HTTP flow
        """
        # Get container config from flow metadata
        container_config = get_container_config(flow)

        if container_config is None:
            # Container identity not established - let container_identity addon handle
            logger.debug("Rate limiter: No container config, skipping")
            return

        container_id = container_config.container_id
        upstream_host = flow.request.pretty_host

        # Check rate limit
        now = time.time()
        allowed, retry_after = self._check_rate_limit(container_id, upstream_host, now)

        if not allowed:
            # Rate limit exceeded - deny request
            self._deny_request(flow, container_id, upstream_host, retry_after)
            return

        # Request allowed
        logger.debug(
            f"Rate limiter: Allowed request from container={container_id} "
            f"to upstream={upstream_host}"
        )

        # Periodic cleanup of stale buckets
        if now - self.last_cleanup > self.cleanup_interval:
            self._cleanup_stale_buckets(now)

    def _check_rate_limit(
        self,
        container_id: str,
        upstream_host: str,
        now: float,
    ) -> Tuple[bool, float]:
        """Check if request should be rate limited.

        Args:
            container_id: Container identifier
            upstream_host: Upstream host identifier
            now: Current timestamp

        Returns:
            Tuple of (allowed: bool, retry_after: float)
        """
        bucket_key = (container_id, upstream_host)

        with self.lock:
            # Get or create bucket
            if bucket_key not in self.buckets:
                self.buckets[bucket_key] = TokenBucket(
                    tokens=self.capacity,
                    last_refill=now,
                    capacity=self.capacity,
                    refill_rate=self.refill_rate,
                    last_access=now,
                )
                logger.debug(
                    f"Rate limiter: Created new bucket for "
                    f"container={container_id}, upstream={upstream_host}"
                )

            bucket = self.buckets[bucket_key]

            # Try to consume a token
            if bucket.consume(now):
                # Request allowed
                logger.debug(
                    f"Rate limiter: Token consumed, "
                    f"container={container_id}, upstream={upstream_host}, "
                    f"tokens_remaining={bucket.tokens:.2f}"
                )
                return (True, 0.0)
            else:
                # Rate limited
                retry_after = bucket.get_retry_after(now)
                logger.info(
                    f"Rate limiter: RATE LIMITED, "
                    f"container={container_id}, upstream={upstream_host}, "
                    f"tokens_remaining={bucket.tokens:.2f}, "
                    f"retry_after={retry_after:.2f}s"
                )
                return (False, retry_after)

    def _deny_request(
        self,
        flow: http.HTTPFlow,
        container_id: str,
        upstream_host: str,
        retry_after: float,
    ) -> None:
        """Deny request with 429 Too Many Requests response.

        Args:
            flow: The mitmproxy HTTP flow
            container_id: Container identifier (for logging)
            upstream_host: Upstream host (for logging)
            retry_after: Seconds to wait before retrying
        """
        # Round up retry_after to whole seconds
        retry_after_header = str(int(retry_after) + 1)

        logger.info(
            f"Rate limiter: Denying request from container={container_id} "
            f"to upstream={upstream_host}, retry_after={retry_after_header}s"
        )

        # Create 429 response with Retry-After header
        flow.response = http.Response.make(
            429,
            b"Too Many Requests: Rate limit exceeded",
            {
                "Content-Type": "text/plain",
                "Retry-After": retry_after_header,
            },
        )

    def _cleanup_stale_buckets(self, now: float) -> None:
        """Remove buckets that haven't been accessed recently.

        Args:
            now: Current timestamp
        """
        with self.lock:
            stale_keys = [
                key
                for key, bucket in self.buckets.items()
                if now - bucket.last_access > BUCKET_EXPIRY_SECONDS
            ]

            for key in stale_keys:
                del self.buckets[key]
                container_id, upstream_host = key
                logger.debug(
                    f"Rate limiter: Cleaned up stale bucket for "
                    f"container={container_id}, upstream={upstream_host}"
                )

            if stale_keys:
                logger.info(
                    f"Rate limiter: Cleanup completed, removed {len(stale_keys)} "
                    f"stale buckets, {len(self.buckets)} remaining"
                )

            self.last_cleanup = now


# Export addon instance for mitmproxy
addons = [RateLimiterAddon()]
