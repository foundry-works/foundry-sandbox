"""HMAC authentication, nonce replay protection, and rate limiting for the git API."""

import hashlib
import hmac
import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Configuration
SECRETS_MOUNT_PATH = os.environ.get(
    "GIT_API_SECRETS_PATH", "/run/secrets/sandbox-hmac"
)
CLOCK_WINDOW_SECONDS = 300
NONCE_TTL_SECONDS = 600
NONCE_MAX_PER_SANDBOX = 1000
RATE_BURST = 300
RATE_SUSTAINED = 120
RATE_GLOBAL_CEILING = 1000
IP_THROTTLE_WINDOW = 60
IP_THROTTLE_MAX = 100
MAX_REQUEST_BODY = 256 * 1024


class SecretStore:
    """Manages per-sandbox HMAC secrets from file-based storage."""

    def __init__(self, secrets_path: str = SECRETS_MOUNT_PATH):
        self._path = secrets_path
        self._cache: Dict[str, bytes] = {}
        self._lock = threading.Lock()

    def get_secret(self, sandbox_id: str) -> Optional[bytes]:
        """Get the HMAC secret for a sandbox."""
        with self._lock:
            if sandbox_id in self._cache:
                return self._cache[sandbox_id]

        secret_path = os.path.join(self._path, sandbox_id)
        try:
            with open(secret_path, "rb") as f:
                secret = f.read()
                if secret.endswith(b"\n"):
                    secret = secret[:-1]
            if secret:
                with self._lock:
                    self._cache[sandbox_id] = secret
                return secret
        except FileNotFoundError:
            logger.warning("No secret found for sandbox: %s", sandbox_id)
        except OSError as exc:
            logger.error("Failed to read secret for %s: %s", sandbox_id, exc)

        return None

    def revoke(self, sandbox_id: str) -> None:
        with self._lock:
            self._cache.pop(sandbox_id, None)

    def rotate(self, sandbox_id: str) -> None:
        with self._lock:
            self._cache.pop(sandbox_id, None)

    def clear_all(self) -> None:
        with self._lock:
            self._cache.clear()


class NonceStore:
    """Per-sandbox nonce tracking with TTL and LRU eviction."""

    def __init__(
        self,
        ttl: int = NONCE_TTL_SECONDS,
        max_per_sandbox: int = NONCE_MAX_PER_SANDBOX,
    ):
        self._stores: Dict[str, OrderedDict] = {}
        self._lock = threading.Lock()
        self._ttl = ttl
        self._max = max_per_sandbox

    def check_and_store(self, sandbox_id: str, nonce: str) -> bool:
        """Check if nonce is unique for this sandbox. Returns True if new."""
        now = time.time()

        with self._lock:
            if sandbox_id not in self._stores:
                self._stores[sandbox_id] = OrderedDict()

            store = self._stores[sandbox_id]

            expired_keys = [
                k for k, ts in store.items() if now - ts > self._ttl
            ]
            for k in expired_keys:
                del store[k]

            if nonce in store:
                return False

            while len(store) >= self._max:
                store.popitem(last=False)

            store[nonce] = now
            return True

    def clear_sandbox(self, sandbox_id: str) -> None:
        with self._lock:
            self._stores.pop(sandbox_id, None)


@dataclass
class TokenBucket:
    """Token bucket rate limiter."""

    tokens: float
    last_refill: float
    capacity: float
    refill_rate: float

    def try_consume(self, now: float) -> bool:
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    @property
    def retry_after(self) -> float:
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.refill_rate


class RateLimiter:
    """Per-sandbox + global rate limiting with pre-auth IP throttling."""

    def __init__(
        self,
        burst: int = RATE_BURST,
        sustained: float = RATE_SUSTAINED,
        global_ceiling: int = RATE_GLOBAL_CEILING,
        ip_window: int = IP_THROTTLE_WINDOW,
        ip_max: int = IP_THROTTLE_MAX,
    ):
        self._sandbox_buckets: Dict[str, TokenBucket] = {}
        self._ip_counters: Dict[str, list] = {}
        self._global_timestamps: list = []
        self._lock = threading.Lock()
        self._burst = burst
        self._sustained_per_sec = sustained / 60.0
        self._global_ceiling = global_ceiling
        self._ip_window = ip_window
        self._ip_max = ip_max

    def check_ip_throttle(self, ip: str) -> Tuple[bool, float]:
        now = time.time()
        with self._lock:
            if ip not in self._ip_counters:
                self._ip_counters[ip] = []

            timestamps = self._ip_counters[ip]
            cutoff = now - self._ip_window
            self._ip_counters[ip] = [t for t in timestamps if t > cutoff]
            timestamps = self._ip_counters[ip]

            if len(timestamps) >= self._ip_max:
                oldest = timestamps[0] if timestamps else now
                retry = self._ip_window - (now - oldest)
                return False, max(retry, 1.0)

            timestamps.append(now)
            return True, 0.0

    def check_sandbox_rate(self, sandbox_id: str) -> Tuple[bool, float]:
        now = time.time()
        with self._lock:
            if sandbox_id not in self._sandbox_buckets:
                self._sandbox_buckets[sandbox_id] = TokenBucket(
                    tokens=float(self._burst),
                    last_refill=now,
                    capacity=float(self._burst),
                    refill_rate=self._sustained_per_sec,
                )

            bucket = self._sandbox_buckets[sandbox_id]
            if bucket.try_consume(now):
                return True, 0.0
            return False, bucket.retry_after

    def check_global_rate(self) -> Tuple[bool, float]:
        now = time.time()
        with self._lock:
            cutoff = now - 60.0
            self._global_timestamps = [
                t for t in self._global_timestamps if t > cutoff
            ]

            if len(self._global_timestamps) >= self._global_ceiling:
                oldest = self._global_timestamps[0]
                retry = 60.0 - (now - oldest)
                return False, max(retry, 1.0)

            self._global_timestamps.append(now)
            return True, 0.0

    def clear_sandbox(self, sandbox_id: str) -> None:
        with self._lock:
            self._sandbox_buckets.pop(sandbox_id, None)

    def cleanup_stale(self, max_age: float = 3600.0) -> None:
        now = time.time()
        with self._lock:
            stale_ips = [
                ip
                for ip, ts in self._ip_counters.items()
                if not ts or (now - max(ts)) > max_age
            ]
            for ip in stale_ips:
                del self._ip_counters[ip]


def compute_signature(
    method: str,
    path: str,
    body: bytes,
    timestamp: str,
    nonce: str,
    secret: bytes,
) -> str:
    """Compute HMAC-SHA256 signature over canonical request string."""
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{method}\n{path}\n{body_hash}\n{timestamp}\n{nonce}"
    sig = hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256)
    return sig.hexdigest()


def verify_signature(
    method: str,
    path: str,
    body: bytes,
    timestamp: str,
    nonce: str,
    provided_sig: str,
    secret: bytes,
) -> bool:
    """Verify HMAC-SHA256 signature using constant-time comparison."""
    expected = compute_signature(method, path, body, timestamp, nonce, secret)
    return hmac.compare_digest(expected, provided_sig)
