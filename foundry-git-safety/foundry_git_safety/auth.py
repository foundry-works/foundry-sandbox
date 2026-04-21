"""HMAC authentication, nonce replay protection, and rate limiting for the git API."""

import hashlib
import hmac
import logging
import os
import re
import threading
import time
import typing
from collections import OrderedDict
from dataclasses import dataclass


logger = logging.getLogger(__name__)

# Default secrets directory for standalone host usage (user-writable).
# Container workloads override via GIT_API_SECRETS_PATH env var.
_FOUNDRY_BASE = os.path.expanduser("~/.foundry")
SECRETS_MOUNT_PATH = os.environ.get(
    "GIT_API_SECRETS_PATH", f"{_FOUNDRY_BASE}/secrets/sandbox-hmac"
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

SANDBOX_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class SecretStore:
    """Manages per-sandbox HMAC secrets from file-based storage.

    Caches secrets in memory but detects external file changes via mtime
    so that out-of-process rotation (e.g. watchdog) invalidates the cache
    without requiring an explicit rotate() call or server restart.
    """

    def __init__(self, secrets_path: str = SECRETS_MOUNT_PATH):
        self._path = secrets_path
        self._cache: dict[str, bytes] = {}
        self._mtimes: dict[str, float] = {}
        self._lock = threading.Lock()
        self.on_secret_changed: typing.Callable[[str], None] | None = None

    _MAX_SECRET_SIZE = 1024

    @staticmethod
    def _validate_sandbox_id(sandbox_id: str) -> None:
        if not SANDBOX_ID_RE.match(sandbox_id):
            raise ValueError(f"Invalid sandbox_id: {sandbox_id!r}")

    def _get_mtime(self, sandbox_id: str) -> float | None:
        try:
            return os.stat(os.path.join(self._path, sandbox_id)).st_mtime
        except (FileNotFoundError, OSError):
            return None

    def get_secret(self, sandbox_id: str) -> bytes | None:
        """Get the HMAC secret for a sandbox.

        Detects external file rotation via mtime and evicts stale cache
        entries before re-reading from disk.
        """
        self._validate_sandbox_id(sandbox_id)
        fire_callback = False

        with self._lock:
            if sandbox_id in self._cache:
                current_mtime = self._get_mtime(sandbox_id)
                if current_mtime is not None and current_mtime != self._mtimes.get(sandbox_id):
                    logger.info("Secret file mtime changed for %s, re-reading", sandbox_id)
                    self._cache.pop(sandbox_id, None)
                    self._mtimes.pop(sandbox_id, None)
                    fire_callback = True
                else:
                    return self._cache[sandbox_id]

            secret_path = os.path.join(self._path, sandbox_id)
            try:
                stat_result = os.stat(secret_path)
                with open(secret_path, "rb") as f:
                    secret = f.read(self._MAX_SECRET_SIZE)
                    if secret.endswith(b"\n"):
                        secret = secret[:-1]
                if secret:
                    self._cache[sandbox_id] = secret
                    self._mtimes[sandbox_id] = stat_result.st_mtime
            except FileNotFoundError:
                logger.warning("No secret found for sandbox: %s", sandbox_id)
                secret = None
            except OSError as exc:
                logger.error("Failed to read secret for %s: %s", sandbox_id, exc)
                secret = None

        if fire_callback and self.on_secret_changed is not None:
            self.on_secret_changed(sandbox_id)

        return secret

    def revoke(self, sandbox_id: str) -> None:
        with self._lock:
            self._cache.pop(sandbox_id, None)
            self._mtimes.pop(sandbox_id, None)

    def rotate(self, sandbox_id: str) -> None:
        with self._lock:
            self._cache.pop(sandbox_id, None)
            self._mtimes.pop(sandbox_id, None)

    def clear_all(self) -> None:
        with self._lock:
            self._cache.clear()
            self._mtimes.clear()


class NonceStore:
    """Per-sandbox nonce tracking with TTL and LRU eviction."""

    def __init__(
        self,
        ttl: int = NONCE_TTL_SECONDS,
        max_per_sandbox: int = NONCE_MAX_PER_SANDBOX,
    ):
        self._stores: dict[str, OrderedDict] = {}
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

            if nonce in store:
                # Check if the stored nonce has expired
                if now - store[nonce] <= self._ttl:
                    return False
                # Expired — remove it and fall through to re-store
                del store[nonce]

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
        self._sandbox_buckets: dict[str, TokenBucket] = {}
        self._ip_counters: dict[str, list] = {}
        self._global_timestamps: list = []
        self._lock = threading.Lock()
        self._burst = burst
        self._sustained_per_sec = sustained / 60.0
        self._global_ceiling = global_ceiling
        self._ip_window = ip_window
        self._ip_max = ip_max

    def check_ip_throttle(self, ip: str) -> tuple[bool, float]:
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

    def check_sandbox_rate(self, sandbox_id: str) -> tuple[bool, float]:
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

    def check_global_rate(self) -> tuple[bool, float]:
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

    # Multiplier applied to the longest rate window to determine stale entry age.
    _STALE_AGE_MULTIPLIER = 3

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
            stale_buckets = [
                sid
                for sid, bucket in self._sandbox_buckets.items()
                if (now - bucket.last_refill) > max_age
            ]
            for sid in stale_buckets:
                del self._sandbox_buckets[sid]


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
    sig = hmac.HMAC(secret, canonical.encode("utf-8"), hashlib.sha256)
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
    # Reject malformed signatures before comparison
    if len(provided_sig) != 64 or not all(
        c in "0123456789abcdef" for c in provided_sig
    ):
        return False
    expected = compute_signature(method, path, body, timestamp, nonce, secret)
    return hmac.compare_digest(expected, provided_sig)


def authenticate_request(
    request,
    *,
    secret_store: SecretStore,
    nonce_store: NonceStore,
    rate_limiter: RateLimiter,
    clock_window: float = CLOCK_WINDOW_SECONDS,
) -> tuple[str | None, tuple | None]:
    """Authenticate a Flask request using the standard 8-step HMAC flow.

    Returns (sandbox_id, None) on success, or (None, error_tuple) on failure
    where error_tuple is (jsonify_body, status_code).
    """
    import time as _time

    from flask import jsonify

    # 1. Pre-auth IP throttle
    client_ip = request.remote_addr or "unknown"
    allowed, retry = rate_limiter.check_ip_throttle(client_ip)
    if not allowed:
        logger.warning("IP throttled: %s", client_ip)
        resp = jsonify({"error": "Rate limit exceeded"})
        resp.headers["Retry-After"] = str(int(retry) + 1)
        return None, (resp, 429)

    # 2. Extract auth headers
    sandbox_id: str = request.headers.get("X-Sandbox-Id", "")
    signature: str = request.headers.get("X-Request-Signature", "")
    timestamp: str = request.headers.get("X-Request-Timestamp", "")
    nonce: str = request.headers.get("X-Request-Nonce", "")

    if not all([sandbox_id, signature, timestamp, nonce]):
        return None, (jsonify({"error": "Missing authentication headers"}), 401)

    # 3. Clock window validation
    try:
        req_time = float(timestamp)
    except (ValueError, TypeError):
        return None, (jsonify({"error": "Invalid timestamp"}), 401)

    now = _time.time()
    if abs(now - req_time) > clock_window:
        logger.warning(
            "Clock skew for sandbox %s: delta=%.1fs",
            sandbox_id, abs(now - req_time),
        )
        return None, (jsonify({"error": "Request timestamp outside clock window"}), 401)

    # 4. Get sandbox secret
    secret = secret_store.get_secret(sandbox_id)
    if secret is None:
        return None, (jsonify({"error": "Unknown sandbox or missing secret"}), 401)

    # 5. Verify HMAC signature
    body = request.get_data()
    if not verify_signature(
        method=request.method,
        path=request.path,
        body=body,
        timestamp=timestamp,
        nonce=nonce,
        provided_sig=signature,
        secret=secret,
    ):
        logger.warning("Invalid HMAC signature for sandbox %s", sandbox_id)
        return None, (jsonify({"error": "Invalid signature"}), 401)

    # 6. Nonce replay protection
    if not nonce_store.check_and_store(sandbox_id, nonce):
        logger.warning("Replayed nonce for sandbox %s: %s", sandbox_id, nonce)
        return None, (jsonify({"error": "Replayed request (duplicate nonce)"}), 401)

    # 7. Per-sandbox rate limit
    allowed, retry = rate_limiter.check_sandbox_rate(sandbox_id)
    if not allowed:
        resp = jsonify({"error": "Rate limit exceeded"})
        resp.headers["Retry-After"] = str(int(retry) + 1)
        return None, (resp, 429)

    # 8. Global rate limit
    allowed, retry = rate_limiter.check_global_rate()
    if not allowed:
        resp = jsonify({"error": "Rate limit exceeded"})
        resp.headers["Retry-After"] = str(int(retry) + 1)
        return None, (resp, 429)

    return sandbox_id, None
