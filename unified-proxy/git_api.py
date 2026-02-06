"""Authenticated git API TCP server.

Dedicated TCP server on port 8083 serving POST /git/exec only.
Does NOT expose /internal/* registry routes.

Security model:
- Bound to credential-isolation network only (configured via bind address)
- HMAC-SHA256 signature on every request (per-sandbox shared secret)
- Replay protection via nonce uniqueness + clock window (5 min)
- Per-sandbox rate limiting (300 burst, 120 sustained)
- Global rate ceiling (1000 req/min)
- Pre-auth IP-based throttling
- Secrets delivered via Docker secrets mount (not env vars)
"""

import hashlib
import hmac
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from flask import Flask, Response, jsonify, request

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GIT_API_PORT = int(os.environ.get("GIT_API_PORT", "8083"))
GIT_API_BIND = os.environ.get("GIT_API_BIND", "0.0.0.0")
SECRETS_MOUNT_PATH = os.environ.get(
    "GIT_API_SECRETS_PATH", "/run/secrets/sandbox-hmac"
)

# Clock window for timestamp validation
CLOCK_WINDOW_SECONDS = 300  # 5 minutes

# Nonce cache settings
NONCE_TTL_SECONDS = 600     # 10 minutes
NONCE_MAX_PER_SANDBOX = 1000  # LRU eviction threshold

# Rate limiting
RATE_BURST = 300            # Per-sandbox burst capacity
RATE_SUSTAINED = 120        # Per-sandbox tokens/min (2/sec)
RATE_GLOBAL_CEILING = 1000  # Global req/min

# Pre-auth IP throttle
IP_THROTTLE_WINDOW = 60     # 1 minute
IP_THROTTLE_MAX = 100       # Max requests per IP per window

# Request size limits
MAX_REQUEST_BODY = 256 * 1024  # 256KB


# ---------------------------------------------------------------------------
# HMAC Secret Management
# ---------------------------------------------------------------------------


class SecretStore:
    """Manages per-sandbox HMAC secrets from Docker secrets mount.

    Secrets are stored as files: {SECRETS_MOUNT_PATH}/{sandbox_id}
    Each file contains the raw shared secret.
    """

    def __init__(self, secrets_path: str = SECRETS_MOUNT_PATH):
        self._path = secrets_path
        self._cache: Dict[str, bytes] = {}
        self._lock = threading.Lock()

    def get_secret(self, sandbox_id: str) -> Optional[bytes]:
        """Get the HMAC secret for a sandbox.

        Returns cached value if available, otherwise reads from disk.
        """
        with self._lock:
            if sandbox_id in self._cache:
                return self._cache[sandbox_id]

        # Read from secrets mount
        secret_path = os.path.join(self._path, sandbox_id)
        try:
            with open(secret_path, "rb") as f:
                secret = f.read().strip()
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
        """Revoke a sandbox's secret (e.g., on teardown)."""
        with self._lock:
            self._cache.pop(sandbox_id, None)

    def rotate(self, sandbox_id: str) -> None:
        """Force re-read of secret on next access (e.g., after rotation)."""
        with self._lock:
            self._cache.pop(sandbox_id, None)

    def clear_all(self) -> None:
        """Clear entire secret cache."""
        with self._lock:
            self._cache.clear()


# ---------------------------------------------------------------------------
# Nonce Store (Replay Protection)
# ---------------------------------------------------------------------------


class NonceStore:
    """Per-sandbox nonce tracking with TTL and LRU eviction.

    Each sandbox has its own OrderedDict of nonce -> timestamp.
    When the cache exceeds NONCE_MAX_PER_SANDBOX, oldest entries are evicted.
    Expired nonces (older than NONCE_TTL_SECONDS) are cleaned on access.
    """

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
        """Check if nonce is unique for this sandbox, store if so.

        Returns True if nonce is new (valid), False if replayed.
        """
        now = time.time()

        with self._lock:
            if sandbox_id not in self._stores:
                self._stores[sandbox_id] = OrderedDict()

            store = self._stores[sandbox_id]

            # Clean expired entries
            expired_keys = [
                k for k, ts in store.items() if now - ts > self._ttl
            ]
            for k in expired_keys:
                del store[k]

            # Check for replay
            if nonce in store:
                return False

            # LRU eviction if at capacity
            while len(store) >= self._max:
                store.popitem(last=False)

            # Store the nonce
            store[nonce] = now
            return True

    def clear_sandbox(self, sandbox_id: str) -> None:
        """Clear nonce cache for a sandbox."""
        with self._lock:
            self._stores.pop(sandbox_id, None)


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------


@dataclass
class TokenBucket:
    """Token bucket rate limiter."""

    tokens: float
    last_refill: float
    capacity: float
    refill_rate: float  # tokens per second

    def try_consume(self, now: float) -> bool:
        """Try to consume one token. Returns True if allowed."""
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    @property
    def retry_after(self) -> float:
        """Seconds until a token is available."""
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
        self._ip_counters: Dict[str, list] = {}  # ip -> [timestamps]
        self._global_timestamps: list = []
        self._lock = threading.Lock()
        self._burst = burst
        self._sustained_per_sec = sustained / 60.0
        self._global_ceiling = global_ceiling
        self._ip_window = ip_window
        self._ip_max = ip_max

    def check_ip_throttle(self, ip: str) -> Tuple[bool, float]:
        """Pre-auth IP-based throttle. Returns (allowed, retry_after)."""
        now = time.time()
        with self._lock:
            if ip not in self._ip_counters:
                self._ip_counters[ip] = []

            timestamps = self._ip_counters[ip]
            # Prune old entries
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
        """Per-sandbox token bucket. Returns (allowed, retry_after)."""
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
        """Global rate ceiling. Returns (allowed, retry_after)."""
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
        """Remove rate limit state for a sandbox."""
        with self._lock:
            self._sandbox_buckets.pop(sandbox_id, None)

    def cleanup_stale(self, max_age: float = 3600.0) -> None:
        """Remove stale entries older than max_age seconds."""
        now = time.time()
        with self._lock:
            stale_ips = [
                ip
                for ip, ts in self._ip_counters.items()
                if not ts or (now - max(ts)) > max_age
            ]
            for ip in stale_ips:
                del self._ip_counters[ip]


# ---------------------------------------------------------------------------
# HMAC Signature Verification
# ---------------------------------------------------------------------------


def compute_signature(
    method: str,
    path: str,
    body: bytes,
    timestamp: str,
    nonce: str,
    secret: bytes,
) -> str:
    """Compute HMAC-SHA256 signature over canonical request string.

    Canonical string: METHOD\nPATH\nSHA256(body)\nTIMESTAMP\nNONCE
    """
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


# ---------------------------------------------------------------------------
# Flask Application
# ---------------------------------------------------------------------------


def create_git_api(
    secret_store: Optional[SecretStore] = None,
    nonce_store: Optional[NonceStore] = None,
    rate_limiter: Optional[RateLimiter] = None,
    repo_root_resolver=None,
) -> Flask:
    """Create the git API Flask application.

    Args:
        secret_store: HMAC secret storage (defaults to file-based).
        nonce_store: Replay protection nonce tracker.
        rate_limiter: Rate limiter instance.
        repo_root_resolver: Callable(sandbox_id, metadata) -> repo_root path.
            Defaults to reading from container metadata.
    """
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BODY

    secrets = secret_store or SecretStore()
    nonces = nonce_store or NonceStore()
    limiter = rate_limiter or RateLimiter()

    # Import here to avoid circular imports at module level
    from git_operations import execute_git, validate_request

    def _resolve_repo_root(sandbox_id: str, metadata: Optional[dict]) -> str:
        """Resolve repo root from metadata or default."""
        if repo_root_resolver:
            return repo_root_resolver(sandbox_id, metadata)
        if metadata:
            return metadata.get("repo_root", "/git-workspace")
        return "/git-workspace"

    def _make_error(message: str, status: int) -> Response:
        """Create a JSON error response."""
        return Response(
            json.dumps({"error": message}),
            status=status,
            content_type="application/json",
        )

    def _make_rate_limited(retry_after: float) -> Response:
        """Create a 429 response with Retry-After header."""
        resp = _make_error("Rate limit exceeded", 429)
        resp.headers["Retry-After"] = str(int(retry_after) + 1)
        return resp

    @app.route("/git/exec", methods=["POST"])
    def git_exec():
        # --- Pre-auth IP throttle ---
        client_ip = request.remote_addr or "unknown"
        allowed, retry = limiter.check_ip_throttle(client_ip)
        if not allowed:
            logger.warning("IP throttled: %s", client_ip)
            return _make_rate_limited(retry)

        # --- Extract auth headers ---
        sandbox_id: str = request.headers.get("X-Sandbox-Id", "")
        signature: str = request.headers.get("X-Request-Signature", "")
        timestamp: str = request.headers.get("X-Request-Timestamp", "")
        nonce: str = request.headers.get("X-Request-Nonce", "")

        if not all([sandbox_id, signature, timestamp, nonce]):
            return _make_error("Missing authentication headers", 401)

        # --- Clock window validation ---
        try:
            req_time = float(timestamp)
        except (ValueError, TypeError):
            return _make_error("Invalid timestamp", 401)

        now = time.time()
        if abs(now - req_time) > CLOCK_WINDOW_SECONDS:
            logger.warning(
                "Clock skew for sandbox %s: delta=%.1fs",
                sandbox_id,
                abs(now - req_time),
            )
            return _make_error("Request timestamp outside clock window", 401)

        # --- Get sandbox secret ---
        secret = secrets.get_secret(sandbox_id)
        if secret is None:
            return _make_error("Unknown sandbox or missing secret", 401)

        # --- Verify HMAC signature ---
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
            logger.warning(
                "Invalid HMAC signature for sandbox %s", sandbox_id
            )
            return _make_error("Invalid signature", 401)

        # --- Nonce replay protection ---
        if not nonces.check_and_store(sandbox_id, nonce):
            logger.warning(
                "Replayed nonce for sandbox %s: %s", sandbox_id, nonce
            )
            return _make_error("Replayed request (duplicate nonce)", 401)

        # --- Per-sandbox rate limit ---
        allowed, retry = limiter.check_sandbox_rate(sandbox_id)
        if not allowed:
            return _make_rate_limited(retry)

        # --- Global rate limit ---
        allowed, retry = limiter.check_global_rate()
        if not allowed:
            return _make_rate_limited(retry)

        # --- Parse and validate request body ---
        try:
            raw = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _make_error("Invalid JSON body", 400)

        req, err = validate_request(raw)
        if err:
            return _make_error(err.reason, 400)

        # --- Resolve repo root (server-side, ignoring client cwd for path) ---
        metadata = _get_sandbox_metadata(sandbox_id, client_ip)
        repo_root = _resolve_repo_root(sandbox_id, metadata)

        # --- Execute git command ---
        response, err = execute_git(req, repo_root, metadata)
        if err:
            return _make_error(err.reason, 422)

        return jsonify(response.to_dict())

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"})

    @app.errorhandler(404)
    def not_found(e):
        return _make_error("Not found", 404)

    @app.errorhandler(405)
    def method_not_allowed(e):
        return _make_error("Method not allowed", 405)

    @app.errorhandler(413)
    def request_too_large(e):
        return _make_error(
            f"Request body too large (max {MAX_REQUEST_BODY} bytes)", 413
        )

    def _get_sandbox_metadata(
        sandbox_id: str,
        client_ip: Optional[str] = None,
    ) -> Optional[dict]:
        """Get sandbox metadata from container registry.

        Lookup order:
        1. sandbox_id as registry container_id (legacy behavior)
        2. client IP address (matches internal proxy registration model)
        """
        try:
            from registry import ContainerRegistry

            registry = ContainerRegistry()
            config = registry.get_by_container_id(sandbox_id)
            if config:
                return config.metadata
            if client_ip and client_ip != "unknown":
                config = registry.get_by_ip(client_ip)
                if config:
                    return config.metadata
        except Exception:
            logger.debug(
                "Could not load metadata for sandbox %s", sandbox_id
            )
        return None

    # Attach components for external access (admin commands, testing)
    app.secret_store = secrets
    app.nonce_store = nonces
    app.rate_limiter = limiter

    return app


# ---------------------------------------------------------------------------
# Server Entry Point
# ---------------------------------------------------------------------------


def run_tcp_server(
    app: Optional[Flask] = None,
    host: str = GIT_API_BIND,
    port: int = GIT_API_PORT,
) -> None:
    """Run the git API on a TCP socket.

    Args:
        app: Flask application (creates default if None).
        host: Bind address.
        port: TCP port.
    """
    from werkzeug.serving import make_server

    if app is None:
        app = create_git_api()

    logger.info("Starting git API server on %s:%d", host, port)

    server = make_server(host, port, app, threaded=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Git API server shutting down")
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Admin Operations
# ---------------------------------------------------------------------------


def revoke_sandbox_secret(app: Flask, sandbox_id: str) -> None:
    """Revoke a sandbox's HMAC secret and clear associated state."""
    app.secret_store.revoke(sandbox_id)
    app.nonce_store.clear_sandbox(sandbox_id)
    app.rate_limiter.clear_sandbox(sandbox_id)
    logger.info("Revoked secret and cleared state for sandbox: %s", sandbox_id)


def rotate_sandbox_secret(app: Flask, sandbox_id: str) -> None:
    """Force re-read of sandbox secret (after file rotation)."""
    app.secret_store.rotate(sandbox_id)
    app.nonce_store.clear_sandbox(sandbox_id)
    logger.info("Rotated secret for sandbox: %s", sandbox_id)


# Create default app instance
app = create_git_api()


if __name__ == "__main__":
    run_tcp_server(app)
