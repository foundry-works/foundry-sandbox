"""Authenticated git API TCP server.

Dedicated TCP server serving POST /git/exec with HMAC authentication,
nonce replay protection, rate limiting, and file-based sandbox metadata.

Security model:
- HMAC-SHA256 signature on every request (per-sandbox shared secret)
- Replay protection via nonce uniqueness + clock window (5 min)
- Per-sandbox rate limiting (300 burst, 120 sustained)
- Global rate ceiling (1000 req/min)
- Pre-auth IP-based throttling
"""

import json
import logging
import os
import threading
import time

try:
    from flask import Flask, Response, jsonify, request
except ImportError as exc:
    raise ImportError(
        "Flask is required for the git safety server. "
        "Install with: pip install foundry-git-safety[server]"
    ) from exc

from .auth import (
    MAX_REQUEST_BODY,
    SANDBOX_ID_RE,
    NonceStore,
    RateLimiter,
    SecretStore,
    verify_signature,
)
from .logging_config import flask_request_middleware

logger = logging.getLogger(__name__)

# Default data directory for sandbox metadata
DEFAULT_DATA_DIR = os.environ.get(
    "FOUNDRY_DATA_DIR", "/var/lib/foundry-git-safety"
)


class _InFlightCounter:
    """Thread-safe counter for tracking in-flight requests during shutdown."""

    def __init__(self) -> None:
        self._count = 0
        self._lock = threading.Lock()
        self._zero = threading.Event()
        self._zero.set()

    def increment(self) -> None:
        with self._lock:
            self._count += 1
            self._zero.clear()

    def decrement(self) -> None:
        with self._lock:
            self._count -= 1
            if self._count <= 0:
                self._zero.set()

    def wait_for_zero(self, timeout: float = 30.0) -> bool:
        return self._zero.wait(timeout)


_in_flight_count = _InFlightCounter()


def _load_sandbox_metadata(
    sandbox_id: str,
    data_dir: str = DEFAULT_DATA_DIR,
) -> dict | None:
    """Load sandbox metadata from a JSON file.

    File path: {data_dir}/sandboxes/{sandbox_id}.json
    """
    if not SANDBOX_ID_RE.match(sandbox_id):
        logger.warning("Invalid sandbox_id rejected: %r", sandbox_id)
        return None
    metadata_path = os.path.join(data_dir, "sandboxes", f"{sandbox_id}.json")
    try:
        with open(metadata_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning("No metadata found for sandbox: %s", sandbox_id)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to read metadata for %s: %s", sandbox_id, exc)
    return None


def create_git_api(
    secret_store: SecretStore | None = None,
    nonce_store: NonceStore | None = None,
    rate_limiter: RateLimiter | None = None,
    data_dir: str | None = None,
    repo_root_resolver=None,
) -> Flask:
    """Create the git API Flask application.

    Args:
        secret_store: HMAC secret storage.
        nonce_store: Replay protection nonce tracker.
        rate_limiter: Rate limiter instance.
        data_dir: Directory for sandbox metadata JSON files.
        repo_root_resolver: Callable(sandbox_id, metadata) -> repo_root path.
    """
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BODY

    flask_request_middleware(app)

    secrets = secret_store or SecretStore()
    nonces = nonce_store or NonceStore()
    limiter = rate_limiter or RateLimiter()
    resolved_data_dir = data_dir or DEFAULT_DATA_DIR

    # Import here to avoid circular imports
    from .command_validation import validate_request
    from .operations import execute_git

    def _resolve_repo_root(sandbox_id: str, metadata: dict | None) -> str:
        if repo_root_resolver:
            return repo_root_resolver(sandbox_id, metadata)
        if metadata:
            return metadata.get("repo_root", "/git-workspace")
        return "/git-workspace"

    def _make_error(message: str, status: int) -> Response:
        return Response(
            json.dumps({"error": message}),
            status=status,
            content_type="application/json",
        )

    def _make_rate_limited(retry_after: float) -> Response:
        resp = _make_error("Rate limit exceeded", 429)
        resp.headers["Retry-After"] = str(int(retry_after) + 1)
        return resp

    @app.route("/git/exec", methods=["POST"])
    def git_exec():
        from .auth import CLOCK_WINDOW_SECONDS

        client_ip = request.remote_addr or "unknown"
        _in_flight_count.increment()
        try:
            return _git_exec_inner(CLOCK_WINDOW_SECONDS, client_ip)
        finally:
            _in_flight_count.decrement()

    def _git_exec_inner(clock_window: float, client_ip: str) -> Response:

        # Pre-auth IP throttle
        allowed, retry = limiter.check_ip_throttle(client_ip)
        if not allowed:
            logger.warning("IP throttled: %s", client_ip)
            return _make_rate_limited(retry)

        # Extract auth headers
        sandbox_id: str = request.headers.get("X-Sandbox-Id", "")
        signature: str = request.headers.get("X-Request-Signature", "")
        timestamp: str = request.headers.get("X-Request-Timestamp", "")
        nonce: str = request.headers.get("X-Request-Nonce", "")

        if not all([sandbox_id, signature, timestamp, nonce]):
            return _make_error("Missing authentication headers", 401)

        # Clock window validation
        try:
            req_time = float(timestamp)
        except (ValueError, TypeError):
            return _make_error("Invalid timestamp", 401)

        now = time.time()
        if abs(now - req_time) > clock_window:
            logger.warning(
                "Clock skew for sandbox %s: delta=%.1fs",
                sandbox_id,
                abs(now - req_time),
            )
            return _make_error("Request timestamp outside clock window", 401)

        # Get sandbox secret
        secret = secrets.get_secret(sandbox_id)
        if secret is None:
            return _make_error("Unknown sandbox or missing secret", 401)

        # Verify HMAC signature
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
            return _make_error("Invalid signature", 401)

        # Nonce replay protection
        if not nonces.check_and_store(sandbox_id, nonce):
            logger.warning("Replayed nonce for sandbox %s: %s", sandbox_id, nonce)
            return _make_error("Replayed request (duplicate nonce)", 401)

        # Per-sandbox rate limit
        allowed, retry = limiter.check_sandbox_rate(sandbox_id)
        if not allowed:
            return _make_rate_limited(retry)

        # Global rate limit
        allowed, retry = limiter.check_global_rate()
        if not allowed:
            return _make_rate_limited(retry)

        # Parse and validate request body
        try:
            raw = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _make_error("Invalid JSON body", 400)

        req, err = validate_request(raw)
        if err:
            return _make_error(err.reason, 400)

        # Resolve metadata and repo root
        metadata = _load_sandbox_metadata(sandbox_id, resolved_data_dir)
        repo_root = _resolve_repo_root(sandbox_id, metadata)

        # Execute git command
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

    # Attach components for external access (admin commands, testing)
    app.secret_store = secrets
    app.nonce_store = nonces
    app.rate_limiter = limiter

    return app


def run_tcp_server(
    app: Flask | None = None,
    host: str = "127.0.0.1",
    port: int = 8083,
) -> None:
    """Run the git API on a TCP socket."""
    from werkzeug.serving import make_server

    if app is None:
        app = create_git_api()

    logger.info("Starting git API server on %s:%d", host, port)

    server = make_server(host, port, app, threaded=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Git API server shutting down, draining in-flight requests...")
    finally:
        server.shutdown()
        # Wait for in-flight requests to complete before closing
        drained = _in_flight_count.wait_for_zero(timeout=30.0)
        if not drained:
            logger.warning("Shutdown timed out with in-flight requests still pending")
        else:
            logger.info("All in-flight requests completed")


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
