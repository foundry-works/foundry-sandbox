"""Internal API for container registration.

This module provides a Flask-based HTTP API for container registration,
exposed via Unix socket only. The API allows containers to register their
identity (container_id + IP address) with the proxy registry.

Security Model:
- Unix socket binding only (no TCP exposure)
- Rate limited to 10 requests/second per client
- Used by container lifecycle scripts, not by containers themselves

Endpoints:
- POST /internal/containers - Register a container
- DELETE /internal/containers/{id} - Unregister a container
- GET /internal/health - Health check
"""

import json
import logging
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from flask import Flask, request, jsonify, Response

from registry import ContainerRegistry

# Configure logging
class _HealthCheckFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return "/internal/health" not in msg

logging.basicConfig(level=logging.INFO)
logging.getLogger("werkzeug").addFilter(_HealthCheckFilter())
logger = logging.getLogger(__name__)

# Configuration
UNIX_SOCKET_PATH = os.environ.get(
    "INTERNAL_API_SOCKET",
    "/var/run/proxy/internal.sock",
)
REGISTRY_DB_PATH = os.environ.get(
    "REGISTRY_DB_PATH",
    "/var/lib/unified-proxy/registry.db",
)

# Rate limiting configuration
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", 10))
RATE_LIMIT_WINDOW = float(os.environ.get("RATE_LIMIT_WINDOW", 1.0))  # seconds


def get_peer_credentials(environ: dict) -> Optional[tuple[int, int, int]]:
    """Extract peer credentials (pid, uid, gid) from Unix socket connection.

    For Unix domain sockets on Linux, SO_PEERCRED provides the credentials
    of the connecting process. This enables per-user rate limiting.

    Args:
        environ: WSGI environ dict containing the socket.

    Returns:
        Tuple of (pid, uid, gid) if available, None otherwise.
    """
    # Try to get the underlying socket from werkzeug's environ
    wsgi_input = environ.get("wsgi.input")
    if wsgi_input is None:
        return None

    # werkzeug wraps the socket in a LimitedStream; try to get raw socket
    raw_socket = getattr(wsgi_input, "_sock", None)
    if raw_socket is None:
        # Try alternative attribute names
        raw_socket = getattr(wsgi_input, "raw", None)
        if raw_socket is not None:
            raw_socket = getattr(raw_socket, "_sock", None)

    if raw_socket is None:
        return None

    try:
        # SO_PEERCRED is Linux-specific (value 17)
        SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
        cred = raw_socket.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("iII"))
        pid, uid, gid = struct.unpack("iII", cred)
        return (pid, uid, gid)
    except (OSError, AttributeError, struct.error):
        return None


def get_client_identifier(request_obj) -> str:
    """Get a unique client identifier for rate limiting.

    For Unix sockets, attempts to use peer UID for per-user rate limiting.
    Falls back to remote_addr or a default identifier.

    Args:
        request_obj: Flask request object.

    Returns:
        String identifier for the client.
    """
    # Try to get peer credentials from Unix socket
    if hasattr(request_obj, "environ"):
        creds = get_peer_credentials(request_obj.environ)
        if creds is not None:
            pid, uid, gid = creds
            return f"uid:{uid}"

    # Fall back to remote_addr for TCP connections
    if request_obj.remote_addr:
        return request_obj.remote_addr

    # Last resort: use a default that won't unfairly rate limit
    # Log warning since this indicates unexpected connection type
    logger.warning("Could not determine client identity for rate limiting")
    return "unknown"


@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""

    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = field(default=0.0)
    last_refill: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        self.tokens = float(self.capacity)

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if successful."""
        with self.lock:
            now = time.time()
            # Refill tokens based on elapsed time
            elapsed = now - self.last_refill
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.refill_rate,
            )
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


class RateLimiter:
    """Per-client rate limiter using token buckets."""

    def __init__(
        self,
        requests_per_window: int = RATE_LIMIT_REQUESTS,
        window_seconds: float = RATE_LIMIT_WINDOW,
    ):
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
        self._requests_per_window = requests_per_window
        self._window_seconds = window_seconds
        # Cleanup old buckets periodically
        self._last_cleanup = time.time()
        self._cleanup_interval = 60.0  # seconds

    def _get_bucket(self, client_id: str) -> TokenBucket:
        """Get or create a token bucket for a client."""
        with self._lock:
            # Periodic cleanup of stale buckets
            now = time.time()
            if now - self._last_cleanup > self._cleanup_interval:
                self._cleanup_stale_buckets()
                self._last_cleanup = now

            if client_id not in self._buckets:
                self._buckets[client_id] = TokenBucket(
                    capacity=self._requests_per_window,
                    refill_rate=self._requests_per_window / self._window_seconds,
                )
            return self._buckets[client_id]

    def _cleanup_stale_buckets(self) -> None:
        """Remove buckets that haven't been used recently."""
        now = time.time()
        stale_threshold = 300.0  # 5 minutes
        stale_clients = [
            client_id
            for client_id, bucket in self._buckets.items()
            if now - bucket.last_refill > stale_threshold
        ]
        for client_id in stale_clients:
            del self._buckets[client_id]
        if stale_clients:
            logger.debug(f"Cleaned up {len(stale_clients)} stale rate limit buckets")

    def is_allowed(self, client_id: str) -> bool:
        """Check if a request from client_id is allowed."""
        bucket = self._get_bucket(client_id)
        return bucket.consume()


# Global rate limiter instance
rate_limiter = RateLimiter()

# Global registry instance (initialized in create_app or externally)
_registry: Optional[ContainerRegistry] = None


def get_registry() -> ContainerRegistry:
    """Get the global registry instance."""
    global _registry
    if _registry is None:
        _registry = ContainerRegistry(db_path=REGISTRY_DB_PATH)
    return _registry


def set_registry(registry: ContainerRegistry) -> None:
    """Set the global registry instance (for testing)."""
    global _registry
    _registry = registry


def create_app(registry: Optional[ContainerRegistry] = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        registry: Optional registry instance. If not provided,
                  uses the global registry.

    Returns:
        Configured Flask application.
    """
    app = Flask(__name__)

    if registry is not None:
        set_registry(registry)

    @app.before_request
    def check_rate_limit():
        """Apply rate limiting before each request."""
        # Use peer UID for Unix sockets, remote_addr for TCP
        client_id = get_client_identifier(request)

        if not rate_limiter.is_allowed(client_id):
            logger.warning(f"Rate limit exceeded for client: {client_id}")
            return Response(
                json.dumps({
                    "error": "Rate limit exceeded",
                    "message": f"Maximum {RATE_LIMIT_REQUESTS} requests per second",
                }),
                status=429,
                mimetype="application/json",
                headers={"Retry-After": "1"},
            )

    @app.route("/internal/health", methods=["GET"])
    def health():
        """Health check endpoint.

        Returns:
            200 with status info if healthy.
        """
        try:
            registry = get_registry()
            container_count = registry.count()
            return jsonify({
                "status": "healthy",
                "containers_registered": container_count,
            }), 200
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({
                "status": "unhealthy",
                "error": "Health check failed",
            }), 503

    @app.route("/internal/containers", methods=["POST"])
    def register_container():
        """Register a new container.

        Request body (JSON):
            container_id: Unique container identifier (required)
            ip_address: Container's IP address (required)
            ttl_seconds: Time-to-live in seconds (optional, default 86400)
            metadata: Optional metadata dictionary

        Returns:
            201 with registration details on success.
            400 if required fields are missing or invalid.
            409 if IP is already registered to different container.
        """
        try:
            data = request.get_json()
            if data is None:
                return jsonify({
                    "error": "Invalid request",
                    "message": "Request body must be valid JSON",
                }), 400

            # Validate required fields
            container_id = data.get("container_id")
            ip_address = data.get("ip_address")

            if not container_id:
                return jsonify({
                    "error": "Missing required field",
                    "message": "container_id is required",
                }), 400

            if not ip_address:
                return jsonify({
                    "error": "Missing required field",
                    "message": "ip_address is required",
                }), 400

            # Validate container_id format (alphanumeric with optional separators)
            if not isinstance(container_id, str) or len(container_id) > 128:
                return jsonify({
                    "error": "Invalid container_id",
                    "message": "container_id must be a string of 128 characters or less",
                }), 400

            # Validate IP address format (basic check)
            if not isinstance(ip_address, str) or not _is_valid_ip(ip_address):
                return jsonify({
                    "error": "Invalid ip_address",
                    "message": "ip_address must be a valid IPv4 or IPv6 address",
                }), 400

            # Optional fields
            ttl_seconds = data.get("ttl_seconds", 86400)
            if not isinstance(ttl_seconds, int) or ttl_seconds < 1:
                return jsonify({
                    "error": "Invalid ttl_seconds",
                    "message": "ttl_seconds must be a positive integer",
                }), 400

            metadata = data.get("metadata")
            if metadata is not None and not isinstance(metadata, dict):
                return jsonify({
                    "error": "Invalid metadata",
                    "message": "metadata must be a JSON object",
                }), 400

            # Register the container
            registry = get_registry()
            config = registry.register(
                container_id=container_id,
                ip_address=ip_address,
                ttl_seconds=ttl_seconds,
                metadata=metadata,
            )

            # Warn about legacy sandboxes missing branch identity
            if not (metadata and metadata.get("sandbox_branch")):
                logger.warning(
                    f"Container {container_id}: sandbox branch identity missing "
                    f"(created before branch isolation support). Commands "
                    f"requiring git proxy validation will be denied. "
                    f"Recreate sandbox to enable branch isolation."
                )

            logger.info(
                f"Registered container {container_id} with IP {ip_address} "
                f"(TTL: {ttl_seconds}s)"
            )

            return jsonify({
                "status": "registered",
                "container": config.to_dict(),
            }), 201

        except ValueError as e:
            # IP conflict with different container
            logger.warning(f"Registration conflict: {e}")
            return jsonify({
                "error": "Conflict",
                "message": str(e),
            }), 409

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return jsonify({
                "error": "Internal error",
                "message": "Failed to register container",
            }), 500

    @app.route("/internal/containers/<container_id>", methods=["DELETE"])
    def unregister_container(container_id: str):
        """Unregister a container.

        Args:
            container_id: The container ID to unregister.

        Returns:
            200 if container was unregistered.
            404 if container was not found.
        """
        try:
            registry = get_registry()
            if registry.unregister(container_id):
                logger.info(f"Unregistered container {container_id}")
                return jsonify({
                    "status": "unregistered",
                    "container_id": container_id,
                }), 200
            else:
                return jsonify({
                    "error": "Not found",
                    "message": f"Container {container_id} not registered",
                }), 404

        except Exception as e:
            logger.error(f"Unregistration error: {e}")
            return jsonify({
                "error": "Internal error",
                "message": "Failed to unregister container",
            }), 500

    @app.route("/internal/containers/<container_id>", methods=["GET"])
    def get_container(container_id: str):
        """Get container registration details.

        Args:
            container_id: The container ID to look up.

        Returns:
            200 with container details if found.
            404 if container was not found or expired.
        """
        try:
            registry = get_registry()
            config = registry.get_by_container_id(container_id)

            if config is None:
                return jsonify({
                    "error": "Not found",
                    "message": f"Container {container_id} not registered or expired",
                }), 404

            return jsonify({
                "status": "found",
                "container": config.to_dict(),
            }), 200

        except Exception as e:
            logger.error(f"Lookup error: {e}")
            return jsonify({
                "error": "Internal error",
                "message": "Failed to look up container",
            }), 500

    @app.route("/internal/containers", methods=["GET"])
    def list_containers():
        """List all registered containers.

        Returns:
            200 with list of all containers.
        """
        try:
            registry = get_registry()
            containers = registry.list_all()

            return jsonify({
                "status": "ok",
                "count": len(containers),
                "containers": [c.to_dict() for c in containers],
            }), 200

        except Exception as e:
            logger.error(f"List error: {e}")
            return jsonify({
                "error": "Internal error",
                "message": "Failed to list containers",
            }), 500

    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors."""
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        """Handle 405 errors."""
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors."""
        logger.error(f"Internal server error: {error}")
        return jsonify({"error": "Internal server error"}), 500

    return app


def _is_valid_ip(ip_string: str) -> bool:
    """Validate an IP address string (IPv4 or IPv6).

    Args:
        ip_string: The string to validate.

    Returns:
        True if valid IP address, False otherwise.
    """
    import ipaddress

    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def run_unix_socket(app: Flask, socket_path: str = UNIX_SOCKET_PATH) -> None:
    """Run the Flask app on a Unix socket.

    Args:
        app: The Flask application.
        socket_path: Path to the Unix socket.

    Note:
        For production, use gunicorn with --bind unix:path instead.
        This function uses werkzeug's make_server for Unix socket support.
    """
    import socket as socket_module
    from pathlib import Path
    from werkzeug.serving import make_server

    # Ensure socket directory exists
    socket_dir = Path(socket_path).parent
    socket_dir.mkdir(parents=True, exist_ok=True)

    # Remove existing socket file if present
    if Path(socket_path).exists():
        Path(socket_path).unlink()

    # Create Unix socket
    sock = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    sock.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
    sock.bind(socket_path)
    sock.listen(128)

    # Set socket permissions (owner read/write only by default)
    os.chmod(socket_path, 0o600)

    logger.info(f"Starting internal API on Unix socket: {socket_path}")

    # Create WSGI server using the pre-bound socket's file descriptor
    server = make_server(
        host="localhost",
        port=0,
        app=app,
        threaded=True,
        fd=sock.fileno(),
    )

    try:
        server.serve_forever()
    finally:
        sock.close()
        if Path(socket_path).exists():
            Path(socket_path).unlink()


# Create default app instance
app = create_app()


if __name__ == "__main__":
    run_unix_socket(app)
