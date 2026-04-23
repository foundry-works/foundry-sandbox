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
    authenticate_request,
)
from .logging_config import flask_request_middleware

logger = logging.getLogger(__name__)

# Default data directory for sandbox metadata (user-writable).
# Container workloads override via FOUNDRY_DATA_DIR env var.
_FOUNDRY_BASE = os.path.expanduser("~/.foundry")
DEFAULT_DATA_DIR = os.environ.get(
    "FOUNDRY_DATA_DIR", f"{_FOUNDRY_BASE}/data/git-safety"
)


def _resolved_user_services(config) -> list:
    """Return user service entries from the active foundry config."""
    if config is None:
        from .config import load_foundry_config
        config = load_foundry_config()
    return list(getattr(config, "user_services", []))


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
    config=None,
) -> Flask:
    """Create the git API Flask application.

    Args:
        secret_store: HMAC secret storage.
        nonce_store: Replay protection nonce tracker.
        rate_limiter: Rate limiter instance.
        data_dir: Directory for sandbox metadata JSON files.
        repo_root_resolver: Callable(sandbox_id, metadata) -> repo_root path.
        config: Optional FoundryConfig for deep policy registration.
    """
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BODY
    app._start_time = time.time()

    flask_request_middleware(app)

    secrets = secret_store or SecretStore()
    nonces = nonce_store or NonceStore()
    limiter = rate_limiter or RateLimiter()
    resolved_data_dir = data_dir or DEFAULT_DATA_DIR

    # When mtime-based secret rotation is detected (e.g. watchdog writes a
    # new secret file), clear the nonce store for that sandbox so replayed
    # nonces from the old secret epoch are evicted.
    secrets.on_secret_changed = nonces.clear_sandbox

    # Configure decision-log writer from config if available.
    if config is not None:
        obs = config.git_safety.observability
        if obs.decision_log_dir:
            from .decision_log import configure_decision_log
            configure_decision_log(
                log_dir=obs.decision_log_dir,
                max_bytes=obs.decision_log_max_bytes,
                backup_count=obs.decision_log_backup_count,
            )

    # Import here to avoid circular imports
    from .command_validation import validate_request
    from .operations import execute_git

    def _resolve_repo_root(sandbox_id: str, metadata: dict | None) -> str:
        if repo_root_resolver:
            return repo_root_resolver(sandbox_id, metadata)
        if metadata and metadata.get("repo_root"):
            return metadata["repo_root"]
        logger.error(
            "Sandbox %s has no repo_root in metadata — registration incomplete",
            sandbox_id,
        )
        return ""

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

    def _record_outcome(verb: str, sandbox_id: str, outcome: str) -> None:
        from .metrics import registry
        registry.inc_counter(
            "git_safety_operations_total",
            {"verb": verb, "sandbox": sandbox_id, "outcome": outcome},
        )

    def _git_exec_inner(clock_window: float, client_ip: str) -> Response:

        sandbox_id, auth_error = authenticate_request(
            request,
            secret_store=secrets,
            nonce_store=nonces,
            rate_limiter=limiter,
            clock_window=clock_window,
        )
        if auth_error is not None:
            _record_outcome("unknown", sandbox_id or "unknown", "error")
            return auth_error

        body = request.get_data()

        # Parse and validate request body
        try:
            raw = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            _record_outcome("unknown", sandbox_id, "error")
            return _make_error("Invalid JSON body", 400)

        req, err = validate_request(raw)
        if err or req is None:
            _record_outcome("unknown", sandbox_id, "error")
            return _make_error(err.reason if err else "Invalid request", 400)

        # Store verb for histogram labels
        from flask import g
        if req.args:
            g.git_verb = req.args[0] if req.args[0] != "git" else (req.args[1] if len(req.args) > 1 else "unknown")
        verb = getattr(g, "git_verb", "unknown")

        # Resolve metadata and repo root
        metadata = _load_sandbox_metadata(sandbox_id, resolved_data_dir)
        repo_root = _resolve_repo_root(sandbox_id, metadata)

        if not repo_root:
            _record_outcome(verb, sandbox_id, "error")
            return _make_error(
                f"Sandbox {sandbox_id} has no registered repo_root — "
                "re-register with `cast new` or check registration",
                400,
            )

        # Execute git command
        response, err = execute_git(req, repo_root, metadata)
        if err:
            _record_outcome(verb, sandbox_id, "deny")
            return _make_error(err.reason, 422)

        _record_outcome(verb, sandbox_id, "allow")
        return jsonify(response.to_dict())

    @app.route("/health", methods=["GET"])
    def health():
        from .config import load_foundry_config

        config_valid = True
        config_error = None
        try:
            load_foundry_config()
        except Exception as exc:
            config_valid = False
            config_error = str(exc)

        # Decision-log status
        log_check = _check_decision_log()

        status = "ok" if config_valid and log_check["ok"] else "degraded"
        return jsonify({
            "status": status,
            "config_valid": config_valid,
            "config_error": config_error,
            "logging": log_check,
            "uptime_seconds": round(time.time() - app._start_time, 2),
        })

    def _check_workspace(data_dir: str) -> dict:
        if not os.path.isdir(data_dir):
            return {"ok": False, "detail": f"Data directory missing: {data_dir}"}
        if not os.access(data_dir, os.W_OK):
            return {"ok": False, "detail": f"Data directory not writable: {data_dir}"}
        return {"ok": True, "detail": "Data directory accessible"}

    def _check_config() -> dict:
        try:
            from .config import load_foundry_config
            load_foundry_config()
            return {"ok": True, "detail": "Configuration valid"}
        except Exception as exc:
            return {"ok": False, "detail": str(exc)}

    def _check_secret_store(store: SecretStore) -> dict:
        secrets_path = getattr(store, "_path", None)
        if secrets_path and not os.path.isdir(secrets_path):
            return {"ok": False, "detail": f"Secrets directory missing: {secrets_path}"}
        return {"ok": True, "detail": "Secret store available"}

    def _check_decision_log() -> dict:
        from .decision_log import get_decision_log_writer

        try:
            writer = get_decision_log_writer()
            log_dir = str(writer._log_dir)
            test_entry = {"_health_check": True, "ts": time.time()}
            writer.write(test_entry)
            return {"ok": True, "detail": f"Decision log writable at {log_dir}"}
        except Exception as exc:
            return {"ok": False, "detail": f"Decision log write failed: {exc}"}

    @app.route("/ready", methods=["GET"])
    def ready():
        fatal_checks = {
            "workspace": _check_workspace(resolved_data_dir),
            "config": _check_config(),
            "secret_store": _check_secret_store(secrets),
        }
        # Decision log is non-fatal: degraded logging should not trigger
        # orchestration restarts.
        log_check = {"decision_log": _check_decision_log()}

        all_fatal_ok = all(c["ok"] for c in fatal_checks.values())
        checks = {**fatal_checks, **log_check}
        status = 200 if all_fatal_ok else 503
        return jsonify({"ready": all_fatal_ok, "checks": checks}), status

    @app.route("/metrics", methods=["GET"])
    def metrics():
        from .metrics import registry as metrics_registry
        content = metrics_registry.render_prometheus()
        return Response(content, content_type="text/plain; version=0.0.4; charset=utf-8")

    @app.route("/tamper-event", methods=["POST"])
    def tamper_event():
        """Record a wrapper tamper event.

        Always increments the Prometheus counter.  Writes to the decision
        log on a best-effort basis — a degraded log does not prevent the
        counter from being incremented.

        No HMAC auth: localhost-only (server binds 127.0.0.1), and the
        endpoint only records observability data.
        """
        from .metrics import registry as metrics_registry

        try:
            body = request.get_json(silent=True)
        except Exception:
            body = None

        if not body or not isinstance(body, dict):
            return _make_error("Invalid JSON body", 400)

        sandbox = body.get("sandbox", "")
        action = body.get("action", "")
        expected_sha = body.get("expected_sha256", "")
        actual_sha = body.get("actual_sha256", "")

        if not sandbox or not action:
            return _make_error("Missing required fields: sandbox, action", 400)

        # Always increment the counter.
        metrics_registry.inc_counter(
            "wrapper_tamper_events_total",
            {"sandbox": sandbox, "action": action},
        )

        # Best-effort decision log write.
        log_ok = True
        try:
            from .decision_log import write_decision
            write_decision(
                sandbox=sandbox,
                rule="wrapper_integrity",
                verb="wrapper_tamper",
                outcome=action,
                expected_sha256=expected_sha,
                actual_sha256=actual_sha,
            )
        except Exception as exc:
            log_ok = False
            logger.warning(
                "Tamper-event decision log write failed for %s: %s",
                sandbox, exc,
            )

        status = 200 if log_ok else 202
        return jsonify({"recorded": True, "log_written": log_ok}), status

    # Register user services proxy blueprint (if configured)
    try:
        from .user_services_proxy import create_user_services_blueprint

        entries = _resolved_user_services(config)
        if entries:
            bp = create_user_services_blueprint(
                entries,
                secret_store=secrets,
                nonce_store=nonces,
                rate_limiter=limiter,
            )
            app.register_blueprint(bp)
            logger.info("Registered %d user service proxy routes", len(entries))
    except Exception as exc:
        logger.debug("User services proxy not loaded: %s", exc)

    # Register deep policy proxy blueprint (if configured)
    try:
        from .config import load_foundry_config
        from .deep_policy_engine import CircuitBreaker, load_policy_sets
        from .deep_policy_proxy import create_deep_policy_blueprint

        cfg = config or load_foundry_config()
        deep_cfg = cfg.git_safety.deep_policy
        if deep_cfg and deep_cfg.enabled:
            policy_sets, dp_services = load_policy_sets(deep_cfg)
            if policy_sets:
                cb = CircuitBreaker(
                    threshold=deep_cfg.circuit_breaker_threshold,
                    recovery_seconds=deep_cfg.circuit_breaker_recovery_seconds,
                )
                dp_bp = create_deep_policy_blueprint(
                    policy_sets, dp_services,
                    secret_store=secrets, nonce_store=nonces,
                    rate_limiter=limiter, circuit_breaker=cb,
                )
                app.register_blueprint(dp_bp)
                logger.info(
                    "Registered deep policy proxy for %d services",
                    len(policy_sets),
                )
    except Exception as exc:
        logger.debug("Deep policy proxy not loaded: %s", exc)

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
