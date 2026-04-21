"""Deep policy sidecar Flask Blueprint.

Provides /deep-policy/<service_slug>/<path> routes that evaluate request-shape
policies (method, path, body patterns) before forwarding to upstream services.
Includes HMAC authentication, per-sandbox rate limiting (via verified identity),
and per-service circuit breaking.
"""

from __future__ import annotations

import http.client
import logging

try:
    from flask import Blueprint, Response, jsonify, request
except ImportError as exc:
    raise ImportError(
        "Flask is required for the deep policy proxy. "
        "Install with: pip install foundry-git-safety[server]"
    ) from exc

from .auth import NonceStore, RateLimiter, SecretStore, authenticate_request
from .deep_policy_engine import CircuitBreaker, PolicySet
from .schemas.foundry_yaml import DeepPolicyServiceConfig

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 64 * 1024  # 64 KiB

_HOP_BY_HOP = frozenset({
    "transfer-encoding", "connection", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "upgrade",
    "content-length",
})


def create_deep_policy_blueprint(
    policy_sets: dict[str, PolicySet],
    services: dict[str, DeepPolicyServiceConfig],
    secret_store: SecretStore,
    nonce_store: NonceStore,
    rate_limiter: RateLimiter,
    circuit_breaker: CircuitBreaker,
) -> Blueprint:
    """Create a Flask Blueprint that proxies with deep policy enforcement.

    All proxy routes require HMAC authentication. Identity for rate limiting
    is derived from the verified sandbox_id, not from caller-supplied headers.
    The health endpoint remains unauthenticated.
    """
    bp = Blueprint("deep_policy_proxy", __name__)

    @bp.route("/deep-policy/health", methods=["GET"])
    def deep_policy_health():
        result = []
        for slug, ps in sorted(policy_sets.items()):
            result.append({
                "slug": slug,
                "host": ps.host,
                "rule_count": ps.rule_count,
                "default_action": ps.default_action,
                "circuit_breaker_state": circuit_breaker.get_state(slug),
            })
        return jsonify({"services": result})

    @bp.route(
        "/deep-policy/<service_slug>/<path:upstream_path>",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )
    def deep_policy_proxy(service_slug: str, upstream_path: str):
        # HMAC authentication — verified sandbox identity
        sandbox_id, auth_error = authenticate_request(
            request,
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        if auth_error is not None:
            return auth_error

        ps = policy_sets.get(service_slug)
        if ps is None:
            return jsonify({"error": f"Unknown service: {service_slug}"}), 404

        # Circuit breaker
        if circuit_breaker.is_open(service_slug):
            return jsonify({
                "error": f"Service {service_slug} is circuit-broken (upstream failures)",
            }), 503

        # Read body
        body = request.get_data() or None

        # Build evaluation context from config
        context: dict[str, str] = {}

        # Policy evaluation
        full_path = f"/{upstream_path}"
        if request.query_string:
            full_path += f"?{request.query_string.decode()}"

        # Use path without query for policy matching
        path_for_eval = f"/{upstream_path}"

        allowed, reason = ps.evaluate(
            method=request.method,
            path=path_for_eval,
            body=body,
            context=context,
        )

        if not allowed:
            logger.warning(
                "BLOCKED deep policy: %s %s/%s - %s",
                request.method, service_slug, upstream_path, reason,
            )
            resp = jsonify({
                "error": "BLOCKED",
                "message": reason,
            })
            resp.headers["X-Sandbox-Blocked"] = "true"
            return resp, 403

        # Forward to upstream
        if not ps.host:
            return jsonify({"error": f"No upstream host configured for {service_slug}"}), 502

        target_port = ps.port or (443 if ps.scheme == "https" else 80)
        try:
            if ps.scheme == "https":
                conn = http.client.HTTPSConnection(ps.host, target_port)
            else:
                conn = http.client.HTTPConnection(ps.host, target_port)
        except Exception as exc:
            logger.error("Failed to connect to %s: %s", ps.host, exc)
            circuit_breaker.record_failure(service_slug)
            return jsonify({"error": f"Upstream connection failed: {ps.host}"}), 502

        # Build headers
        headers = {}
        for key, value in request.headers:
            if key.lower() not in _HOP_BY_HOP and key.lower() != "host":
                headers[key] = value
        headers["Host"] = ps.host

        try:
            conn.request(request.method, full_path, body=body, headers=headers)
            upstream_response = conn.getresponse()
        except Exception as exc:
            logger.error("Upstream request to %s failed: %s", ps.host, exc)
            circuit_breaker.record_failure(service_slug)
            return jsonify({"error": f"Upstream request failed: {ps.host}"}), 502

        # Circuit breaker: record success or failure based on upstream status
        if upstream_response.status >= 500:
            circuit_breaker.record_failure(service_slug)
        else:
            circuit_breaker.record_success(service_slug)

        # Stream response back
        def generate():
            try:
                while True:
                    chunk = upstream_response.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    yield chunk
            finally:
                conn.close()

        resp_headers = [
            (k, v) for k, v in upstream_response.getheaders()
            if k.lower() not in _HOP_BY_HOP
        ]

        logger.info(
            "Proxied %s %s/%s -> %s://%s%s (%d)",
            request.method, service_slug, upstream_path,
            ps.scheme, ps.host, full_path, upstream_response.status,
        )

        return Response(
            generate(), status=upstream_response.status, headers=resp_headers,
        )

    return bp
