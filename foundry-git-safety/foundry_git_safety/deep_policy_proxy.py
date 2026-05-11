"""Deep policy sidecar Flask Blueprint.

Provides /deep-policy/<service_slug>/<path> routes that evaluate request-shape
policies (method, path, body patterns) before forwarding to upstream services.
Includes HMAC authentication, per-sandbox rate limiting (via verified identity),
and per-service circuit breaking.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

try:
    from flask import Blueprint, Response, jsonify, request
except ImportError as exc:
    raise ImportError(
        "Flask is required for the deep policy proxy. "
        "Install with: pip install foundry-git-safety[server]"
    ) from exc

from .auth import NonceStore, RateLimiter, SecretStore, authenticate_request
from .deep_policy_engine import CircuitBreaker, PolicySet
from .proxy_limits import (
    UPSTREAM_TIMEOUT_SECONDS,
    UpstreamResponseTooLarge,
    read_capped_response,
)
from .security_policies import (
    check_github_blocklist,
    check_github_body_policies,
    is_merge_request,
    normalize_path,
)
from .schemas.foundry_yaml import DeepPolicyServiceConfig

logger = logging.getLogger(__name__)

_FOUNDRY_BASE = os.path.expanduser("~/.foundry")
_DEFAULT_DATA_DIR = os.environ.get(
    "FOUNDRY_DATA_DIR", f"{_FOUNDRY_BASE}/data/git-safety"
)

_HOP_BY_HOP = frozenset({
    "transfer-encoding", "connection", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "upgrade",
    "content-length",
})

_INTERNAL_PROXY_HEADERS = frozenset({
    "x-sandbox-id",
    "x-request-signature",
    "x-request-timestamp",
    "x-request-nonce",
})


def _should_forward_header(name: str) -> bool:
    """Keep Foundry auth metadata inside the proxy trust boundary."""
    lower = name.lower()
    return (
        lower not in _HOP_BY_HOP
        and lower not in _INTERNAL_PROXY_HEADERS
        and lower != "host"
        and not lower.startswith("x-foundry-")
    )


def _raw_upstream_path(service_slug: str, fallback_path: str) -> str:
    """Return the raw upstream path from WSGI metadata when available.

    Flask path converters expose a decoded route value, which is too late for
    double-encoding checks. RAW_URI/REQUEST_URI preserve the original path.
    """
    raw_uri = request.environ.get("RAW_URI") or request.environ.get("REQUEST_URI")
    if not raw_uri:
        return fallback_path

    raw_path = urlsplit(raw_uri).path
    prefix = f"/deep-policy/{service_slug}/"
    if not raw_path.startswith(prefix):
        return fallback_path

    return "/" + raw_path[len(prefix):]


def _load_policy_context(sandbox_id: str) -> dict[str, str]:
    """Load conditional-rule context for a verified sandbox.

    Today this is just PR policy, exposed under both the legacy
    `allow_pr` key and the foundry.yaml-facing `allow_pr_operations` key.
    """
    data_dir = os.environ.get("FOUNDRY_DATA_DIR", _DEFAULT_DATA_DIR)
    metadata_path = Path(data_dir) / "sandboxes" / f"{sandbox_id}.json"

    try:
        metadata = json.loads(metadata_path.read_text())
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}

    allow_pr = metadata.get("allow_pr")
    if not isinstance(allow_pr, bool):
        return {}

    value = "true" if allow_pr else "false"
    return {
        "allow_pr": value,
        "allow_pr_operations": value,
    }


def create_deep_policy_blueprint(
    policy_sets: dict[str, PolicySet],
    services: dict[str, DeepPolicyServiceConfig],
    secret_store: SecretStore,
    nonce_store: NonceStore,
    rate_limiter: RateLimiter,
    circuit_breaker: CircuitBreaker,
    context_resolver: Callable[[str], dict[str, str]] | None = None,
    admin_auth: Callable[[], Response | tuple | None] | None = None,
) -> Blueprint:
    """Create a Flask Blueprint that proxies with deep policy enforcement.

    All proxy routes require HMAC authentication. Identity for rate limiting
    is derived from the verified sandbox_id, not from caller-supplied headers.
    The health endpoint may be protected by server admin auth.
    """
    bp = Blueprint("deep_policy_proxy", __name__)
    resolve_context = context_resolver or _load_policy_context

    @bp.route("/deep-policy/health", methods=["GET"])
    def deep_policy_health():
        if admin_auth is not None:
            auth_error = admin_auth()
            if auth_error is not None:
                return auth_error

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

        # Build evaluation context from sandbox metadata.
        try:
            context = resolve_context(sandbox_id) or {}
        except Exception as exc:
            logger.warning(
                "Failed to load deep-policy context for %s: %s",
                sandbox_id,
                exc,
            )
            context = {}

        # Policy evaluation
        full_path = f"/{upstream_path}"
        if request.query_string:
            full_path += f"?{request.query_string.decode()}"

        # Use path without query for policy matching
        path_for_eval = f"/{upstream_path}"

        if service_slug == "github" or ps.host == "api.github.com":
            normalized_path = normalize_path(
                _raw_upstream_path(service_slug, path_for_eval)
            )
            if normalized_path is None:
                return _blocked("Malformed or double-encoded GitHub API path")

            if is_merge_request(normalized_path, body or b""):
                return _blocked("GitHub PR merge operations are blocked by policy")

            reason = check_github_blocklist(request.method.upper(), normalized_path)
            if reason:
                return _blocked(reason)

            reason = check_github_body_policies(
                request.method.upper(),
                normalized_path,
                body,
                request.headers.get("Content-Type", ""),
                request.headers.get("Content-Encoding", ""),
            )
            if reason:
                return _blocked(reason)

            path_for_eval = normalized_path

        allowed, reason = ps.evaluate(
            method=request.method,
            path=path_for_eval,
            body=body,
            context=context,
        )

        if not allowed:
            return _blocked(reason or "Request denied by policy")

        # Forward to upstream
        if not ps.host:
            return jsonify({"error": f"No upstream host configured for {service_slug}"}), 502

        target_port = ps.port or (443 if ps.scheme == "https" else 80)
        try:
            if ps.scheme == "https":
                conn = http.client.HTTPSConnection(
                    ps.host,
                    target_port,
                    timeout=UPSTREAM_TIMEOUT_SECONDS,
                )
            else:
                conn = http.client.HTTPConnection(
                    ps.host,
                    target_port,
                    timeout=UPSTREAM_TIMEOUT_SECONDS,
                )
        except Exception as exc:
            logger.error("Failed to connect to %s: %s", ps.host, exc)
            circuit_breaker.record_failure(service_slug)
            return jsonify({"error": f"Upstream connection failed: {ps.host}"}), 502

        # Build headers
        headers = {}
        for key, value in request.headers:
            if _should_forward_header(key):
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

        resp_headers = [
            (k, v) for k, v in upstream_response.getheaders()
            if k.lower() not in _HOP_BY_HOP
        ]

        try:
            response_body = read_capped_response(upstream_response)
        except UpstreamResponseTooLarge:
            logger.warning("Upstream response from %s exceeded size cap", ps.host)
            circuit_breaker.record_failure(service_slug)
            return jsonify({"error": "Upstream response too large"}), 502
        except Exception as exc:
            logger.error("Reading upstream response from %s failed: %s", ps.host, exc)
            circuit_breaker.record_failure(service_slug)
            return jsonify({"error": f"Upstream response failed: {ps.host}"}), 502
        finally:
            conn.close()

        logger.info(
            "Proxied %s %s/%s -> %s://%s%s (%d)",
            request.method, service_slug, upstream_path,
            ps.scheme, ps.host, full_path, upstream_response.status,
        )

        return Response(
            response_body, status=upstream_response.status, headers=resp_headers,
        )

    def _blocked(reason: str):
        logger.warning(
            "BLOCKED deep policy: %s %s/%s - %s",
            request.method, request.view_args.get("service_slug", ""),
            request.view_args.get("upstream_path", ""), reason,
        )
        resp = jsonify({
            "error": "BLOCKED",
            "message": reason,
        })
        resp.headers["X-Sandbox-Blocked"] = "true"
        return resp, 403

    return bp
