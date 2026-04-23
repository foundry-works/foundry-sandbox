"""Reverse-proxy blueprint for user-defined service credential injection.

Extends the foundry-git-safety Flask server with /proxy/<service>/<path>
routes. The sandbox talks HTTP to the proxy; the proxy reads the real API
key from the host environment, adds the configured header, and forwards
via HTTPS to the upstream service. No MITM, no custom CA.

All proxy routes require HMAC authentication. Health endpoints remain
unauthenticated.
"""

from __future__ import annotations

import http.client
import logging
import os
import re
from fnmatch import fnmatch
from urllib.parse import parse_qsl, urlencode

try:
    from flask import Blueprint, Response, jsonify, request
except ImportError as exc:
    raise ImportError(
        "Flask is required for the user services proxy. "
        "Install with: pip install foundry-git-safety[server]"
    ) from exc

from .auth import NonceStore, RateLimiter, SecretStore, authenticate_request
from .schemas.foundry_yaml import UserServiceEntry

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 64 * 1024  # 64 KiB

_HOP_BY_HOP = frozenset({
    "transfer-encoding", "connection", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "upgrade",
    "content-length",
})


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "unknown"


def create_user_services_blueprint(
    services: list[UserServiceEntry],
    secret_store: SecretStore,
    nonce_store: NonceStore,
    rate_limiter: RateLimiter,
) -> Blueprint:
    """Create a Flask Blueprint that reverse-proxies to declared services.

    All proxy routes require HMAC authentication. The health endpoint
    remains unauthenticated.
    """
    bp = Blueprint("user_services_proxy", __name__)

    slug_map: dict[str, UserServiceEntry] = {_slug(s.name): s for s in services}

    @bp.route("/proxy/health", methods=["GET"])
    def proxy_health():
        result = []
        for slug, svc in sorted(slug_map.items()):
            key_present = bool(os.environ.get(svc.env_var, ""))
            result.append({
                "slug": slug,
                "name": svc.name,
                "domain": svc.domain,
                "key_present": key_present,
            })
        return jsonify({"services": result})

    @bp.route("/proxy/<service_slug>/<path:upstream_path>", methods=[
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
    ])
    def proxy_request(service_slug: str, upstream_path: str):
        # HMAC authentication
        sandbox_id, auth_error = authenticate_request(
            request,
            secret_store=secret_store,
            nonce_store=nonce_store,
            rate_limiter=rate_limiter,
        )
        if auth_error is not None:
            return auth_error

        svc = slug_map.get(service_slug)
        if svc is None:
            return jsonify({"error": f"Unknown service: {service_slug}"}), 404

        # Method filtering
        if svc.methods:
            allowed_methods = [m.upper() for m in svc.methods]
            if request.method.upper() not in allowed_methods:
                return jsonify({
                    "error": (
                        f"Method {request.method} not allowed for {svc.name}. "
                        f"Allowed: {', '.join(allowed_methods)}"
                    ),
                }), 405

        # Path filtering
        if svc.paths:
            if not any(fnmatch(f"/{upstream_path}", p) for p in svc.paths):
                return jsonify({
                    "error": f"Path /{upstream_path} not allowed for {svc.name}",
                }), 403

        # Read credential from host environment
        api_key = os.environ.get(svc.env_var, "")
        if not api_key:
            logger.error(
                "Missing API key for %s (env var: %s)", svc.name, svc.env_var,
            )
            return jsonify({
                "error": (
                    f"API key not configured for {svc.name}. "
                    f"Set {svc.env_var} on the host."
                ),
            }), 503

        # Build upstream connection
        target_port = svc.port or (443 if svc.scheme == "https" else 80)
        try:
            if svc.scheme == "https":
                conn = http.client.HTTPSConnection(svc.domain, target_port)
            else:
                conn = http.client.HTTPConnection(svc.domain, target_port)
        except Exception as exc:
            logger.error("Failed to connect to %s: %s", svc.domain, exc)
            return jsonify({
                "error": f"Upstream connection failed: {svc.domain}",
            }), 502

        # Build headers — inject credential
        headers = {}
        for key, value in request.headers:
            if key.lower() not in _HOP_BY_HOP and key.lower() != "host":
                headers[key] = value
        headers["Host"] = svc.domain

        # Inject the credential using the configured transport.
        if svc.format == "bearer":
            headers[svc.header] = f"Bearer {api_key}"
        elif svc.format == "header":
            headers[svc.header] = api_key

        # Preserve query string and optionally inject the key there.
        full_path = f"/{upstream_path}"
        query_pairs = parse_qsl(
            request.query_string.decode(),
            keep_blank_values=True,
        )
        if svc.format == "query":
            query_pairs.append((svc.header, api_key))
        if query_pairs:
            full_path += f"?{urlencode(query_pairs)}"

        # Read request body
        body = request.get_data() or None

        try:
            conn.request(request.method, full_path, body=body, headers=headers)
            upstream_response = conn.getresponse()
        except Exception as exc:
            logger.error("Upstream request to %s failed: %s", svc.domain, exc)
            return jsonify({
                "error": f"Upstream request failed: {svc.domain}",
            }), 502

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

        # Build response headers, stripping hop-by-hop
        resp_headers = [
            (k, v) for k, v in upstream_response.getheaders()
            if k.lower() not in _HOP_BY_HOP
        ]

        logger.info(
            "Proxied %s %s/%s -> %s://%s%s (%d)",
            request.method, service_slug, upstream_path,
            svc.scheme, svc.domain, full_path, upstream_response.status,
        )

        return Response(
            generate(), status=upstream_response.status, headers=resp_headers,
        )

    return bp
