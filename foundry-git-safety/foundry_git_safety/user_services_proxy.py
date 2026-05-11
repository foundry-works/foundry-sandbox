"""Reverse-proxy blueprint for user-defined service credential injection.

Extends the foundry-git-safety Flask server with /proxy/<service>/<path>
routes. The sandbox talks HTTP to the proxy; the proxy reads the real API
key from the host environment, adds the configured header, and forwards
via HTTPS to the upstream service. No MITM, no custom CA.

All proxy routes require HMAC authentication. Health endpoints may be
protected by server admin auth.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qsl, urlencode

try:
    from flask import Blueprint, Response, jsonify, request
except ImportError as exc:
    raise ImportError(
        "Flask is required for the user services proxy. "
        "Install with: pip install foundry-git-safety[server]"
    ) from exc

from .auth import NonceStore, RateLimiter, SecretStore, authenticate_request
from .proxy_limits import (
    UPSTREAM_TIMEOUT_SECONDS,
    UpstreamResponseTooLarge,
    read_capped_response,
)
from .schemas.foundry_yaml import UserServiceEntry

logger = logging.getLogger(__name__)

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


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "unknown"


def _path_without_query(path: str) -> str:
    """Return a path safe for logs by dropping query parameters."""
    return path.split("?", 1)[0]


def _should_forward_header(name: str) -> bool:
    """Keep Foundry auth metadata inside the proxy trust boundary."""
    lower = name.lower()
    return (
        lower not in _HOP_BY_HOP
        and lower not in _INTERNAL_PROXY_HEADERS
        and lower != "host"
        and not lower.startswith("x-foundry-")
    )


def create_user_services_blueprint(
    services: list[UserServiceEntry],
    secret_store: SecretStore,
    nonce_store: NonceStore,
    rate_limiter: RateLimiter,
    data_dir: str | None = None,
    admin_auth: Callable[[], Response | tuple | None] | None = None,
) -> Blueprint:
    """Create a Flask Blueprint that reverse-proxies to declared services.

    All proxy routes require HMAC authentication. The health endpoint may be
    protected by server admin auth.
    """
    bp = Blueprint("user_services_proxy", __name__)

    slug_map: dict[str, UserServiceEntry] = {_slug(s.name): s for s in services}
    unrestricted_warnings: set[str] = set()

    def _warn_if_unrestricted(service_slug: str, svc: UserServiceEntry) -> None:
        if svc.allow_all:
            return

        missing: list[str] = []
        if not svc.methods:
            missing.append("methods")
        if not svc.paths:
            missing.append("paths")
        if not missing:
            return

        warning_key = f"{service_slug}:{','.join(missing)}"
        if warning_key in unrestricted_warnings:
            return
        unrestricted_warnings.add(warning_key)
        logger.warning(
            "Proxy service %s has unrestricted %s without allow_all=true; "
            "add explicit restrictions or mark the broad access intentionally",
            service_slug,
            " and ".join(missing),
        )

    def _load_sandbox_services(sandbox_id: str) -> dict[str, UserServiceEntry]:
        if not data_dir:
            return {}

        metadata_path = Path(data_dir) / "sandboxes" / f"{sandbox_id}.json"
        try:
            metadata = json.loads(metadata_path.read_text())
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return {}

        raw_services = metadata.get("user_services", [])
        if isinstance(raw_services, dict):
            candidates = list(raw_services.values())
        elif isinstance(raw_services, list):
            candidates = raw_services
        else:
            return {}

        result: dict[str, UserServiceEntry] = {}
        for raw in candidates:
            if not isinstance(raw, dict):
                continue
            try:
                entry = UserServiceEntry(**raw)
            except Exception as exc:
                logger.warning(
                    "Invalid proxy service metadata for sandbox %s: %s",
                    sandbox_id,
                    exc,
                )
                continue
            result[_slug(entry.name)] = entry
        return result

    @bp.route("/proxy/health", methods=["GET"])
    def proxy_health():
        if admin_auth is not None:
            auth_error = admin_auth()
            if auth_error is not None:
                return auth_error

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

        effective_services = dict(slug_map)
        effective_services.update(_load_sandbox_services(sandbox_id))

        svc = effective_services.get(service_slug)
        if svc is None:
            return jsonify({"error": f"Unknown service: {service_slug}"}), 404
        _warn_if_unrestricted(service_slug, svc)

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
                conn = http.client.HTTPSConnection(
                    svc.domain,
                    target_port,
                    timeout=UPSTREAM_TIMEOUT_SECONDS,
                )
            else:
                conn = http.client.HTTPConnection(
                    svc.domain,
                    target_port,
                    timeout=UPSTREAM_TIMEOUT_SECONDS,
                )
        except Exception as exc:
            logger.error("Failed to connect to %s: %s", svc.domain, exc)
            return jsonify({
                "error": f"Upstream connection failed: {svc.domain}",
            }), 502

        # Build headers — inject credential
        headers = {}
        for key, value in request.headers:
            if _should_forward_header(key):
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

        # Build response headers, stripping hop-by-hop
        resp_headers = [
            (k, v) for k, v in upstream_response.getheaders()
            if k.lower() not in _HOP_BY_HOP
        ]

        try:
            response_body = read_capped_response(upstream_response)
        except UpstreamResponseTooLarge:
            logger.warning(
                "Upstream response from %s exceeded size cap",
                svc.domain,
            )
            return jsonify({"error": "Upstream response too large"}), 502
        except Exception as exc:
            logger.error(
                "Reading upstream response from %s failed: %s",
                svc.domain,
                exc,
            )
            return jsonify({"error": f"Upstream response failed: {svc.domain}"}), 502
        finally:
            conn.close()

        logger.info(
            "Proxied %s %s/%s -> %s://%s%s (%d)",
            request.method, service_slug, upstream_path,
            svc.scheme, svc.domain, _path_without_query(full_path),
            upstream_response.status,
        )

        return Response(
            response_body, status=upstream_response.status, headers=resp_headers,
        )

    return bp
