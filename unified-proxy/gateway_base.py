"""Shared API gateway infrastructure — identity validation, header
filtering, upstream forwarding, and streaming response relay.

All three API gateways (Anthropic, OpenAI, GitHub) share identical logic
for container identity validation, header stripping, placeholder filtering,
upstream request forwarding with streaming, and error handling.  This module
provides a factory function ``create_gateway_app()`` that builds a fully
configured aiohttp Application given per-gateway configuration.

Each gateway module becomes a thin wrapper (~50 lines) that calls the
factory with its specific settings (upstream URL, credential loader,
routes, optional request hook).

Port allocation:
  :9848  Anthropic gateway (gateway.py)
  :9849  OpenAI gateway    (openai_gateway.py)
  :9850  GitHub gateway     (github_gateway.py)
"""

import asyncio
import json
import os
import sys
from typing import Callable, Optional, Sequence, Tuple

import aiohttp
from aiohttp import web

# ---------------------------------------------------------------------------
# Ensure /opt/proxy is on sys.path so imports work inside the container
# ---------------------------------------------------------------------------
_PROXY_DIR = "/opt/proxy"
if _PROXY_DIR not in sys.path:
    sys.path.insert(0, _PROXY_DIR)

from gateway_middleware import create_gateway_middlewares, set_container_id  # noqa: E402
from logging_config import get_logger  # noqa: E402
from registry import ContainerRegistry  # noqa: E402

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants (previously duplicated in each gateway)
# ---------------------------------------------------------------------------

# Headers that must not be forwarded from the sandbox to the upstream.
# The gateway injects real credentials; sandbox-supplied values are stripped.
# Connection-hop headers must not be forwarded per RFC 7230 §6.1.
_BASE_STRIPPED_HEADERS = frozenset({
    "authorization",
    "host",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
})

# Hop-by-hop headers that must not be forwarded in upstream responses.
_HOP_BY_HOP = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})

# Marker strings in header values that indicate sandbox placeholder
# credentials which must be filtered out.
_PLACEHOLDER_MARKERS = ("CRED_PROXY_", "CREDENTIAL_PROXY_PLACEHOLDER")

# Default registry database path (shared with other proxy components).
DEFAULT_REGISTRY_DB_PATH = os.environ.get(
    "REGISTRY_DB_PATH", "/var/lib/unified-proxy/registry.db"
)

# ---------------------------------------------------------------------------
# Types for gateway configuration
# ---------------------------------------------------------------------------

# A request hook receives (request, method, body, container_id) and returns
# an optional web.Response.  If it returns a response, the request is
# short-circuited (e.g., policy violation).  If it returns None, forwarding
# proceeds.
RequestHook = Callable[
    [web.Request, str, bytes, str],
    "asyncio.coroutine",  # actually returns Optional[web.Response]
]

# Route: (methods_str, path_pattern) — methods_str is "*" for catch-all or
# a specific method like "GET".
Route = Tuple[str, str]


# ---------------------------------------------------------------------------
# JSON error helpers
# ---------------------------------------------------------------------------

def gateway_error(status: int, message: str) -> web.Response:
    """Return a JSON error response matching the gateway error contract."""
    body = json.dumps({"error": {"type": "gateway_error", "message": message}})
    return web.Response(
        status=status,
        body=body.encode(),
        content_type="application/json",
    )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_gateway_app(
    *,
    upstream_base_url: str,
    upstream_host: str,
    service_name: str,
    credential_loader: Callable[[], Optional[dict]],
    routes: Sequence[Route],
    port: int,
    bind: str = "0.0.0.0",
    max_request_body: int = 32 * 1024 * 1024,
    connect_timeout: int = 30,
    total_timeout: int = 600,
    credential_required: bool = True,
    extra_stripped_headers: frozenset = frozenset(),
    request_hook: Optional[Callable] = None,
    app_state_hook: Optional[Callable[[web.Application], None]] = None,
    registry: Optional[ContainerRegistry] = None,
) -> web.Application:
    """Create a fully configured aiohttp Application for an API gateway.

    Args:
        upstream_base_url: Full URL of the upstream API (e.g., "https://api.anthropic.com").
        upstream_host: Hostname for the Host header (e.g., "api.anthropic.com").
        service_name: Name for health check and logging (e.g., "anthropic-gateway").
        credential_loader: Callable that returns a dict with 'header' and 'value'
                           keys, or None if no credential is available.
        routes: List of (method, path) tuples to register. Use ("*", "/path") for
                catch-all. Health check at /health is always registered.
        port: Listen port (stored on app for reference; caller runs the app).
        bind: Bind address (stored on app for reference).
        max_request_body: Maximum request body size in bytes.
        connect_timeout: Upstream connection timeout in seconds.
        total_timeout: Upstream total request timeout in seconds.
        credential_required: If True, requests fail 502 when no credential is
                             configured. If False (e.g., GitHub), unauthenticated
                             requests are forwarded.
        extra_stripped_headers: Additional headers to strip beyond the base set.
        request_hook: Optional async callable(request, method, body, container_id)
                      that returns Optional[web.Response]. Called after identity
                      validation, before upstream forwarding.
        app_state_hook: Optional callable(app) to set additional app state after
                        credential loading (e.g., custom_headers for Anthropic).
        registry: Optional ContainerRegistry instance.

    Returns:
        Configured aiohttp Application ready to be run.
    """
    stripped_headers = _BASE_STRIPPED_HEADERS | extra_stripped_headers

    middlewares = create_gateway_middlewares(upstream_host)
    app = web.Application(
        client_max_size=max_request_body,
        middlewares=middlewares,
    )

    # --- Shared state -------------------------------------------------
    app["registry"] = registry or ContainerRegistry(
        db_path=DEFAULT_REGISTRY_DB_PATH
    )
    app["credential"] = credential_loader()
    app["_gw_upstream_base_url"] = upstream_base_url
    app["_gw_upstream_host"] = upstream_host
    app["_gw_service_name"] = service_name
    app["_gw_connect_timeout"] = connect_timeout
    app["_gw_total_timeout"] = total_timeout
    app["_gw_credential_required"] = credential_required
    app["_gw_stripped_headers"] = stripped_headers
    app["_gw_request_hook"] = request_hook

    if app_state_hook:
        app_state_hook(app)

    if app["credential"]:
        header_name = app["credential"]["header"]
        logger.info(f"{service_name}: credential loaded (header: {header_name})")
    else:
        if credential_required:
            logger.warning(f"{service_name}: no credential found")
        else:
            logger.warning(
                f"{service_name}: no credential found — "
                f"unauthenticated requests will be forwarded"
            )

    # --- Routes -------------------------------------------------------
    app.router.add_get("/health", _health)
    for method_str, path_pattern in routes:
        app.router.add_route(method_str, path_pattern, _proxy_request)

    # --- Lifecycle hooks ----------------------------------------------
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)

    return app


# ---------------------------------------------------------------------------
# Shared request handler
# ---------------------------------------------------------------------------

async def _proxy_request(request: web.Request) -> web.StreamResponse:
    """Forward an API request to the upstream and stream the response."""
    app = request.app
    registry: ContainerRegistry = app["registry"]
    credential: Optional[dict] = app["credential"]
    upstream_session: aiohttp.ClientSession = app["upstream_session"]
    upstream_base_url: str = app["_gw_upstream_base_url"]
    upstream_host: str = app["_gw_upstream_host"]
    service_name: str = app["_gw_service_name"]
    connect_timeout: int = app["_gw_connect_timeout"]
    total_timeout: int = app["_gw_total_timeout"]
    credential_required: bool = app["_gw_credential_required"]
    stripped_headers: frozenset = app["_gw_stripped_headers"]
    request_hook = app["_gw_request_hook"]

    # --- 1. Validate container identity -------------------------------
    peername = request.remote
    if not peername:
        logger.warning(f"{service_name}: request with no remote address")
        return gateway_error(403, "Unable to determine request source")

    container = registry.get_by_ip(peername)
    if container is None:
        logger.warning(f"{service_name}: unknown source IP: {peername}")
        return gateway_error(403, "Unknown container — not registered")
    if container.is_expired:
        logger.warning(
            f"{service_name}: expired container: "
            f"{container.container_id} (IP {peername})"
        )
        return gateway_error(403, "Container registration expired")

    container_id = container.container_id
    set_container_id(request, container_id)

    # --- 2. Check credential availability -----------------------------
    if credential is None and credential_required:
        logger.error(
            f"{service_name}: no credential configured "
            f"(container: {container_id})"
        )
        return gateway_error(
            502, f"{service_name.split('-')[0].capitalize()} "
                 f"credential not configured on gateway"
        )

    # --- 3. Read body and run request hook ----------------------------
    method = request.method.upper()
    body = await request.read()

    if request_hook is not None:
        hook_response = await request_hook(request, method, body, container_id)
        if hook_response is not None:
            return hook_response

    # --- 4. Build upstream request ------------------------------------
    upstream_path = request.path
    if request.query_string:
        upstream_path = f"{upstream_path}?{request.query_string}"
    upstream_url = f"{upstream_base_url}{upstream_path}"

    # Build headers: forward safe headers, inject credential.
    upstream_headers: dict[str, str] = {}
    for name, value in request.headers.items():
        if name.lower() not in stripped_headers:
            if any(marker in value for marker in _PLACEHOLDER_MARKERS):
                continue
            upstream_headers[name] = value

    # Inject credential (if available)
    if credential is not None:
        upstream_headers[credential["header"]] = credential["value"]
    elif not credential_required:
        logger.info(
            f"{service_name}: forwarding unauthenticated "
            f"{method} {request.path} (container: {container_id})"
        )

    # Inject extra headers from app state (e.g., Anthropic custom headers)
    custom_headers = app.get("custom_headers", [])
    for h_name, h_value in custom_headers:
        upstream_headers[h_name] = h_value

    upstream_headers["Host"] = upstream_host

    logger.info(
        f"{service_name}: forwarding {method} {request.path} -> "
        f"{upstream_url} (container: {container_id})"
    )

    # --- 5. Forward to upstream and stream response -------------------
    try:
        timeout = aiohttp.ClientTimeout(
            total=total_timeout,
            connect=connect_timeout,
        )
        async with upstream_session.request(
            method=request.method,
            url=upstream_url,
            headers=upstream_headers,
            data=body,
            timeout=timeout,
            auto_decompress=True,
        ) as upstream_resp:
            response = web.StreamResponse(
                status=upstream_resp.status,
                reason=upstream_resp.reason,
            )

            for name, value in upstream_resp.headers.items():
                if name.lower() not in _HOP_BY_HOP:
                    response.headers[name] = value

            await response.prepare(request)

            async for chunk in upstream_resp.content.iter_any():
                await response.write(chunk)

            await response.write_eof()

            logger.info(
                f"{service_name}: completed {method} {request.path} -> "
                f"{upstream_resp.status} (container: {container_id})"
            )
            return response

    except asyncio.TimeoutError:
        logger.error(
            f"{service_name}: upstream timeout for {method} {request.path} "
            f"(container: {container_id})"
        )
        return gateway_error(504, "Upstream request timed out")
    except aiohttp.ClientConnectorError as exc:
        logger.error(
            f"{service_name}: upstream connection error for "
            f"{method} {request.path}: {exc} (container: {container_id})"
        )
        return gateway_error(502, f"Cannot connect to upstream: {exc}")
    except aiohttp.ClientError as exc:
        logger.error(
            f"{service_name}: upstream client error for "
            f"{method} {request.path}: {exc} (container: {container_id})"
        )
        return gateway_error(502, f"Upstream error: {exc}")
    except ConnectionResetError:
        logger.info(
            f"{service_name}: client disconnected during "
            f"{method} {request.path} (container: {container_id})"
        )
        return web.Response(status=499)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

async def _health(request: web.Request) -> web.Response:
    """Health check endpoint."""
    service_name = request.app.get("_gw_service_name", "gateway")
    return web.json_response({"status": "ok", "service": service_name})


# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------

async def _on_startup(app: web.Application) -> None:
    """Initialize shared resources when the server starts."""
    connector = aiohttp.TCPConnector(
        limit=100,
        limit_per_host=50,
        enable_cleanup_closed=True,
        keepalive_timeout=30,
    )
    app["upstream_session"] = aiohttp.ClientSession(connector=connector)
    service_name = app.get("_gw_service_name", "gateway")
    logger.info(f"{service_name}: upstream HTTP session created")


async def _on_cleanup(app: web.Application) -> None:
    """Clean up shared resources on shutdown."""
    service_name = app.get("_gw_service_name", "gateway")

    session: aiohttp.ClientSession = app.get("upstream_session")
    if session:
        await session.close()
        logger.info(f"{service_name}: upstream HTTP session closed")

    registry: ContainerRegistry = app.get("registry")
    if registry:
        registry.close()
        logger.info(f"{service_name}: container registry closed")


# ---------------------------------------------------------------------------
# Runner helper
# ---------------------------------------------------------------------------

def run_gateway(
    app: web.Application,
    host: str,
    port: int,
) -> None:
    """Run a gateway server (blocking).

    Args:
        app: Configured aiohttp Application from create_gateway_app().
        host: Bind address.
        port: Listen port.
    """
    service_name = app.get("_gw_service_name", "gateway")
    logger.info(f"Starting {service_name} on {host}:{port}")
    web.run_app(
        app,
        host=host,
        port=port,
        print=None,
        shutdown_timeout=10.0,
    )
