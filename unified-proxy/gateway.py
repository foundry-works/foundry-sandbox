"""Anthropic API Gateway — plaintext HTTP relay with credential injection.

Accepts plaintext HTTP from sandboxes on the internal Docker network,
validates container identity, injects API credentials, and forwards to
https://api.anthropic.com over HTTPS.  Streams SSE responses back
chunk-by-chunk without buffering.

Port allocation:
  :9848  Anthropic gateway (this module)
  :9849  OpenAI gateway   (openai_gateway.py)
  :9850  GitHub gateway    (github_gateway.py)

Error contract:
  - Upstream 4xx/5xx: proxy response body and status code transparently.
  - Upstream unreachable: 502 {"error":{"type":"gateway_error","message":"..."}}
  - Gateway timeout:      504 {"error":{"type":"gateway_error","message":"..."}}
  - Identity failure:     403 {"error":{"type":"gateway_error","message":"..."}}
"""

import asyncio
import json
import os
import re
import sys
from typing import Optional

import aiohttp
from aiohttp import web

# ---------------------------------------------------------------------------
# Ensure /opt/proxy is on sys.path so imports work inside the container
# ---------------------------------------------------------------------------
_PROXY_DIR = "/opt/proxy"
if _PROXY_DIR not in sys.path:
    sys.path.insert(0, _PROXY_DIR)

from gateway_middleware import create_gateway_middlewares, set_container_id  # noqa: E402
from logging_config import get_logger, setup_logging  # noqa: E402
from registry import ContainerRegistry  # noqa: E402

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "9848"))
GATEWAY_BIND = os.environ.get("GATEWAY_BIND", "0.0.0.0")

UPSTREAM_BASE_URL = "https://api.anthropic.com"

# Timeout for connecting to the upstream API (seconds).
UPSTREAM_CONNECT_TIMEOUT = 30
# Total timeout is intentionally very long — tool-use responses from
# the Anthropic API can take minutes.
UPSTREAM_TOTAL_TIMEOUT = 600  # 10 minutes

# Maximum request body size (same as Claude API limit).
MAX_REQUEST_BODY = 32 * 1024 * 1024  # 32 MB

# Registry database path (shared with other proxy components).
REGISTRY_DB_PATH = os.environ.get(
    "REGISTRY_DB_PATH", "/var/lib/unified-proxy/registry.db"
)

# Header names that must not be forwarded from the sandbox.
# The gateway injects the real credential; sandbox-supplied values are stripped.
_STRIPPED_HEADERS = frozenset({
    "x-api-key",
    "authorization",
    # Connection-hop headers that must not be forwarded (RFC 7230 §6.1)
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

# Reserved header names that custom headers must not override.
_RESERVED_HEADER_NAMES = frozenset({"x-api-key", "authorization"})


# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------

def _load_anthropic_credential() -> Optional[dict]:
    """Load the Anthropic API credential from environment variables.

    Priority order (matches credential_injector.py):
      1. CLAUDE_CODE_OAUTH_TOKEN  → Authorization: Bearer <token>
      2. ANTHROPIC_API_KEY        → x-api-key: <key>

    Returns dict with 'header' and 'value' keys, or None.
    """
    oauth_token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "").strip()
    if oauth_token:
        return {"header": "Authorization", "value": f"Bearer {oauth_token}"}

    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if api_key:
        return {"header": "x-api-key", "value": api_key}

    return None


def _parse_custom_headers(raw: str) -> list[tuple[str, str]]:
    """Parse ANTHROPIC_CUSTOM_HEADERS env var into (name, value) pairs.

    Mirrors the logic in credential_injector.py.
    """
    if not raw:
        return []
    headers: list[tuple[str, str]] = []
    for entry in re.split(r"[,\n]", raw):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        name, _, value = entry.partition(":")
        name = name.strip()
        if name.lower() in _RESERVED_HEADER_NAMES:
            logger.warning(
                f"Ignoring custom header '{name}': conflicts with credential injection"
            )
            continue
        headers.append((name, value.strip()))
    return headers


# ---------------------------------------------------------------------------
# JSON error helpers
# ---------------------------------------------------------------------------

def _gateway_error(status: int, message: str) -> web.Response:
    """Return a JSON error response matching the gateway error contract."""
    body = json.dumps({"error": {"type": "gateway_error", "message": message}})
    return web.Response(
        status=status,
        body=body.encode(),
        content_type="application/json",
    )


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

async def _proxy_request(request: web.Request) -> web.StreamResponse:
    """Forward an Anthropic API request to the upstream and stream the response."""

    app = request.app
    registry: ContainerRegistry = app["registry"]
    credential: Optional[dict] = app["credential"]
    custom_headers: list[tuple[str, str]] = app["custom_headers"]
    upstream_session: aiohttp.ClientSession = app["upstream_session"]

    # --- 1. Validate container identity -----------------------------------
    peername = request.remote
    if not peername:
        logger.warning("Request with no remote address")
        return _gateway_error(403, "Unable to determine request source")

    container = registry.get_by_ip(peername)
    if container is None:
        logger.warning(f"Unknown source IP: {peername}")
        return _gateway_error(403, "Unknown container — not registered")
    if container.is_expired:
        logger.warning(
            f"Expired container: {container.container_id} (IP {peername})"
        )
        return _gateway_error(403, "Container registration expired")

    container_id = container.container_id

    # Stash container_id for middleware (rate limiter, metrics, etc.)
    set_container_id(request, container_id)

    # --- 2. Check credential availability ---------------------------------
    if credential is None:
        logger.error(
            f"No Anthropic credential configured "
            f"(container: {container_id})"
        )
        return _gateway_error(502, "Anthropic credential not configured on gateway")

    # --- 3. Build upstream request ----------------------------------------
    upstream_path = request.path
    if request.query_string:
        upstream_path = f"{upstream_path}?{request.query_string}"
    upstream_url = f"{UPSTREAM_BASE_URL}{upstream_path}"

    # Read the request body (enforced by client_max_size on the app).
    body = await request.read()

    # Build headers: forward safe headers, inject credential + custom headers.
    _PLACEHOLDER_MARKERS = ("CRED_PROXY_", "CREDENTIAL_PROXY_PLACEHOLDER")
    upstream_headers: dict[str, str] = {}
    for name, value in request.headers.items():
        if name.lower() not in _STRIPPED_HEADERS:
            if any(marker in value for marker in _PLACEHOLDER_MARKERS):
                continue
            upstream_headers[name] = value

    # Inject credential
    upstream_headers[credential["header"]] = credential["value"]

    # Inject custom headers
    for h_name, h_value in custom_headers:
        upstream_headers[h_name] = h_value

    # Override Host to match the upstream
    upstream_headers["Host"] = "api.anthropic.com"

    logger.info(
        f"Forwarding {request.method} {request.path} -> {upstream_url} "
        f"(container: {container_id})"
    )

    # --- 4. Forward to upstream and stream response -----------------------
    try:
        timeout = aiohttp.ClientTimeout(
            total=UPSTREAM_TOTAL_TIMEOUT,
            connect=UPSTREAM_CONNECT_TIMEOUT,
        )
        async with upstream_session.request(
            method=request.method,
            url=upstream_url,
            headers=upstream_headers,
            data=body,
            timeout=timeout,
            # Let aiohttp handle decompression transparently.
            auto_decompress=True,
        ) as upstream_resp:
            # Build the downstream response, preserving upstream status.
            response = web.StreamResponse(
                status=upstream_resp.status,
                reason=upstream_resp.reason,
            )

            # Forward response headers (skip hop-by-hop).
            _HOP_BY_HOP = frozenset({
                "connection", "keep-alive", "proxy-authenticate",
                "proxy-authorization", "te", "trailer",
                "transfer-encoding", "upgrade",
            })
            for name, value in upstream_resp.headers.items():
                if name.lower() not in _HOP_BY_HOP:
                    response.headers[name] = value

            await response.prepare(request)

            # Stream body chunks as they arrive.
            async for chunk in upstream_resp.content.iter_any():
                await response.write(chunk)

            await response.write_eof()

            logger.info(
                f"Completed {request.method} {request.path} -> {upstream_resp.status} "
                f"(container: {container_id})"
            )
            return response

    except asyncio.TimeoutError:
        logger.error(
            f"Upstream timeout for {request.method} {request.path} "
            f"(container: {container_id})"
        )
        return _gateway_error(504, "Upstream request timed out")
    except aiohttp.ClientConnectorError as exc:
        logger.error(
            f"Upstream connection error for {request.method} {request.path}: {exc} "
            f"(container: {container_id})"
        )
        return _gateway_error(502, f"Cannot connect to upstream: {exc}")
    except aiohttp.ClientError as exc:
        logger.error(
            f"Upstream client error for {request.method} {request.path}: {exc} "
            f"(container: {container_id})"
        )
        return _gateway_error(502, f"Upstream error: {exc}")
    except ConnectionResetError:
        # Client (sandbox) disconnected mid-stream — nothing to send back.
        logger.info(
            f"Client disconnected during {request.method} {request.path} "
            f"(container: {container_id})"
        )
        return web.Response(status=499)  # nginx-style client-closed


async def _health(_request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.json_response({"status": "ok", "service": "anthropic-gateway"})


# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------

async def _on_startup(app: web.Application) -> None:
    """Initialize shared resources when the server starts."""
    # Create a persistent aiohttp session for upstream requests.
    # connector with keepalive for connection reuse.
    connector = aiohttp.TCPConnector(
        limit=100,               # max simultaneous connections
        limit_per_host=50,       # max per upstream host
        enable_cleanup_closed=True,
        keepalive_timeout=30,
    )
    app["upstream_session"] = aiohttp.ClientSession(connector=connector)
    logger.info("Upstream HTTP session created")


async def _on_cleanup(app: web.Application) -> None:
    """Clean up shared resources on shutdown."""
    session: aiohttp.ClientSession = app.get("upstream_session")
    if session:
        await session.close()
        logger.info("Upstream HTTP session closed")

    registry: ContainerRegistry = app.get("registry")
    if registry:
        registry.close()
        logger.info("Container registry closed")


def create_gateway_app(
    registry: Optional[ContainerRegistry] = None,
) -> web.Application:
    """Create the aiohttp application for the Anthropic gateway.

    Args:
        registry: Optional ContainerRegistry instance. If not provided,
                  a new one is created using REGISTRY_DB_PATH.

    Returns:
        Configured aiohttp Application.
    """
    middlewares = create_gateway_middlewares("api.anthropic.com")
    app = web.Application(
        client_max_size=MAX_REQUEST_BODY,
        middlewares=middlewares,
    )

    # --- Shared state -----------------------------------------------------
    app["registry"] = registry or ContainerRegistry(db_path=REGISTRY_DB_PATH)
    app["credential"] = _load_anthropic_credential()
    app["custom_headers"] = _parse_custom_headers(
        os.environ.get("ANTHROPIC_CUSTOM_HEADERS", "")
    )

    if app["credential"]:
        header_name = app["credential"]["header"]
        logger.info(f"Anthropic credential loaded (header: {header_name})")
    else:
        logger.warning(
            "No Anthropic credential found — "
            "set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN"
        )

    if app["custom_headers"]:
        logger.info(
            f"Loaded {len(app['custom_headers'])} custom Anthropic header(s)"
        )

    # --- Routes -----------------------------------------------------------
    app.router.add_route("*", "/v1/messages", _proxy_request)
    app.router.add_route("*", "/v1/complete", _proxy_request)
    app.router.add_route("*", "/api/oauth/profile", _proxy_request)
    app.router.add_get("/health", _health)

    # --- Lifecycle hooks --------------------------------------------------
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)

    return app


def run_gateway(
    host: str = GATEWAY_BIND,
    port: int = GATEWAY_PORT,
    app: Optional[web.Application] = None,
) -> None:
    """Run the gateway server (blocking).

    Args:
        host: Bind address.
        port: Listen port.
        app: Optional pre-configured Application.
    """
    if app is None:
        app = create_gateway_app()

    logger.info(f"Starting Anthropic gateway on {host}:{port}")
    web.run_app(
        app,
        host=host,
        port=port,
        print=None,  # suppress aiohttp's default startup banner
        shutdown_timeout=10.0,
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    setup_logging()
    run_gateway()
