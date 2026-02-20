"""OpenAI API Gateway — plaintext HTTP relay with credential injection.

Accepts plaintext HTTP from sandboxes on the internal Docker network,
validates container identity, injects API credentials, and forwards to
https://api.openai.com over HTTPS.  Streams SSE responses back
chunk-by-chunk without buffering.

Port allocation:
  :9848  Anthropic gateway (gateway.py)
  :9849  OpenAI gateway   (this module)
  :9850  GitHub gateway    (github_gateway.py)

Error contract:
  - Upstream 4xx/5xx: proxy response body and status code transparently.
  - Upstream unreachable: 502 {"error":{"type":"gateway_error","message":"..."}}
  - Gateway timeout:      504 {"error":{"type":"gateway_error","message":"..."}}
  - Identity failure:     403 {"error":{"type":"gateway_error","message":"..."}}

Perplexity conflict:
  Perplexity uses OPENAI_BASE_URL via the OpenAI SDK.  If both OpenAI and
  Perplexity need proxying, they cannot share the same env var.  For now,
  Perplexity continues to use the MITM path until its SDK adds a dedicated
  env var.  See PLAN.md §3.1 Phase 2 for details.
"""

import asyncio
import json
import os
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

OPENAI_GATEWAY_PORT = int(os.environ.get("OPENAI_GATEWAY_PORT", "9849"))
OPENAI_GATEWAY_BIND = os.environ.get("OPENAI_GATEWAY_BIND", "0.0.0.0")

UPSTREAM_BASE_URL = "https://api.openai.com"

# Timeout for connecting to the upstream API (seconds).
UPSTREAM_CONNECT_TIMEOUT = 30
# Total timeout is intentionally very long — streaming responses from
# the OpenAI API can take minutes for large completions with tool use.
UPSTREAM_TOTAL_TIMEOUT = 600  # 10 minutes

# Maximum request body size (generous limit for large prompts).
MAX_REQUEST_BODY = 32 * 1024 * 1024  # 32 MB

# Registry database path (shared with other proxy components).
REGISTRY_DB_PATH = os.environ.get(
    "REGISTRY_DB_PATH", "/var/lib/unified-proxy/registry.db"
)

# Header names that must not be forwarded from the sandbox.
# The gateway injects the real credential; sandbox-supplied values are stripped.
_STRIPPED_HEADERS = frozenset({
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


# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------

def _load_openai_credential() -> Optional[dict]:
    """Load the OpenAI API credential from environment variables.

    Returns dict with 'header' and 'value' keys, or None.
    """
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if api_key:
        return {"header": "Authorization", "value": f"Bearer {api_key}"}

    return None


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
    """Forward an OpenAI API request to the upstream and stream the response."""

    app = request.app
    registry: ContainerRegistry = app["registry"]
    credential: Optional[dict] = app["credential"]
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
            f"No OpenAI credential configured "
            f"(container: {container_id})"
        )
        return _gateway_error(502, "OpenAI credential not configured on gateway")

    # --- 3. Build upstream request ----------------------------------------
    upstream_path = request.path
    if request.query_string:
        upstream_path = f"{upstream_path}?{request.query_string}"
    upstream_url = f"{UPSTREAM_BASE_URL}{upstream_path}"

    # Read the request body (enforced by client_max_size on the app).
    body = await request.read()

    # Build headers: forward safe headers, inject credential.
    upstream_headers: dict[str, str] = {}
    for name, value in request.headers.items():
        if name.lower() not in _STRIPPED_HEADERS:
            upstream_headers[name] = value

    # Inject credential
    upstream_headers[credential["header"]] = credential["value"]

    # Override Host to match the upstream
    upstream_headers["Host"] = "api.openai.com"

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
    return web.json_response({"status": "ok", "service": "openai-gateway"})


# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------

async def _on_startup(app: web.Application) -> None:
    """Initialize shared resources when the server starts."""
    # Create a persistent aiohttp session for upstream requests.
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


def create_openai_gateway_app(
    registry: Optional[ContainerRegistry] = None,
) -> web.Application:
    """Create the aiohttp application for the OpenAI gateway.

    Args:
        registry: Optional ContainerRegistry instance. If not provided,
                  a new one is created using REGISTRY_DB_PATH.

    Returns:
        Configured aiohttp Application.
    """
    middlewares = create_gateway_middlewares("api.openai.com")
    app = web.Application(
        client_max_size=MAX_REQUEST_BODY,
        middlewares=middlewares,
    )

    # --- Shared state -----------------------------------------------------
    app["registry"] = registry or ContainerRegistry(db_path=REGISTRY_DB_PATH)
    app["credential"] = _load_openai_credential()

    if app["credential"]:
        logger.info("OpenAI credential loaded (header: Authorization)")
    else:
        logger.warning(
            "No OpenAI credential found — set OPENAI_API_KEY"
        )

    # --- Routes -----------------------------------------------------------
    app.router.add_route("*", "/v1/chat/completions", _proxy_request)
    app.router.add_route("*", "/v1/completions", _proxy_request)
    app.router.add_route("*", "/v1/models", _proxy_request)
    app.router.add_route("*", "/v1/responses", _proxy_request)
    app.router.add_get("/health", _health)

    # --- Lifecycle hooks --------------------------------------------------
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)

    return app


def run_openai_gateway(
    host: str = OPENAI_GATEWAY_BIND,
    port: int = OPENAI_GATEWAY_PORT,
    app: Optional[web.Application] = None,
) -> None:
    """Run the OpenAI gateway server (blocking).

    Args:
        host: Bind address.
        port: Listen port.
        app: Optional pre-configured Application.
    """
    if app is None:
        app = create_openai_gateway_app()

    logger.info(f"Starting OpenAI gateway on {host}:{port}")
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
    run_openai_gateway()
