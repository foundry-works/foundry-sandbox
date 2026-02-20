"""GitHub API Gateway — plaintext HTTP relay with credential injection
and security policy enforcement.

Accepts plaintext HTTP from sandboxes on the internal Docker network,
validates container identity, enforces GitHub security policies (merge
blocking, operation blocklist, body inspection), injects API credentials,
and forwards to https://api.github.com over HTTPS.  Streams responses
back chunk-by-chunk without buffering.

Port allocation:
  :9848  Anthropic gateway (gateway.py)
  :9849  OpenAI gateway   (openai_gateway.py)
  :9850  GitHub gateway    (this module)

Error contract:
  - Upstream 4xx/5xx: proxy response body and status code transparently.
  - Upstream unreachable: 502 {"error":{"type":"gateway_error","message":"..."}}
  - Gateway timeout:      504 {"error":{"type":"gateway_error","message":"..."}}
  - Identity failure:     403 {"error":{"type":"gateway_error","message":"..."}}
  - Policy violation:     403 {"error":{"type":"policy_error","message":"..."}}

GitHub security policies (moved from policy_engine.py):
  - Merge blocking: REST PUT /pulls/N/merge, /pulls/N/auto-merge;
    GraphQL mergePullRequest, enablePullRequestAutoMerge
  - Blocklist: release creation, git ref mutations, review deletion
  - Body inspection: PR/issue close via state:closed, PR self-approval

These policies are duplicated from policy_engine.py for defense-in-depth.
If a request bypasses the gateway (e.g., direct MITM path), the policy
engine's checks still apply.

Sandbox configuration:
  GITHUB_API_URL=http://unified-proxy:9850
  GH_TOKEN=CREDENTIAL_PROXY_PLACEHOLDER
"""

import asyncio
import json
import os
import posixpath
import re
import sys
from typing import Optional
from urllib.parse import unquote, urlparse

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

GITHUB_GATEWAY_PORT = int(os.environ.get("GITHUB_GATEWAY_PORT", "9850"))
GITHUB_GATEWAY_BIND = os.environ.get("GITHUB_GATEWAY_BIND", "0.0.0.0")

UPSTREAM_BASE_URL = "https://api.github.com"

# Timeout for connecting to the upstream API (seconds).
UPSTREAM_CONNECT_TIMEOUT = 30
# Total timeout — GitHub API responses are usually fast, but large
# diff queries or GraphQL operations can take a while.
UPSTREAM_TOTAL_TIMEOUT = 300  # 5 minutes

# Maximum request body size (generous for large GraphQL queries).
MAX_REQUEST_BODY = 16 * 1024 * 1024  # 16 MB

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


def _load_github_credential() -> Optional[dict]:
    """Load the GitHub API credential from environment variables.

    Priority order (matches credential_injector.py):
      1. GITHUB_TOKEN → Authorization: Bearer <token>
      2. GH_TOKEN     → Authorization: Bearer <token>

    Returns dict with 'header' and 'value' keys, or None.
    Unlike other providers, GitHub allows unauthenticated access for
    public resources, so None is acceptable (not an error).
    """
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        token = os.environ.get("GH_TOKEN", "").strip()

    if token:
        return {"header": "Authorization", "value": f"Bearer {token}"}

    return None


# ---------------------------------------------------------------------------
# GitHub security policies
#
# These are duplicated from policy_engine.py for defense-in-depth.
# The gateway enforces them on all gh CLI traffic; the policy engine
# enforces them on any direct api.github.com traffic that bypasses
# the gateway (e.g., via the MITM proxy path).
# ---------------------------------------------------------------------------

# --- Path normalization (from policy_engine.py) ---

def _normalize_path(raw_path: str) -> Optional[str]:
    """Normalize a URL path with strict security rules.

    Steps:
    1. Strip query string and fragment
    2. URL-decode once
    3. Reject if '%' still present (double-encoding prevention)
    4. Collapse repeated slashes (// -> /)
    5. Resolve .. segments via posixpath.normpath
    6. Strip trailing slash (except bare /)

    Returns normalized path, or None if rejected (double-encoding).
    """
    path = urlparse(raw_path).path
    path = unquote(path)
    if "%" in path:
        return None
    while "//" in path:
        path = path.replace("//", "/")
    path = posixpath.normpath(path)
    if path == ".":
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path


# --- Merge blocking (from policy_engine.py Step E) ---

_MERGE_PATH_PATTERNS = [
    re.compile(r"/pulls/\d+/merge$"),
    re.compile(r"/pulls/\d+/auto-merge$"),
]

_MERGE_BODY_KEYWORDS = [
    b"mergePullRequest",
    b"enablePullRequestAutoMerge",
]


def _is_merge_request(path: str, body: bytes) -> bool:
    """Check if a request is a merge operation (REST or GraphQL)."""
    if any(p.search(path) for p in _MERGE_PATH_PATTERNS):
        return True
    if body and any(kw in body for kw in _MERGE_BODY_KEYWORDS):
        return True
    return False


# --- GitHub REST blocklist (from policy_engine.py Step 3) ---

_GITHUB_MERGE_PR_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/merge$")
_GITHUB_CREATE_RELEASE_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/releases$")
_GITHUB_GIT_REFS_ROOT_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/git/refs$")
_GITHUB_GIT_REFS_SUBPATH_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/git/refs/.+$")
_GITHUB_AUTO_MERGE_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/auto-merge$")
_GITHUB_DELETE_REVIEW_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews/\d+$")
_GITHUB_REPO_MERGES_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/merges$")

# Blocked paths — dangerous endpoints that must never be accessed
_BLOCKED_PATH_PATTERNS = [
    re.compile(r"^/repos/[^/]+/[^/]+/hooks(/\d+)?$"),
    re.compile(r"^/repos/[^/]+/[^/]+/keys(/\d+)?$"),
    re.compile(r"^/repos/[^/]+/[^/]+/deploy_keys(/\d+)?$"),
    re.compile(r"^/repos/[^/]+/[^/]+/environments/[^/]+/deployment-branch-policy$"),
    re.compile(r"^/repos/[^/]+/[^/]+/actions/secrets(/[^/]+)?$"),
    re.compile(r"^/repos/[^/]+/[^/]+/actions/variables(/[^/]+)?$"),
    re.compile(r"^/repos/[^/]+/[^/]+/branches/.+/protection(/.*)?$"),
    re.compile(r"^/repos/[^/]+/[^/]+/branches/.+/rename$"),
]


def _check_github_blocklist(method: str, path: str) -> Optional[str]:
    """Check GitHub-specific blocklist policies.

    Returns block reason if request should be blocked, None otherwise.
    """
    # Block PR merge operations (redundant with early-exit merge check)
    if method == "PUT" and _GITHUB_MERGE_PR_PATTERN.match(path):
        return "GitHub PR merge operations are blocked by policy"

    # Block release creation
    if method == "POST" and _GITHUB_CREATE_RELEASE_PATTERN.match(path):
        return "GitHub release creation is blocked by policy"

    # Block repo merge API (branch merges)
    if method == "POST" and _GITHUB_REPO_MERGES_PATTERN.match(path):
        return "GitHub repo merge operations are blocked by policy"

    # Block Git ref mutations (branch/tag create/update/delete via REST API)
    if method == "POST" and _GITHUB_GIT_REFS_ROOT_PATTERN.match(path):
        return "GitHub git ref creation is blocked by policy"
    if method in {"PATCH", "DELETE"} and _GITHUB_GIT_REFS_SUBPATH_PATTERN.match(path):
        return "GitHub git ref mutation is blocked by policy"

    # Block auto-merge enablement/disablement
    if method in ("PUT", "DELETE") and _GITHUB_AUTO_MERGE_PATTERN.match(path):
        return "GitHub auto-merge operations are blocked by policy"

    # Block review deletion (prevents removing blocking reviews)
    if method == "DELETE" and _GITHUB_DELETE_REVIEW_PATTERN.match(path):
        return "Deleting pull request reviews is blocked by policy"

    # Block dangerous endpoints (webhooks, deploy keys, secrets, etc.)
    for pattern in _BLOCKED_PATH_PATTERNS:
        if pattern.match(path):
            return f"Path '{path}' is blocked by policy"

    return None


# --- Body inspection (from policy_engine.py Step 3b) ---

_GITHUB_PATCH_PR_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+$")
_GITHUB_PATCH_ISSUE_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/issues/\d+$")
_GITHUB_PR_REVIEW_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews$")


def _check_github_body_policies(
    method: str,
    path: str,
    body: Optional[bytes],
    content_type: str,
    content_encoding: str,
) -> Optional[str]:
    """Check GitHub body-level policies for PATCH and POST operations.

    Inspects request bodies on security-relevant endpoints to block
    PR close, issue close, and PR review approval operations.

    Returns block reason if request should be blocked, None otherwise.
    """
    if method not in ("PATCH", "POST"):
        return None

    # POST: PR review approval check
    if method == "POST" and _GITHUB_PR_REVIEW_PATTERN.match(path):
        if content_encoding:
            return (
                "Compressed request bodies are not allowed for "
                "security-relevant GitHub POST endpoints"
            )
        if not content_type or not content_type.lower().startswith("application/json"):
            return (
                "Content-Type must be application/json for "
                "security-relevant GitHub POST endpoints"
            )
        if body is None:
            return (
                "Streaming request bodies are not allowed for "
                "security-relevant GitHub POST endpoints"
            )
        body_str = body.lstrip(b"\xef\xbb\xbf").decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body_str)
        except (json.JSONDecodeError, ValueError):
            return "Malformed JSON body in security-relevant GitHub POST request"
        if not isinstance(parsed, dict):
            return (
                "Request body must be a JSON object for "
                "security-relevant GitHub POST endpoints"
            )
        event = parsed.get("event")
        if event is not None and str(event).upper() == "APPROVE":
            return "Self-approving pull requests is blocked by policy"
        return None

    # PATCH: PR/issue close check
    if not (
        _GITHUB_PATCH_PR_PATTERN.match(path)
        or _GITHUB_PATCH_ISSUE_PATTERN.match(path)
    ):
        return None

    if content_encoding:
        return (
            "Compressed request bodies are not allowed for "
            "security-relevant GitHub PATCH endpoints"
        )
    if not content_type:
        return (
            "Content-Type header is required for "
            "security-relevant GitHub PATCH endpoints"
        )
    if not content_type.lower().startswith("application/json"):
        return (
            f"Content-Type must be application/json for "
            f"security-relevant GitHub PATCH endpoints, "
            f"got: {content_type}"
        )
    if body is None:
        return (
            "Streaming request bodies are not allowed for "
            "security-relevant GitHub PATCH endpoints"
        )

    body_str = body.lstrip(b"\xef\xbb\xbf").decode("utf-8", errors="replace")
    try:
        parsed = json.loads(body_str)
    except (json.JSONDecodeError, ValueError):
        return "Malformed JSON body in security-relevant GitHub PATCH request"

    if not isinstance(parsed, dict):
        return (
            "Request body must be a JSON object for "
            "security-relevant GitHub PATCH endpoints"
        )

    state = parsed.get("state")
    if state is not None and str(state).lower() == "closed":
        if _GITHUB_PATCH_PR_PATTERN.match(path):
            return "Closing pull requests via API is blocked by policy"
        else:
            return "Closing issues via API is blocked by policy"

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


def _policy_error(message: str) -> web.Response:
    """Return a 403 JSON error for policy violations."""
    body = json.dumps({"error": {"type": "policy_error", "message": message}})
    return web.Response(
        status=403,
        body=body.encode(),
        content_type="application/json",
        headers={"X-Sandbox-Blocked": "true"},
    )


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

async def _proxy_request(request: web.Request) -> web.StreamResponse:
    """Forward a GitHub API request to the upstream and stream the response."""

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

    # --- 2. Read body and apply security policies -------------------------
    body = await request.read()
    method = request.method.upper()
    raw_path = request.path

    # Step E: Early-exit merge blocking (unconditional)
    if _is_merge_request(raw_path, body):
        logger.warning(
            f"Blocked merge operation: {method} {raw_path} "
            f"(container: {container_id})"
        )
        return _policy_error("Merge operations are not permitted")

    # Normalize path for policy checks
    normalized_path = _normalize_path(raw_path)
    if normalized_path is None:
        logger.warning(
            f"Rejected double-encoded path: {method} {raw_path} "
            f"(container: {container_id})"
        )
        return _policy_error("Path rejected: double-encoding detected")

    # Step 3: GitHub blocklist
    block_reason = _check_github_blocklist(method, normalized_path)
    if block_reason:
        logger.warning(
            f"Blocked by GitHub policy: {method} {raw_path} — {block_reason} "
            f"(container: {container_id})"
        )
        return _policy_error(block_reason)

    # Step 3b: Body inspection
    content_type = request.headers.get("content-type", "")
    content_encoding = request.headers.get("content-encoding", "")
    body_block = _check_github_body_policies(
        method, normalized_path, body, content_type, content_encoding
    )
    if body_block:
        logger.warning(
            f"Blocked by body policy: {method} {raw_path} — {body_block} "
            f"(container: {container_id})"
        )
        return _policy_error(body_block)

    # --- 3. Build upstream request ----------------------------------------
    upstream_path = request.path
    if request.query_string:
        upstream_path = f"{upstream_path}?{request.query_string}"
    upstream_url = f"{UPSTREAM_BASE_URL}{upstream_path}"

    # Build headers: forward safe headers, inject credential.
    upstream_headers: dict[str, str] = {}
    for name, value in request.headers.items():
        if name.lower() not in _STRIPPED_HEADERS:
            upstream_headers[name] = value

    # Inject credential (if available)
    if credential is not None:
        upstream_headers[credential["header"]] = credential["value"]
    else:
        logger.info(
            f"No GitHub credential configured; forwarding unauthenticated "
            f"{method} {raw_path} (container: {container_id})"
        )

    # Override Host to match the upstream
    upstream_headers["Host"] = "api.github.com"

    logger.info(
        f"Forwarding {method} {request.path} -> {upstream_url} "
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
            auto_decompress=True,
        ) as upstream_resp:
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
                f"Completed {method} {request.path} -> {upstream_resp.status} "
                f"(container: {container_id})"
            )
            return response

    except asyncio.TimeoutError:
        logger.error(
            f"Upstream timeout for {method} {request.path} "
            f"(container: {container_id})"
        )
        return _gateway_error(504, "Upstream request timed out")
    except aiohttp.ClientConnectorError as exc:
        logger.error(
            f"Upstream connection error for {method} {request.path}: {exc} "
            f"(container: {container_id})"
        )
        return _gateway_error(502, f"Cannot connect to upstream: {exc}")
    except aiohttp.ClientError as exc:
        logger.error(
            f"Upstream client error for {method} {request.path}: {exc} "
            f"(container: {container_id})"
        )
        return _gateway_error(502, f"Upstream error: {exc}")
    except ConnectionResetError:
        logger.info(
            f"Client disconnected during {method} {request.path} "
            f"(container: {container_id})"
        )
        return web.Response(status=499)  # nginx-style client-closed


async def _health(_request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.json_response({"status": "ok", "service": "github-gateway"})


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


def create_github_gateway_app(
    registry: Optional[ContainerRegistry] = None,
) -> web.Application:
    """Create the aiohttp application for the GitHub gateway.

    Args:
        registry: Optional ContainerRegistry instance. If not provided,
                  a new one is created using REGISTRY_DB_PATH.

    Returns:
        Configured aiohttp Application.
    """
    middlewares = create_gateway_middlewares("api.github.com")
    app = web.Application(
        client_max_size=MAX_REQUEST_BODY,
        middlewares=middlewares,
    )

    # --- Shared state -----------------------------------------------------
    app["registry"] = registry or ContainerRegistry(db_path=REGISTRY_DB_PATH)
    app["credential"] = _load_github_credential()

    if app["credential"]:
        logger.info("GitHub credential loaded (header: Authorization)")
    else:
        # Unlike other providers, GitHub allows unauthenticated access.
        # This is a warning, not an error.
        logger.warning(
            "No GitHub credential found — "
            "set GITHUB_TOKEN or GH_TOKEN for authenticated access"
        )

    # --- Routes -----------------------------------------------------------
    # Health check must be registered before the catch-all.
    app.router.add_get("/health", _health)
    # Catch-all route for all GitHub API paths.
    # The gh CLI accesses many different endpoints; we forward them all.
    app.router.add_route("*", "/{path_info:.*}", _proxy_request)

    # --- Lifecycle hooks --------------------------------------------------
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)

    return app


def run_github_gateway(
    host: str = GITHUB_GATEWAY_BIND,
    port: int = GITHUB_GATEWAY_PORT,
    app: Optional[web.Application] = None,
) -> None:
    """Run the GitHub gateway server (blocking).

    Args:
        host: Bind address.
        port: Listen port.
        app: Optional pre-configured Application.
    """
    if app is None:
        app = create_github_gateway_app()

    logger.info(f"Starting GitHub gateway on {host}:{port}")
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
    run_github_gateway()
