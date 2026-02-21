"""GitHub API Gateway — thin wrapper around gateway_base with security
policy enforcement via security_policies.

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

GitHub security policies are imported from security_policies.py (shared
with addons/policy_engine.py) for defense-in-depth.

Sandbox configuration:
  GITHUB_API_URL=http://unified-proxy:9850
  GH_TOKEN=CREDENTIAL_PROXY_PLACEHOLDER
"""

import json
import os
import sys
from typing import Optional

from aiohttp import web

# ---------------------------------------------------------------------------
# Ensure /opt/proxy is on sys.path so imports work inside the container
# ---------------------------------------------------------------------------
_PROXY_DIR = "/opt/proxy"
if _PROXY_DIR not in sys.path:
    sys.path.insert(0, _PROXY_DIR)

from gateway_base import create_gateway_app, run_gateway  # noqa: E402
from logging_config import get_logger, setup_logging  # noqa: E402
from registry import ContainerRegistry  # noqa: E402
from security_policies import (  # noqa: E402
    check_github_blocklist,
    check_github_body_policies,
    is_merge_request,
    normalize_path,
)

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GITHUB_GATEWAY_PORT = int(os.environ.get("GITHUB_GATEWAY_PORT", "9850"))
GITHUB_GATEWAY_BIND = os.environ.get("GITHUB_GATEWAY_BIND", "0.0.0.0")


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
# Policy error helper
# ---------------------------------------------------------------------------

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
# Request hook — GitHub security policy enforcement
# ---------------------------------------------------------------------------

async def _github_request_hook(
    request: web.Request,
    method: str,
    body: bytes,
    container_id: str,
) -> Optional[web.Response]:
    """Enforce GitHub security policies before upstream forwarding.

    This hook runs after identity validation but before the request is
    forwarded to api.github.com.  It implements the same policy checks
    as addons/policy_engine.py for defense-in-depth.

    Args:
        request: The aiohttp request.
        method: HTTP method (uppercased).
        body: Request body bytes.
        container_id: Validated container ID.

    Returns:
        A web.Response if the request should be blocked, None to proceed.
    """
    raw_path = request.path

    # Normalize path for policy checks
    normalized_path = normalize_path(raw_path)
    if normalized_path is None:
        logger.warning(
            f"Rejected double-encoded path: {method} {raw_path} "
            f"(container: {container_id})"
        )
        return _policy_error("Path rejected: double-encoding detected")

    # Step 3: GitHub blocklist (path-only, no body needed)
    block_reason = check_github_blocklist(method, normalized_path)
    if block_reason:
        logger.warning(
            f"Blocked by GitHub policy: {method} {raw_path} — {block_reason} "
            f"(container: {container_id})"
        )
        return _policy_error(block_reason)

    # Step E: Early-exit merge blocking (needs body for GraphQL keywords)
    if is_merge_request(raw_path, body):
        logger.warning(
            f"Blocked merge operation: {method} {raw_path} "
            f"(container: {container_id})"
        )
        return _policy_error("Merge operations are not permitted")

    # Step 3b: Body inspection
    content_type = request.headers.get("content-type", "")
    content_encoding = request.headers.get("content-encoding", "")
    body_block = check_github_body_policies(
        method, normalized_path, body, content_type, content_encoding
    )
    if body_block:
        logger.warning(
            f"Blocked by body policy: {method} {raw_path} — {body_block} "
            f"(container: {container_id})"
        )
        return _policy_error(body_block)

    return None


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_github_gateway_app(
    registry: Optional[ContainerRegistry] = None,
) -> web.Application:
    """Create the aiohttp application for the GitHub gateway."""
    return create_gateway_app(
        upstream_base_url="https://api.github.com",
        upstream_host="api.github.com",
        service_name="github-gateway",
        credential_loader=_load_github_credential,
        routes=[
            # Catch-all route for all GitHub API paths.
            # The gh CLI accesses many different endpoints; we forward them all.
            ("*", "/{path_info:.*}"),
        ],
        port=GITHUB_GATEWAY_PORT,
        bind=GITHUB_GATEWAY_BIND,
        max_request_body=16 * 1024 * 1024,
        connect_timeout=30,
        total_timeout=300,
        credential_required=False,  # GitHub allows unauthenticated access
        request_hook=_github_request_hook,
        registry=registry,
    )


def run_github_gateway(
    host: str = GITHUB_GATEWAY_BIND,
    port: int = GITHUB_GATEWAY_PORT,
    app: Optional[web.Application] = None,
) -> None:
    """Run the GitHub gateway server (blocking)."""
    if app is None:
        app = create_github_gateway_app()
    run_gateway(app, host, port)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    setup_logging()
    run_github_gateway()
