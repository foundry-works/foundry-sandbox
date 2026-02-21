"""Anthropic API Gateway — thin wrapper around gateway_base.

Accepts plaintext HTTP from sandboxes on the internal Docker network,
validates container identity, injects API credentials, and forwards to
https://api.anthropic.com over HTTPS.  Streams SSE responses back
chunk-by-chunk without buffering.

Port allocation:
  :9848  Anthropic gateway (this module)
  :9849  OpenAI gateway   (openai_gateway.py)
  :9850  GitHub gateway    (github_gateway.py)

Sandbox configuration:
  ANTHROPIC_BASE_URL=http://unified-proxy:9848
  ANTHROPIC_API_KEY=CREDENTIAL_PROXY_PLACEHOLDER
"""

import os
import re
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

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "9848"))
GATEWAY_BIND = os.environ.get("GATEWAY_BIND", "0.0.0.0")

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
    """Parse ANTHROPIC_CUSTOM_HEADERS env var into (name, value) pairs."""
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
# App state hook — inject custom headers
# ---------------------------------------------------------------------------

def _app_state_hook(app: web.Application) -> None:
    """Set custom headers on the app after credential loading."""
    app["custom_headers"] = _parse_custom_headers(
        os.environ.get("ANTHROPIC_CUSTOM_HEADERS", "")
    )
    if app["custom_headers"]:
        logger.info(
            f"Loaded {len(app['custom_headers'])} custom Anthropic header(s)"
        )


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_anthropic_gateway_app(
    registry: Optional[ContainerRegistry] = None,
) -> web.Application:
    """Create the aiohttp application for the Anthropic gateway."""
    return create_gateway_app(
        upstream_base_url="https://api.anthropic.com",
        upstream_host="api.anthropic.com",
        service_name="anthropic-gateway",
        credential_loader=_load_anthropic_credential,
        routes=[
            ("*", "/v1/messages"),
            ("*", "/v1/complete"),
            ("*", "/api/oauth/profile"),
        ],
        port=GATEWAY_PORT,
        bind=GATEWAY_BIND,
        max_request_body=32 * 1024 * 1024,
        connect_timeout=30,
        total_timeout=600,
        credential_required=True,
        extra_stripped_headers=frozenset({"x-api-key"}),
        app_state_hook=_app_state_hook,
        registry=registry,
    )


# Keep backward-compatible name
create_gateway_app_compat = create_anthropic_gateway_app


def run_anthropic_gateway(
    host: str = GATEWAY_BIND,
    port: int = GATEWAY_PORT,
    app: Optional[web.Application] = None,
) -> None:
    """Run the Anthropic gateway server (blocking)."""
    if app is None:
        app = create_anthropic_gateway_app()
    run_gateway(app, host, port)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    setup_logging()
    run_anthropic_gateway()
