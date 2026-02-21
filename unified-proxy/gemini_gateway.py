"""Gemini API Gateway — thin wrapper around gateway_base.

Accepts plaintext HTTP from sandboxes on the internal Docker network,
validates container identity, injects API credentials, and forwards to
https://generativelanguage.googleapis.com over HTTPS.  Streams SSE
responses back chunk-by-chunk without buffering.

Port allocation:
  :9848  Anthropic gateway (gateway.py)
  :9849  OpenAI gateway    (openai_gateway.py)
  :9850  GitHub gateway     (github_gateway.py)
  :9851  Gemini gateway     (this module)

Credential injection:
  Uses x-goog-api-key header (not Authorization: Bearer).
  Reads GEMINI_API_KEY (primary) or GOOGLE_API_KEY (fallback).

OAuth login mode:
  Gemini CLI OAuth login (oauth2.googleapis.com, accounts.google.com)
  still uses the MITM path.  This gateway handles API-key mode only.

Sandbox configuration:
  GOOGLE_GEMINI_BASE_URL=http://unified-proxy:9851
  GEMINI_API_KEY=CREDENTIAL_PROXY_PLACEHOLDER
"""

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

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GEMINI_GATEWAY_PORT = int(os.environ.get("GEMINI_GATEWAY_PORT", "9851"))
GEMINI_GATEWAY_BIND = os.environ.get("GEMINI_GATEWAY_BIND", "0.0.0.0")


# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------

def _load_gemini_credential() -> Optional[dict]:
    """Load the Gemini API credential from environment variables.

    Priority: GEMINI_API_KEY > GOOGLE_API_KEY (matches credential_injector.py).
    Returns dict with 'header' and 'value' keys, or None.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        api_key = os.environ.get("GOOGLE_API_KEY", "").strip()
    if api_key:
        return {"header": "x-goog-api-key", "value": api_key}
    return None


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_gemini_gateway_app(
    registry: Optional[ContainerRegistry] = None,
) -> web.Application:
    """Create the aiohttp application for the Gemini gateway."""
    return create_gateway_app(
        upstream_base_url="https://generativelanguage.googleapis.com",
        upstream_host="generativelanguage.googleapis.com",
        service_name="gemini-gateway",
        credential_loader=_load_gemini_credential,
        routes=[
            ("*", "/{path_info:.*}"),
        ],
        port=GEMINI_GATEWAY_PORT,
        bind=GEMINI_GATEWAY_BIND,
        max_request_body=32 * 1024 * 1024,
        connect_timeout=30,
        total_timeout=600,
        credential_required=True,
        extra_stripped_headers=frozenset({"x-goog-api-key"}),
        registry=registry,
    )


def run_gemini_gateway_server(
    host: str = GEMINI_GATEWAY_BIND,
    port: int = GEMINI_GATEWAY_PORT,
    app: Optional[web.Application] = None,
) -> None:
    """Run the Gemini gateway server (blocking)."""
    if app is None:
        app = create_gemini_gateway_app()
    run_gateway(app, host, port)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    setup_logging()
    run_gemini_gateway_server()
