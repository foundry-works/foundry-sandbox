"""OpenAI API Gateway — thin wrapper around gateway_base.

Accepts plaintext HTTP from sandboxes on the internal Docker network,
validates container identity, injects API credentials, and forwards to
https://api.openai.com over HTTPS.  Streams SSE responses back
chunk-by-chunk without buffering.

Port allocation:
  :9848  Anthropic gateway (gateway.py)
  :9849  OpenAI gateway   (this module)
  :9850  GitHub gateway    (github_gateway.py)

Perplexity conflict:
  Perplexity uses OPENAI_BASE_URL via the OpenAI SDK.  If both OpenAI and
  Perplexity need proxying, they cannot share the same env var.  For now,
  Perplexity continues to use the MITM path until its SDK adds a dedicated
  env var.

Sandbox configuration:
  OPENAI_BASE_URL is intentionally left unset in sandboxes to avoid
  conflicting with Codex subscription mode (which routes through
  chatgpt.com → TLS interception on port 443). OpenAI API-key traffic
  uses the MITM credential injection path instead of this gateway.
  This gateway remains available but is not actively routed to.
  OPENAI_API_KEY=CREDENTIAL_PROXY_PLACEHOLDER
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

OPENAI_GATEWAY_PORT = int(os.environ.get("OPENAI_GATEWAY_PORT", "9849"))
OPENAI_GATEWAY_BIND = os.environ.get("OPENAI_GATEWAY_BIND", "0.0.0.0")


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
# Application factory
# ---------------------------------------------------------------------------

def create_openai_gateway_app(
    registry: Optional[ContainerRegistry] = None,
) -> web.Application:
    """Create the aiohttp application for the OpenAI gateway."""
    return create_gateway_app(
        upstream_base_url="https://api.openai.com",
        upstream_host="api.openai.com",
        service_name="openai-gateway",
        credential_loader=_load_openai_credential,
        routes=[
            ("*", "/{path_info:.*}"),
        ],
        port=OPENAI_GATEWAY_PORT,
        bind=OPENAI_GATEWAY_BIND,
        max_request_body=32 * 1024 * 1024,
        connect_timeout=30,
        total_timeout=600,
        credential_required=True,
        registry=registry,
    )


def run_openai_gateway_server(
    host: str = OPENAI_GATEWAY_BIND,
    port: int = OPENAI_GATEWAY_PORT,
    app: Optional[web.Application] = None,
) -> None:
    """Run the OpenAI gateway server (blocking)."""
    if app is None:
        app = create_openai_gateway_app()
    run_gateway(app, host, port)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    setup_logging()
    run_openai_gateway_server()
