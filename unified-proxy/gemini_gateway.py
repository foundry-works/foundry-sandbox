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
  :9852  ChatGPT gateway    (chatgpt_gateway.py)

Credential injection (two modes):
  API-key mode:
    Uses x-goog-api-key header.
    Reads GEMINI_API_KEY (primary) or GOOGLE_API_KEY (fallback).

  OAuth mode:
    Uses Authorization: Bearer header with tokens from GEMINI_OAUTH_FILE.
    Tokens are loaded via GeminiTokenManager.  Note that Google OAuth
    refresh requires client credentials we don't have, so expired tokens
    require the user to re-run ``gemini login`` on the host.

  Priority: API-key mode wins when both are configured.

Sandbox configuration:
  GOOGLE_GEMINI_BASE_URL=http://unified-proxy:9851
  GEMINI_API_KEY=CREDENTIAL_PROXY_PLACEHOLDER
"""

import asyncio
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

from gateway_base import create_gateway_app, gateway_error, run_gateway  # noqa: E402
from logging_config import get_logger, setup_logging  # noqa: E402
from registry import ContainerRegistry  # noqa: E402

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GEMINI_GATEWAY_PORT = int(os.environ.get("GEMINI_GATEWAY_PORT", "9851"))
GEMINI_GATEWAY_BIND = os.environ.get("GEMINI_GATEWAY_BIND", "0.0.0.0")


# ---------------------------------------------------------------------------
# OAuth token manager (module-level so request_hook can access it)
# ---------------------------------------------------------------------------

_token_manager = None

# Track which credential mode is active so the request hook knows
# whether to refresh tokens.  Set once at app creation time by
# _load_gemini_credential() and read (not written) per-request —
# safe without synchronization in the current single-process model.
_credential_mode: str = "none"  # "api_key", "oauth", or "none"


def _init_token_manager() -> None:
    """Initialize the Gemini OAuth token manager from GEMINI_OAUTH_FILE."""
    global _token_manager

    auth_file = os.environ.get("GEMINI_OAUTH_FILE", "").strip()
    if not auth_file:
        logger.info("gemini-gateway: GEMINI_OAUTH_FILE not set")
        return

    if not os.path.exists(auth_file):
        logger.warning(f"gemini-gateway: OAuth file not found: {auth_file}")
        return

    try:
        from addons.oauth_managers.gemini import GeminiTokenManager
        _token_manager = GeminiTokenManager(auth_file)
        logger.info(f"gemini-gateway: OAuth token manager initialized from {auth_file}")
    except ImportError:
        try:
            from gemini_token_manager import GeminiTokenManager as FallbackManager
            _token_manager = FallbackManager(auth_file)
            logger.info(f"gemini-gateway: OAuth token manager initialized (fallback) from {auth_file}")
        except ImportError:
            logger.error("gemini-gateway: GeminiTokenManager not available")
    except (FileNotFoundError, ValueError) as e:
        logger.warning(f"gemini-gateway: failed to load OAuth file: {e}")
    except Exception as e:
        logger.error(f"gemini-gateway: failed to initialize OAuth manager: {e}")


# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------

def _load_gemini_credential() -> Optional[dict]:
    """Load the Gemini API credential.

    Priority:
      1. GEMINI_API_KEY or GOOGLE_API_KEY → x-goog-api-key (static)
      2. GEMINI_OAUTH_FILE → Authorization: Bearer (via token manager)

    Returns dict with 'header' and 'value' keys, or None.
    """
    global _credential_mode

    # Priority 1: API key
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        api_key = os.environ.get("GOOGLE_API_KEY", "").strip()
    if api_key:
        _credential_mode = "api_key"
        logger.info("gemini-gateway: using API-key mode")
        return {"header": "x-goog-api-key", "value": api_key}

    # Priority 2: OAuth
    if _token_manager is not None:
        try:
            token = _token_manager.get_valid_token()
            _credential_mode = "oauth"
            logger.info("gemini-gateway: using OAuth mode")
            return {"header": "Authorization", "value": f"Bearer {token}"}
        except Exception as e:
            logger.error(f"gemini-gateway: failed to get initial OAuth token: {e}")

    _credential_mode = "none"
    return None


# ---------------------------------------------------------------------------
# Request hook — refresh OAuth token before each request
# ---------------------------------------------------------------------------

async def _gemini_request_hook(
    request: web.Request,
    method: str,
    body: bytes,
    container_id: str,
) -> Optional[web.Response]:
    """Refresh OAuth token before forwarding to upstream.

    Only active in OAuth mode.  In API-key mode this is a no-op.
    """
    if _credential_mode != "oauth":
        return None  # API-key mode — nothing to refresh

    if _token_manager is None:
        return gateway_error(502, "Gemini OAuth credential not configured")

    try:
        # Run in a thread to avoid blocking the event loop — the token
        # manager acquires a threading.Lock and may do I/O in the future.
        token = await asyncio.to_thread(_token_manager.get_valid_token)
        credential = request.app.get("credential")
        if credential is not None:
            credential["value"] = f"Bearer {token}"
        else:
            request.app["credential"] = {
                "header": "Authorization",
                "value": f"Bearer {token}",
            }
    except Exception as e:
        logger.error(f"gemini-gateway: OAuth token error: {e}")
        return gateway_error(502, "Gemini OAuth token refresh failed")

    return None


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_gemini_gateway_app(
    registry: Optional[ContainerRegistry] = None,
) -> web.Application:
    """Create the aiohttp application for the Gemini gateway."""
    _init_token_manager()

    # Determine stripped headers based on credential mode.
    # In API-key mode we strip x-goog-api-key (sandbox placeholder).
    # In OAuth mode we don't need to strip it (Authorization is already
    # in the base stripped set).
    extra_stripped = frozenset({"x-goog-api-key"})

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
        extra_stripped_headers=extra_stripped,
        request_hook=_gemini_request_hook,
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
