"""ChatGPT / Codex API Gateway — thin wrapper around gateway_base.

Accepts plaintext HTTP from sandboxes on the internal Docker network,
validates container identity, injects OAuth credentials, and forwards to
https://chatgpt.com over HTTPS.  Streams responses back chunk-by-chunk
without buffering.

Port allocation:
  :9848  Anthropic gateway (gateway.py)
  :9849  OpenAI gateway    (openai_gateway.py)
  :9850  GitHub gateway     (github_gateway.py)
  :9851  Gemini gateway     (gemini_gateway.py)
  :9852  ChatGPT gateway    (this module)

Credential injection:
  Uses OAuth tokens from Codex CLI auth.json (mounted at CODEX_AUTH_FILE).
  Tokens are refreshed automatically via OAuthTokenManager when expired.

Sandbox configuration:
  CHATGPT_BASE_URL=http://unified-proxy:9852
  # Auth handled via gateway; sandbox sends placeholder Authorization header
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

from gateway_base import create_gateway_app, gateway_error, run_gateway  # noqa: E402
from logging_config import get_logger, setup_logging  # noqa: E402
from registry import ContainerRegistry  # noqa: E402

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CHATGPT_GATEWAY_PORT = int(os.environ.get("CHATGPT_GATEWAY_PORT", "9852"))
CHATGPT_GATEWAY_BIND = os.environ.get("CHATGPT_GATEWAY_BIND", "0.0.0.0")


# ---------------------------------------------------------------------------
# OAuth token manager (module-level so request_hook can access it)
# ---------------------------------------------------------------------------

_token_manager = None


def _init_token_manager() -> None:
    """Initialize the OAuth token manager from CODEX_AUTH_FILE."""
    global _token_manager

    auth_file = os.environ.get("CODEX_AUTH_FILE", "").strip()
    if not auth_file:
        logger.warning("chatgpt-gateway: CODEX_AUTH_FILE not set")
        return

    if not os.path.exists(auth_file):
        logger.warning(f"chatgpt-gateway: auth file not found: {auth_file}")
        return

    try:
        # Import from the addons oauth_managers package (available in container)
        from addons.oauth_managers.codex import OAuthTokenManager
        _token_manager = OAuthTokenManager(auth_file)
        logger.info(f"chatgpt-gateway: OAuth token manager initialized from {auth_file}")
    except ImportError:
        # Fallback: try the top-level module (codex_token_manager.py)
        try:
            from codex_token_manager import OAuthTokenManager as FallbackManager
            _token_manager = FallbackManager(auth_file)
            logger.info(f"chatgpt-gateway: OAuth token manager initialized (fallback) from {auth_file}")
        except ImportError:
            logger.error("chatgpt-gateway: OAuthTokenManager not available")
    except (FileNotFoundError, ValueError) as e:
        logger.warning(f"chatgpt-gateway: failed to load auth file: {e}")
    except Exception as e:
        logger.error(f"chatgpt-gateway: failed to initialize token manager: {e}")


# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------

def _load_chatgpt_credential() -> Optional[dict]:
    """Load the ChatGPT/Codex OAuth credential.

    Reads the current access token from the OAuthTokenManager.
    Returns dict with 'header' and 'value' keys, or None.
    """
    if _token_manager is None:
        return None

    try:
        token = _token_manager.get_valid_token()
        return {"header": "Authorization", "value": f"Bearer {token}"}
    except Exception as e:
        logger.error(f"chatgpt-gateway: failed to get initial token: {e}")
        return None


# ---------------------------------------------------------------------------
# Request hook — refresh token before each request
# ---------------------------------------------------------------------------

async def _chatgpt_request_hook(
    request: web.Request,
    method: str,
    body: bytes,
    container_id: str,
) -> Optional[web.Response]:
    """Refresh OAuth token before forwarding to upstream.

    The gateway_base credential is loaded once at startup, but OAuth tokens
    expire.  This hook mutates the credential dict in-place so the shared
    proxy handler sees a fresh token on every request.
    """
    if _token_manager is None:
        return gateway_error(502, "ChatGPT OAuth credential not configured")

    try:
        token = _token_manager.get_valid_token()
        credential = request.app.get("credential")
        if credential is not None:
            # Mutate in-place so the local var in _proxy_request sees it
            credential["value"] = f"Bearer {token}"
        else:
            # Credential was None at startup but token manager recovered
            request.app["credential"] = {
                "header": "Authorization",
                "value": f"Bearer {token}",
            }
    except Exception as e:
        logger.error(f"chatgpt-gateway: OAuth token refresh failed: {e}")
        return gateway_error(502, f"ChatGPT OAuth token refresh failed: {e}")

    return None  # Continue to upstream forwarding


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_chatgpt_gateway_app(
    registry: Optional[ContainerRegistry] = None,
) -> web.Application:
    """Create the aiohttp application for the ChatGPT/Codex gateway."""
    _init_token_manager()

    return create_gateway_app(
        upstream_base_url="https://chatgpt.com",
        upstream_host="chatgpt.com",
        service_name="chatgpt-gateway",
        credential_loader=_load_chatgpt_credential,
        routes=[
            ("*", "/{path_info:.*}"),
        ],
        port=CHATGPT_GATEWAY_PORT,
        bind=CHATGPT_GATEWAY_BIND,
        max_request_body=32 * 1024 * 1024,
        connect_timeout=30,
        total_timeout=600,
        credential_required=True,
        request_hook=_chatgpt_request_hook,
        registry=registry,
    )


def run_chatgpt_gateway_server(
    host: str = CHATGPT_GATEWAY_BIND,
    port: int = CHATGPT_GATEWAY_PORT,
    app: Optional[web.Application] = None,
) -> None:
    """Run the ChatGPT/Codex gateway server (blocking)."""
    if app is None:
        app = create_chatgpt_gateway_app()
    run_gateway(app, host, port)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    setup_logging()
    run_chatgpt_gateway_server()
