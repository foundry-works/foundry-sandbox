# API Gateway Sidecar for foundry-mcp Credential Isolation

## Summary

Extend the credential isolation gateway sidecar to handle AI API calls from foundry-mcp. This enables true credential isolation where **API keys never enter sandbox containers** - the gateway holds credentials and proxies requests.

---

## Research Findings: CLI Base URL Support

| CLI | Base URL Support | Variable | Status |
|-----|------------------|----------|--------|
| **Claude CLI** | No | N/A | CLI handles HTTP internally, no override |
| **Gemini CLI** | No | N/A | CLI handles HTTP internally, no override |
| **Codex CLI** | Blocked | `OPENAI_BASE_URL` | Explicitly removed - interferes with internal routing |
| **OpenCode** | Yes | `OPENCODE_SERVER_URL` | Server-based, fully proxiable |
| **LLM SDK Layer** | Yes | `base_url` parameter | Works for OpenAI, Anthropic SDKs |

**Key Insight**: The CLI wrappers (Claude, Gemini, Codex) invoke local binaries that handle their own HTTP connections internally. They **cannot** be proxied without modifications to foundry-mcp.

**Solution Path**: Modify foundry-mcp to use the LLM SDK layer (which supports `base_url`) instead of CLI subprocess invocation when running in gateway mode. The existing `OpenAIProvider` and `AnthropicProvider` in `llm_provider.py` already accept `base_url` parameters.

---

## Architecture

```
+---------------------------------------------+
|           Sandbox Container                 |
|  (No API credentials, internal network)     |
|                                             |
|  +---------------------------------------+  |
|  |         foundry-mcp                   |  |
|  |  FOUNDRY_GATEWAY_MODE=1               |  |
|  |  FOUNDRY_GATEWAY_URL=https://gateway  |  |
|  |                                       |  |
|  |  Uses SDK layer (not CLI)             |  |
|  |  for AI provider calls                |  |
|  +-------------------+-------------------+  |
|                      |                      |
+----------------------+----------------------+
                       | HTTPS (internal network)
                       v
+---------------------------------------------+
|         API Gateway Sidecar                 |
|  (Holds real API credentials)               |
|                                             |
|  Endpoints:                                 |
|  /api/anthropic/* -> api.anthropic.com      |
|  /api/openai/*    -> api.openai.com         |
|  /api/google/*    -> googleapis.com         |
|                                             |
|  Auth: Session token (like git gateway)     |
|  Credentials: Real API keys in env          |
+---------------------------------------------+
```

---

## Implementation Plan

### Phase 1: API Gateway Service

**New files in `gateway/` (to be created):**

```
gateway/
├── Dockerfile.gateway        # Gateway container image
├── gateway.py                # Main HTTP server (Flask/Quart)
├── api_proxy.py              # API request proxying to upstream providers
├── api_routes.py             # Route handlers for /api/* endpoints
├── session_manager.py        # Session/token management (reuse for API scope)
├── audit.py                  # Audit logging
├── requirements.txt          # Python dependencies
└── config.yaml               # Gateway configuration
```

**`gateway/api_proxy.py`:**
```python
"""API proxy for AI provider requests."""

import os
import httpx
from typing import Dict, Optional
from quart import Request, Response

# Provider endpoint mappings
PROVIDER_ENDPOINTS = {
    'anthropic': 'https://api.anthropic.com',
    'openai': 'https://api.openai.com',
    'google': 'https://generativelanguage.googleapis.com',
}

# How to inject credentials for each provider
PROVIDER_AUTH_HEADERS = {
    'anthropic': ('x-api-key', 'ANTHROPIC_API_KEY'),
    'openai': ('Authorization', 'Bearer {OPENAI_API_KEY}'),
    'google': ('x-goog-api-key', 'GOOGLE_API_KEY'),
}

async def proxy_api_request(
    provider: str,
    path: str,
    request: Request,
    session_manager,
    audit,
) -> Response:
    """
    Proxy API request to upstream provider with real credentials.

    1. Validate session token
    2. Validate provider is in session scope
    3. Add real API credentials from gateway env
    4. Forward request to upstream
    5. Return response to sandbox
    """
    # Validate session token
    token = extract_token(request)
    if not session_manager.validate_api_request(token, provider):
        audit.log_event('blocked_api', provider=provider, reason='not_in_scope')
        return Response("Provider not in session scope", status=403)

    # Get upstream URL and credentials
    if provider not in PROVIDER_ENDPOINTS:
        return Response("Unknown provider", status=400)

    upstream_url = f"{PROVIDER_ENDPOINTS[provider]}/{path}"
    auth_header_name, env_var_pattern = PROVIDER_AUTH_HEADERS[provider]

    # Resolve env var (handle Bearer {VAR} pattern)
    if '{' in env_var_pattern:
        var_name = env_var_pattern.split('{')[1].split('}')[0]
        api_key = env_var_pattern.replace(f'{{{var_name}}}', os.environ.get(var_name, ''))
    else:
        api_key = os.environ.get(env_var_pattern, '')

    if not api_key:
        audit.log_event('api_key_missing', provider=provider)
        return Response(f"API key not configured for {provider}", status=500)

    # Build headers - forward most headers, inject auth
    headers = dict(request.headers)
    headers.pop('Host', None)
    headers.pop('Authorization', None)  # Remove sandbox auth
    headers[auth_header_name] = api_key

    # Forward request with real credentials
    async with httpx.AsyncClient(timeout=300) as client:
        response = await client.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=await request.get_data(),
        )

    audit.log_event(
        'api_proxied',
        provider=provider,
        path=path,
        status=response.status_code,
    )

    return Response(
        response.content,
        status=response.status_code,
        headers=dict(response.headers),
    )


def extract_token(request: Request) -> Optional[str]:
    """Extract session token from request."""
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    return request.args.get('token')
```

**`gateway/api_routes.py`:**
```python
"""API gateway route handlers."""

from quart import Blueprint, request
from .api_proxy import proxy_api_request, PROVIDER_ENDPOINTS

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/<provider>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
async def api_proxy(provider: str, path: str):
    """
    Route: /api/anthropic/v1/messages -> api.anthropic.com/v1/messages
    Route: /api/openai/v1/chat/completions -> api.openai.com/v1/chat/completions
    Route: /api/google/v1beta/models/... -> generativelanguage.googleapis.com/...
    """
    from . import session_manager, audit  # Import from gateway module

    if provider not in PROVIDER_ENDPOINTS:
        return "Unknown provider", 400

    return await proxy_api_request(provider, path, request, session_manager, audit)
```

---

### Phase 2: Session Scope Extension

**Modify `gateway/session_manager.py`:**

Extend the existing session manager (from git gateway) to include API provider scope:

```python
def create_session(
    self,
    repos: list[str],
    actions: list[str],
    api_providers: list[str] = None,  # NEW
) -> Session:
    """
    Extended to include API provider scope.

    Args:
        repos: Git repos this session can access
        actions: Git actions allowed (pull, push)
        api_providers: API providers allowed (anthropic, openai, google)
    """
    session_id = self._generate_session_id()
    access_token = self._generate_jwt(
        session_id,
        repos,
        actions,
        api_providers=api_providers or [],
        ttl=300,
    )
    # ...

def validate_api_request(self, token: str, provider: str) -> bool:
    """Validate token allows access to this API provider."""
    try:
        payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
        return provider in payload.get('scope', {}).get('api_providers', [])
    except jwt.InvalidTokenError:
        return False
```

**Updated JWT structure:**
```json
{
  "sub": "session:abc123",
  "type": "access",
  "exp": 1706400300,
  "scope": {
    "repos": ["github.com/org/foo"],
    "actions": ["pull", "push"],
    "api_providers": ["anthropic", "openai"]
  }
}
```

---

### Phase 3: foundry-mcp Gateway Mode

**New file: `src/foundry_mcp/core/providers/gateway_mode.py`:**

```python
"""
Gateway mode for running inside credential-isolated sandboxes.

When FOUNDRY_GATEWAY_MODE=1, foundry-mcp uses the LLM SDK layer
instead of CLI subprocess invocation, routing through the gateway.
"""

import os
from typing import Optional

GATEWAY_MODE = os.environ.get('FOUNDRY_GATEWAY_MODE', '0') == '1'
GATEWAY_URL = os.environ.get('FOUNDRY_GATEWAY_URL', 'https://gateway:8081')


def is_gateway_mode() -> bool:
    """Check if running in gateway mode."""
    return GATEWAY_MODE


def get_provider_base_url(provider: str) -> Optional[str]:
    """Get gateway-proxied base URL for provider SDK.

    Args:
        provider: Provider name (anthropic, openai, google)

    Returns:
        Gateway URL for the provider, or None if not in gateway mode
    """
    if not GATEWAY_MODE:
        return None
    return f"{GATEWAY_URL}/api/{provider}"


# Provider mapping: CLI provider ID -> SDK provider config
PROVIDER_SDK_CONFIG = {
    'claude': {
        'sdk_provider': 'anthropic',
        'sdk_class': 'AnthropicProvider',
    },
    'gemini': {
        'sdk_provider': 'google',
        'sdk_class': None,  # Not yet implemented - needs GoogleProvider
    },
    'codex': {
        'sdk_provider': 'openai',
        'sdk_class': 'OpenAIProvider',
    },
}


def get_sdk_provider_for_cli(cli_provider_id: str):
    """
    Get an SDK-based provider instance when in gateway mode.

    This allows CLI providers (claude, codex, gemini) to route through
    the gateway using the SDK layer instead of subprocess invocation.

    Args:
        cli_provider_id: The CLI provider ID (e.g., 'claude', 'codex')

    Returns:
        LLMProvider instance configured for gateway, or None if not supported
    """
    if not GATEWAY_MODE:
        return None

    config = PROVIDER_SDK_CONFIG.get(cli_provider_id)
    if not config or not config['sdk_class']:
        return None

    sdk_provider = config['sdk_provider']
    base_url = get_provider_base_url(sdk_provider)

    # Import and instantiate the appropriate SDK provider
    from foundry_mcp.core.llm_provider import OpenAIProvider, AnthropicProvider

    if config['sdk_class'] == 'AnthropicProvider':
        return AnthropicProvider(
            api_key='gateway-proxied',  # Gateway adds real key
            base_url=base_url,
        )
    elif config['sdk_class'] == 'OpenAIProvider':
        return OpenAIProvider(
            api_key='gateway-proxied',
            base_url=base_url,
        )

    return None


# CLI-only features that won't work in gateway mode
CLI_ONLY_FEATURES = {
    'codex': ['sandbox', 'exec'],  # OS-level sandboxing
    'claude': ['allowed-tools', 'disallowed-tools'],  # Tool restrictions
}


def check_feature_compatibility(provider: str, features: list[str]) -> bool:
    """Check if requested features work in gateway mode."""
    if not GATEWAY_MODE:
        return True

    cli_only = CLI_ONLY_FEATURES.get(provider, [])
    incompatible = set(features) & set(cli_only)

    if incompatible:
        import logging
        logging.warning(
            f"Features {incompatible} require CLI mode, not available in gateway mode. "
            f"Set FOUNDRY_GATEWAY_MODE=0 to use CLI (requires credentials in sandbox)."
        )
        return False
    return True
```

**Modify `src/foundry_mcp/core/providers/registry.py`:**

Add gateway mode routing to `resolve_provider()`:

```python
def resolve_provider(
    provider_id: str,
    *,
    hooks: ProviderHooks,
    model: Optional[str] = None,
    overrides: Optional[Dict[str, object]] = None,
) -> ProviderContext:
    """
    Instantiate a provider by ID using the registered factory.

    In gateway mode, CLI providers are routed through SDK layer instead.
    """
    # Check for gateway mode routing
    from foundry_mcp.core.providers.gateway_mode import (
        is_gateway_mode,
        get_sdk_provider_for_cli,
    )

    if is_gateway_mode() and provider_id in ('claude', 'codex', 'gemini'):
        sdk_provider = get_sdk_provider_for_cli(provider_id)
        if sdk_provider:
            # Wrap SDK provider in a ProviderContext adapter
            return SDKProviderAdapter(
                sdk_provider=sdk_provider,
                provider_id=provider_id,
                model=model,
                hooks=hooks,
            )

    # Normal resolution for non-gateway mode or unsupported providers
    registration = _REGISTRY.get(provider_id)
    if registration is None:
        raise ProviderUnavailableError(
            f"Provider '{provider_id}' is not registered.", provider=provider_id
        )
    # ... rest of existing implementation
```

---

### Phase 4: Sandbox Configuration

**Modify `docker-compose.yml`:**

```yaml
services:
  gateway:
    build:
      context: ./gateway
      dockerfile: Dockerfile.gateway
    environment:
      # Git credentials (existing)
      - GH_TOKEN
      - GITLAB_TOKEN
      # API credentials (new)
      - ANTHROPIC_API_KEY
      - OPENAI_API_KEY
      - GOOGLE_API_KEY
      - GEMINI_API_KEY
      # Gateway signing key
      - GATEWAY_JWT_SECRET
      # TLS config
      - GATEWAY_TLS_ENABLED=true
      - GATEWAY_TLS_CERT=/certs/gateway.crt
      - GATEWAY_TLS_KEY=/certs/gateway.key
    volumes:
      - gateway-certs:/certs:ro
    networks:
      - sandbox_internal
      - sandbox_external
    ports:
      - "8080:8080"  # Git gateway
      - "8081:8081"  # API gateway
    depends_on:
      gateway-init:
        condition: service_completed_successfully

  gateway-init:
    image: alpine/openssl
    command: |
      sh -c "
        if [ ! -f /certs/gateway.crt ]; then
          openssl req -x509 -newkey rsa:2048 -keyout /certs/gateway.key \
            -out /certs/gateway.crt -days 365 -nodes \
            -subj '/CN=gateway' -addext 'subjectAltName=DNS:gateway'
        fi
      "
    volumes:
      - gateway-certs:/certs

  dev:
    environment:
      # Git gateway (existing)
      - GIT_GATEWAY_URL=https://gateway:8080
      - GATEWAY_REFRESH_TOKEN=${GATEWAY_REFRESH_TOKEN}
      # API gateway (new)
      - FOUNDRY_GATEWAY_MODE=1
      - FOUNDRY_GATEWAY_URL=https://gateway:8081
      # NO API KEYS - gateway handles auth
    networks:
      - sandbox_internal
    depends_on:
      - gateway

networks:
  sandbox_internal:
    driver: bridge
    internal: true  # No external connectivity
  sandbox_external:
    driver: bridge

volumes:
  gateway-certs:
```

**Modify `commands/new.sh`:**

Add `--api-providers` flag support:

```bash
# In parse_new_args()
--api-providers|--api)
    shift
    NEW_API_PROVIDERS="$1"
    shift
    ;;

# In cmd_new()
sandbox_new() {
    local repos="$1"
    local api_providers="$NEW_API_PROVIDERS"  # e.g., "anthropic,openai"

    # Create session with API scope
    if [ -n "$api_providers" ]; then
        session=$(curl -sf https://gateway:8080/session/create \
            -d "repos=$repos" \
            -d "api_providers=$api_providers")

        export GATEWAY_REFRESH_TOKEN=$(echo "$session" | jq -r .refresh_token)
    fi

    # Start container with gateway mode enabled
    docker-compose up -d dev
}
```

---

### Phase 5: Streaming Support

AI APIs use Server-Sent Events (SSE) for streaming. The gateway must handle this:

```python
# gateway/api_proxy.py (updated)

async def proxy_api_request_streaming(
    provider: str,
    path: str,
    request: Request,
    session_manager,
    audit,
) -> Response:
    """Handle streaming responses (SSE) from AI APIs."""

    # ... validation same as non-streaming ...

    # Check if this is a streaming request
    body = await request.get_json()
    is_streaming = body.get('stream', False) if body else False

    if not is_streaming:
        return await proxy_api_request(provider, path, request, session_manager, audit)

    async def stream_response():
        async with httpx.AsyncClient(timeout=300) as client:
            async with client.stream(
                method=request.method,
                url=upstream_url,
                headers=headers,
                content=await request.get_data(),
            ) as response:
                async for chunk in response.aiter_bytes():
                    yield chunk

    return Response(
        stream_response(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache'},
    )
```

---

### Phase 6: SDKProviderAdapter

Bridge the LLMProvider interface to ProviderContext for gateway mode:

**New file: `src/foundry_mcp/core/providers/sdk_adapter.py`:**

```python
"""Adapter to use LLMProvider instances as ProviderContext."""

from typing import Optional
from foundry_mcp.core.llm_provider import LLMProvider, ChatRequest, ChatMessage, ChatRole
from foundry_mcp.core.providers.base import (
    ProviderContext,
    ProviderMetadata,
    ProviderRequest,
    ProviderResult,
    ProviderStatus,
    ProviderHooks,
    ProviderCapability,
    TokenUsage,
)


class SDKProviderAdapter(ProviderContext):
    """
    Adapter that wraps an LLMProvider for use as a ProviderContext.

    This enables foundry-mcp's CLI provider system to use the SDK-based
    providers (OpenAIProvider, AnthropicProvider) through the same interface.
    """

    def __init__(
        self,
        sdk_provider: LLMProvider,
        provider_id: str,
        model: Optional[str] = None,
        hooks: Optional[ProviderHooks] = None,
    ):
        metadata = ProviderMetadata(
            provider_id=provider_id,
            display_name=f"{provider_id} (gateway mode)",
            capabilities={ProviderCapability.TEXT, ProviderCapability.STREAMING},
        )
        super().__init__(metadata, hooks)
        self._sdk_provider = sdk_provider
        self._model = model

    def _execute(self, request: ProviderRequest) -> ProviderResult:
        """Execute via SDK provider."""
        import asyncio

        # Build chat request
        messages = []
        if request.system_prompt:
            messages.append(ChatMessage(role=ChatRole.SYSTEM, content=request.system_prompt))
        messages.append(ChatMessage(role=ChatRole.USER, content=request.prompt))

        chat_request = ChatRequest(
            messages=messages,
            max_tokens=request.max_tokens or 4096,
            temperature=request.temperature or 0.7,
            model=self._model,
        )

        # Run async in sync context
        loop = asyncio.get_event_loop()
        response = loop.run_until_complete(self._sdk_provider.chat(chat_request))

        return ProviderResult(
            content=response.message.content or '',
            provider_id=self._metadata.provider_id,
            model_used=response.model or self._model or 'unknown',
            status=ProviderStatus.SUCCESS,
            tokens=TokenUsage(
                input_tokens=response.usage.prompt_tokens,
                output_tokens=response.usage.completion_tokens,
                total_tokens=response.usage.total_tokens,
            ),
        )
```

---

## Files Summary

### foundry-sandbox (this repo)

| File | Action | Purpose |
|------|--------|---------|
| `gateway/Dockerfile.gateway` | Create | Gateway container image |
| `gateway/gateway.py` | Create | HTTP server (Quart/Flask), health checks, routing |
| `gateway/api_proxy.py` | Create | API request proxying logic |
| `gateway/api_routes.py` | Create | Route handlers for /api/* |
| `gateway/session_manager.py` | Create | Session creation, JWT tokens, scope validation |
| `gateway/audit.py` | Create | Structured audit logging |
| `gateway/requirements.txt` | Create | Python deps (quart, httpx, PyJWT) |
| `gateway/config.yaml` | Create | Gateway configuration |
| `docker-compose.yml` | Modify | Add gateway service, API env vars, networks |
| `commands/new.sh` | Modify | Add --api-providers flag |
| `lib/args.sh` | Modify | Parse --api-providers argument |

### foundry-mcp (separate repo)

| File | Action | Purpose |
|------|--------|---------|
| `src/foundry_mcp/core/providers/gateway_mode.py` | Create | Gateway mode detection and routing |
| `src/foundry_mcp/core/providers/sdk_adapter.py` | Create | LLMProvider to ProviderContext adapter |
| `src/foundry_mcp/core/providers/registry.py` | Modify | Route CLI providers to SDK in gateway mode |
| `src/foundry_mcp/core/llm_provider.py` | Verify | Already supports base_url (no changes needed) |

---

## Verification

### Positive Tests

| Test | Command | Expected |
|------|---------|----------|
| API proxy health | `curl https://gateway:8081/health` | 200 OK |
| Anthropic via gateway | `curl -X POST https://gateway:8081/api/anthropic/v1/messages -H "Authorization: Bearer $TOKEN" -d '{...}'` | Proxied to api.anthropic.com |
| foundry-mcp in gateway mode | `FOUNDRY_GATEWAY_MODE=1 foundry-mcp research chat "hello"` | Works without API key in sandbox |
| Session scope check | Request provider not in scope | 403 Forbidden |
| Streaming response | Chat completion with stream=true | SSE chunks proxied correctly |

### Negative Tests

| Test | Command | Expected |
|------|---------|----------|
| No API keys in sandbox | `env \| grep -E 'ANTHROPIC\|OPENAI\|GOOGLE'` | Empty |
| Direct API blocked | `curl --noproxy '*' https://api.anthropic.com` | Connection refused |
| Unauthorized provider | Request google when only anthropic in scope | 403 Forbidden |
| Missing API key on gateway | Gateway without ANTHROPIC_API_KEY | 500 error with clear message |

---

## Migration Path

1. **Phase 1**: Implement API gateway in foundry-sandbox (git gateway integration)
2. **Phase 2**: Add gateway mode to foundry-mcp, opt-in via `FOUNDRY_GATEWAY_MODE=1`
3. **Phase 3**: Test with existing sandbox setups
4. **Phase 4**: Make gateway mode default when `FOUNDRY_GATEWAY_URL` is set
5. **Phase 5**: Document limitations (CLI-only features unavailable in gateway mode)

---

## Known Limitations

1. **CLI-specific features unavailable**: Codex's OS-level sandbox, Claude's tool restrictions won't work in gateway mode
2. **Streaming latency**: Additional hop through gateway adds ~10-50ms per request
3. **Model availability**: SDK layer may have different model access than CLI
4. **Gemini SDK**: GoogleProvider not yet implemented in llm_provider.py - needs to be added

---

## Open Questions

1. Should the API gateway run on a separate port (8081) or share port 8080 with git gateway?
   - **Recommendation**: Separate port for cleaner separation of concerns
2. Do we need rate limiting per-provider in addition to per-session?
   - **Recommendation**: Start with per-session, add per-provider if needed
3. Should we support provider-specific timeout configurations?
   - **Recommendation**: Yes, AI APIs can have long response times for large contexts

---

## Dependencies

This plan depends on the base credential isolation gateway from `PLAN_CREDENTIAL_ISOLATION.md`. The API gateway extends that foundation with AI provider support.
