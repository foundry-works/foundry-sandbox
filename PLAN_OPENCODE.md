# OpenCode Credential Isolation

This document describes how to extend the credential isolation proxy to support OpenCode CLI's authentication methods, including both OAuth tokens and API keys stored in `~/.local/share/opencode/auth.json`.

## Background

OpenCode supports multiple authentication methods:

1. **API Key Auth** - Direct API keys stored in auth.json or via `{env:VAR_NAME}` config syntax
2. **OAuth Auth** - Browser-based login for providers like GitHub Copilot, GitLab Duo, Anthropic

Unlike Codex (single auth context), OpenCode uses a **provider-keyed nested** structure where each provider has its own object with credential fields.

## Auth.json Structure

OpenCode stores credentials at `~/.local/share/opencode/auth.json` using a **nested provider-keyed** format:

```json
{
  "anthropic": {
    "access": "ant-access-xxx",
    "expires": "2026-02-01T00:00:00Z",
    "refresh": "ant-refresh-xxx",
    "type": "oauth"
  },
  "google": {
    "access": "ya29.xxx",
    "email": "user@gmail.com",
    "expires": "2026-02-01T00:00:00Z",
    "projectId": "my-project",
    "refresh": "1//xxx",
    "type": "oauth"
  },
  "openai": {
    "access": "oai-access-xxx",
    "accountId": "org-xxx",
    "expires": "2026-02-01T00:00:00Z",
    "refresh": "oai-refresh-xxx",
    "type": "oauth"
  },
  "zai-coding-plan": {
    "key": "sk-xxx",
    "type": "api"
  }
}
```

## Two Approaches

### Approach A: Environment Variable Injection (Recommended)

OpenCode natively supports environment variable references in config:

```json
// ~/.config/opencode/opencode.json in sandbox
{
  "provider": {
    "anthropic": {
      "apiKey": "{env:ANTHROPIC_API_KEY}"
    },
    "openai": {
      "apiKey": "{env:OPENAI_API_KEY}"
    }
  }
}
```

**How it works:**
1. Sandbox has config referencing env vars
2. Env vars are empty/placeholder in sandbox
3. OpenCode makes requests with placeholder credentials
4. Proxy intercepts and injects real API keys in headers

**Advantages:**
- No auth.json manipulation needed
- Works with existing proxy design
- Simpler implementation

**Limitations:**
- Only works for API key auth, not OAuth

### Approach B: OAuth Token Proxy (For OAuth Providers)

For providers requiring OAuth (GitHub Copilot, Anthropic OAuth):

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Sandbox        │     │  API Proxy      │     │  Provider API   │
│  (OpenCode)     │     │  (mitmproxy)    │     │                 │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │  Request with         │                       │
         │  placeholder token    │                       │
         ├──────────────────────►│                       │
         │                       │  Lookup provider      │
         │                       │  from request host    │
         │                       │                       │
         │                       │  Request with         │
         │                       │  real OAuth token     │
         │                       ├──────────────────────►│
         │                       │                       │
         │◄──────────────────────┤◄──────────────────────┤
         │                       │                       │
```

## Design (Approach B)

### 1. Stub auth.json in Sandbox

Nested provider-keyed structure with placeholder tokens:

```json
{
  "anthropic": {
    "access": "CREDENTIAL_PROXY_PLACEHOLDER",
    "expires": "2099-12-31T23:59:59Z",
    "refresh": "CREDENTIAL_PROXY_PLACEHOLDER",
    "type": "oauth"
  },
  "google": {
    "access": "CREDENTIAL_PROXY_PLACEHOLDER",
    "email": "placeholder@example.com",
    "expires": "2099-12-31T23:59:59Z",
    "projectId": "placeholder",
    "refresh": "CREDENTIAL_PROXY_PLACEHOLDER",
    "type": "oauth"
  },
  "openai": {
    "access": "CREDENTIAL_PROXY_PLACEHOLDER",
    "accountId": "placeholder",
    "expires": "2099-12-31T23:59:59Z",
    "refresh": "CREDENTIAL_PROXY_PLACEHOLDER",
    "type": "oauth"
  },
  "zai-coding-plan": {
    "key": "CREDENTIAL_PROXY_PLACEHOLDER",
    "type": "api"
  }
}
```

The far-future `expires` values prevent OpenCode from attempting client-side refresh.

### 2. Provider Detection

The proxy must map request hosts to providers:

```python
PROVIDER_HOSTS = {
    "api.anthropic.com": "anthropic",
    "api.openai.com": "openai",
    "api.githubcopilot.com": "copilot",
    "copilot-proxy.githubusercontent.com": "copilot",
}

def get_provider_for_host(host: str) -> str | None:
    for pattern, provider in PROVIDER_HOSTS.items():
        if pattern in host:
            return provider
    return None
```

### 3. Multi-Provider Token Manager

Handles the nested provider-keyed structure:

```python
class MultiProviderTokenManager:
    def __init__(self, auth_file: str):
        self.auth_file = auth_file
        self.credentials = self._load_credentials()

    def _load_credentials(self) -> dict:
        with open(self.auth_file) as f:
            return json.load(f)

    def get_valid_token(self, provider: str) -> str:
        creds = self.credentials.get(provider, {})

        if creds.get("type") == "api":
            # API key auth - return the key directly
            return creds.get("key")

        # OAuth: check expiry and refresh if needed
        if self._is_expired(creds.get("expires")):
            self._refresh_token(provider)

        return self.credentials[provider]["access"]

    def _is_expired(self, expires_str: str) -> bool:
        if not expires_str:
            return True
        expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) >= expires

    def _refresh_token(self, provider: str):
        refresh_token = self.credentials[provider]["refresh"]
        endpoint = REFRESH_ENDPOINTS[provider]
        # Perform refresh and update stored credentials
        new_access = self._do_refresh(endpoint, refresh_token)
        self.credentials[provider]["access"] = new_access
        self.credentials[provider]["expires"] = self._new_expiry()
        self._save_credentials()
```

### 4. Provider-Specific Refresh Endpoints

```python
REFRESH_ENDPOINTS = {
    "anthropic": "https://console.anthropic.com/oauth/token",
    "openai": "https://auth.openai.com/oauth/token",
    "copilot": "https://github.com/login/oauth/access_token",
}
```

### 5. Credential Injection Addon

```python
# inject-credentials.py

OAUTH_PLACEHOLDER = "CREDENTIAL_PROXY_PLACEHOLDER"

class OpenCodeCredentialInjector:
    def __init__(self):
        auth_file = os.environ.get("OPENCODE_AUTH_FILE")
        self.token_manager = MultiProviderTokenManager(auth_file)

    def request(self, flow: http.HTTPFlow) -> None:
        auth_header = flow.request.headers.get("Authorization", "")

        if OAUTH_PLACEHOLDER not in auth_header:
            return

        # Determine provider from request host
        provider = get_provider_for_host(flow.request.host)
        if not provider:
            return

        # Get valid token for this provider
        real_token = self.token_manager.get_valid_token(provider)

        # Inject real token
        flow.request.headers["Authorization"] = f"Bearer {real_token}"
```

## File Structure

```
api-proxy/
├── Dockerfile
├── entrypoint.sh
├── inject-credentials.py          # Extended for multi-provider
├── token-manager.py               # Multi-provider token lifecycle
├── stub-auth-codex.json           # Codex stub template
└── stub-auth-opencode.json        # OpenCode stub template

sandbox/
└── .local/share/opencode/
    └── auth.json                  # Mounted stub with placeholders
```

## Configuration

### docker-compose.credential-isolation.yml additions

```yaml
services:
  api-proxy:
    volumes:
      # Real credentials (host's auth files)
      - ${HOME}/.codex/auth.json:/credentials/codex-auth.json:ro
      - ${HOME}/.local/share/opencode/auth.json:/credentials/opencode-auth.json:ro
    environment:
      - CODEX_AUTH_FILE=/credentials/codex-auth.json
      - OPENCODE_AUTH_FILE=/credentials/opencode-auth.json

  dev:
    volumes:
      # Stub credentials for sandbox
      - ./api-proxy/stub-auth-codex.json:/home/user/.codex/auth.json:ro
      - ./api-proxy/stub-auth-opencode.json:/home/user/.local/share/opencode/auth.json:ro
```

## Hybrid Strategy

For maximum compatibility, use both approaches:

1. **API key providers** (OpenAI, Anthropic API) → Environment variable injection
2. **OAuth-only providers** (GitHub Copilot, GitLab Duo) → OAuth token proxy

```json
// Sandbox opencode.json - API keys via env vars
{
  "provider": {
    "anthropic": { "apiKey": "{env:ANTHROPIC_API_KEY}" },
    "openai": { "apiKey": "{env:OPENAI_API_KEY}" }
  }
}
```

```json
// Sandbox auth.json - OAuth providers with placeholders
{
  "copilot": {
    "access": "CREDENTIAL_PROXY_PLACEHOLDER",
    "expires": "2099-12-31T23:59:59Z",
    "refresh": "CREDENTIAL_PROXY_PLACEHOLDER",
    "type": "oauth"
  }
}
```

## Security Considerations

1. **Real auth.json** only in proxy container (read-only)
2. **Sandbox** sees only placeholders or empty env vars
3. **Per-provider isolation** - compromise of one provider doesn't expose others
4. **Network isolation** - sandbox cannot bypass proxy

## Comparison with Codex

| Aspect | Codex | OpenCode |
|--------|-------|----------|
| Auth file location | `~/.codex/auth.json` | `~/.local/share/opencode/auth.json` |
| Structure | Single nested context | Provider-keyed nested objects |
| Token field names | `access_token`, `refresh_token` | `access`, `refresh` |
| Env var support | Via `env_key` config | Native `{env:VAR}` syntax |
| OAuth providers | OpenAI only | Multiple (Anthropic, Google, OpenAI, etc.) |
| API key field | N/A | `key` (for `type: "api"`) |
| Recommended approach | OAuth proxy | Hybrid (env vars + OAuth proxy) |

## Implementation Tasks

1. **Create multi-provider token manager**
   - Load nested provider-keyed auth.json
   - Per-provider token expiry tracking
   - Per-provider refresh logic

2. **Extend credential injection addon**
   - Host-to-provider mapping
   - Multi-provider token lookup
   - Provider-specific header formats

3. **Create stub auth.json template for OpenCode**
   - All supported providers with placeholders

4. **Update compose override**
   - Mount real auth.json to proxy
   - Mount stub auth.json to sandbox
   - Mount opencode.json with env var references

## Testing

1. **API key injection** - Verify env var-based credentials work
2. **OAuth token injection** - Verify placeholder tokens get replaced
3. **Multi-provider** - Test switching between providers in one session
4. **Token refresh** - Verify each provider's refresh flow
5. **Isolation** - Confirm sandbox cannot access real credentials

## References

- [OpenCode Providers](https://opencode.ai/docs/providers/)
- [OpenCode Config](https://opencode.ai/docs/config/)
- [OpenCode CLI](https://opencode.ai/docs/cli/)
- [GitHub Issue #10950 - OAuth credentials override](https://github.com/anomalyco/opencode/issues/10950)
