# Codex OAuth Credential Isolation

This document describes how to extend the credential isolation proxy to support Codex CLI's ChatGPT OAuth authentication (auth.json) rather than just environment variable-based API keys.

## Background

Codex CLI supports two authentication modes:

1. **API Key Auth** - Uses `env_key` in config.toml to read from environment variables
2. **ChatGPT OAuth** - Browser-based login that stores OAuth tokens in `~/.codex/auth.json`

The base credential isolation proxy spec handles API key injection via HTTP headers. This extension adds support for OAuth token-based authentication.

## OAuth Token Flow

When using ChatGPT login:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Sandbox        │     │  API Proxy      │     │  OpenAI API     │
│  (Codex CLI)    │     │  (mitmproxy)    │     │                 │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │  Request with         │                       │
         │  placeholder token    │                       │
         ├──────────────────────►│                       │
         │                       │  Request with         │
         │                       │  real OAuth token     │
         │                       ├──────────────────────►│
         │                       │                       │
         │                       │◄──────────────────────┤
         │◄──────────────────────┤                       │
         │                       │                       │
```

## Design

### 1. Stub auth.json in Sandbox

The sandbox container receives a stub `auth.json` with placeholder tokens:

```json
{
  "access_token": "CREDENTIAL_PROXY_PLACEHOLDER",
  "refresh_token": "CREDENTIAL_PROXY_PLACEHOLDER",
  "expires_at": 9999999999
}
```

- Codex reads this file and uses the placeholder in Authorization headers
- The `expires_at` is set far in the future so Codex doesn't attempt client-side refresh logic
- Sandbox never sees real credentials

### 2. Proxy Token Replacement

The mitmproxy addon intercepts requests and:

1. **Detects placeholder tokens** in Authorization headers
2. **Replaces with real OAuth token** from proxy's credential store
3. **Forwards request** to OpenAI API with valid credentials

```python
# inject-credentials.py additions

OAUTH_PLACEHOLDER = "CREDENTIAL_PROXY_PLACEHOLDER"

def request(self, flow: http.HTTPFlow) -> None:
    auth_header = flow.request.headers.get("Authorization", "")

    if OAUTH_PLACEHOLDER in auth_header:
        real_token = self.get_valid_oauth_token()
        flow.request.headers["Authorization"] = f"Bearer {real_token}"
```

### 3. Token Lifecycle Management

The proxy container manages OAuth token lifecycle:

```
┌─────────────────────────────────────────────────────────────┐
│  API Proxy Container                                        │
│                                                             │
│  ┌─────────────────┐    ┌─────────────────────────────┐    │
│  │  real_auth.json │───►│  Token Manager              │    │
│  │  (mounted)      │    │  - Check expiry             │    │
│  └─────────────────┘    │  - Refresh when needed      │    │
│                         │  - Return valid token       │    │
│                         └─────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

**Token refresh flow:**
1. Proxy checks if `access_token` is expired (or near expiry)
2. If expired, calls OpenAI token refresh endpoint with real `refresh_token`
3. Updates stored credentials
4. Returns fresh `access_token` for injection

### 4. Refresh Request Interception

If Codex attempts to refresh tokens (despite our far-future expiry):

1. Proxy intercepts refresh requests to OpenAI auth endpoints
2. Performs real refresh using proxy's credentials
3. Returns success response with placeholder token (sandbox continues using placeholder)

```python
REFRESH_ENDPOINTS = [
    "auth.openai.com/oauth/token",
    "auth0.openai.com/oauth/token",
]

def request(self, flow: http.HTTPFlow) -> None:
    if any(ep in flow.request.pretty_url for ep in REFRESH_ENDPOINTS):
        # Intercept and handle refresh internally
        self.handle_token_refresh(flow)
        return
```

## File Structure

```
api-proxy/
├── Dockerfile
├── entrypoint.sh
├── inject-credentials.py      # Extended for OAuth
├── oauth-token-manager.py     # New: token lifecycle management
└── stub-auth.json             # Template for sandbox

sandbox/
└── .codex/
    └── auth.json              # Mounted stub with placeholders
```

## Configuration

### docker-compose.credential-isolation.yml additions

```yaml
services:
  api-proxy:
    volumes:
      # Real credentials (host's auth.json)
      - ${HOME}/.codex/auth.json:/credentials/codex-auth.json:ro
    environment:
      - CODEX_AUTH_FILE=/credentials/codex-auth.json

  dev:
    volumes:
      # Stub credentials for sandbox
      - ./api-proxy/stub-auth.json:/home/user/.codex/auth.json:ro
```

## Security Considerations

1. **Real auth.json** is only mounted in the proxy container (read-only)
2. **Sandbox** only sees placeholder tokens that are useless outside the proxy
3. **Token refresh** happens in the proxy, sandbox never handles real refresh tokens
4. **Network isolation** ensures sandbox can't bypass proxy to reach OpenAI directly

## Implementation Tasks

1. **Create OAuth token manager** (`oauth-token-manager.py`)
   - Load real auth.json from mounted path
   - Check token expiry
   - Perform refresh when needed
   - Expose `get_valid_token()` method

2. **Extend credential injection addon**
   - Detect OAuth placeholder pattern
   - Call token manager for valid token
   - Handle refresh endpoint interception

3. **Create stub auth.json template**
   - Placeholder tokens
   - Far-future expiry

4. **Update compose override**
   - Mount real auth.json to proxy
   - Mount stub auth.json to sandbox

## Testing

1. **Token injection** - Verify Codex requests get real tokens injected
2. **Token refresh** - Let token expire, verify proxy refreshes automatically
3. **Isolation** - Confirm sandbox cannot access real credentials via env/filesystem
4. **Refresh interception** - Force Codex to attempt refresh, verify proxy handles it

## References

- [Codex Authentication](https://developers.openai.com/codex/auth/)
- [Codex Configuration Reference](https://developers.openai.com/codex/config-reference/)
- [Codex Advanced Configuration](https://developers.openai.com/codex/config-advanced/)
