# Gemini CLI Credential Isolation

This document describes how to extend the credential isolation proxy to support Gemini CLI's OAuth authentication stored in `~/.gemini/oauth_creds.json`.

## Background

Gemini CLI supports multiple authentication methods:

1. **Login with Google (OAuth)** - Browser-based login, stores tokens in `~/.gemini/oauth_creds.json`
2. **API Key** - Via `GEMINI_API_KEY` environment variable
3. **Vertex AI** - Via `GOOGLE_APPLICATION_CREDENTIALS` or ADC

Like Codex, Gemini CLI uses a **single OAuth context** (not provider-keyed like OpenCode).

## oauth_creds.json Structure

Gemini CLI stores OAuth credentials at `~/.gemini/oauth_creds.json`:

```json
{
  "access_token": "ya29.xxx",
  "expiry_date": 1738200000000,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6...",
  "refresh_token": "1//xxx",
  "scope": "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/generative-language.retriever",
  "token_type": "Bearer"
}
```

**Note:** `expiry_date` is a Unix timestamp in milliseconds (not ISO 8601 like Codex/OpenCode).

## Two Approaches

### Approach A: API Key Injection (Simplest)

If API key auth is acceptable, use environment variable injection:

```bash
# Sandbox has empty var, proxy injects real key in headers
GEMINI_API_KEY=""
```

**Advantages:**
- Works with existing proxy design
- No OAuth complexity

**Limitations:**
- Requires API key (may have different rate limits than OAuth)
- Some features may require OAuth

### Approach B: OAuth Token Proxy (For Google Login)

For full OAuth support with Google account benefits:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Sandbox        │     │  API Proxy      │     │  Google APIs    │
│  (Gemini CLI)   │     │  (mitmproxy)    │     │                 │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │  Request with         │                       │
         │  placeholder token    │                       │
         ├──────────────────────►│                       │
         │                       │  Request with         │
         │                       │  real OAuth token     │
         │                       ├──────────────────────►│
         │                       │                       │
         │◄──────────────────────┤◄──────────────────────┤
         │                       │                       │
```

## Design (Approach B)

### 1. Stub oauth_creds.json in Sandbox

```json
{
  "access_token": "CREDENTIAL_PROXY_PLACEHOLDER",
  "expiry_date": 4102444800000,
  "id_token": "CREDENTIAL_PROXY_PLACEHOLDER",
  "refresh_token": "CREDENTIAL_PROXY_PLACEHOLDER",
  "scope": "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/generative-language.retriever",
  "token_type": "Bearer"
}
```

The far-future `expiry_date` (year 2100) prevents Gemini CLI from attempting client-side refresh.

### 2. Google API Host Detection

```python
GOOGLE_API_HOSTS = [
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "oauth2.googleapis.com",
]

def is_google_api_request(host: str) -> bool:
    return any(api_host in host for api_host in GOOGLE_API_HOSTS)
```

### 3. Token Manager for Gemini

```python
class GeminiTokenManager:
    def __init__(self, creds_file: str):
        self.creds_file = creds_file
        self.credentials = self._load_credentials()

    def _load_credentials(self) -> dict:
        with open(self.creds_file) as f:
            return json.load(f)

    def get_valid_token(self) -> str:
        # expiry_date is Unix timestamp in milliseconds
        expiry_ms = self.credentials.get("expiry_date", 0)
        expiry = datetime.fromtimestamp(expiry_ms / 1000, tz=timezone.utc)

        if datetime.now(timezone.utc) >= expiry:
            self._refresh_token()

        return self.credentials["access_token"]

    def _refresh_token(self):
        refresh_token = self.credentials["refresh_token"]
        # Google OAuth token refresh endpoint
        response = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }
        )
        data = response.json()
        self.credentials["access_token"] = data["access_token"]
        self.credentials["expiry_date"] = int(time.time() * 1000) + (data["expires_in"] * 1000)
        self._save_credentials()
```

**Note:** Google OAuth refresh requires client_id and client_secret from the original OAuth app registration.

### 4. Credential Injection Addon

```python
# inject-credentials.py

OAUTH_PLACEHOLDER = "CREDENTIAL_PROXY_PLACEHOLDER"

class GeminiCredentialInjector:
    def __init__(self):
        creds_file = os.environ.get("GEMINI_OAUTH_FILE")
        self.token_manager = GeminiTokenManager(creds_file)

    def request(self, flow: http.HTTPFlow) -> None:
        if not is_google_api_request(flow.request.host):
            return

        auth_header = flow.request.headers.get("Authorization", "")

        if OAUTH_PLACEHOLDER in auth_header:
            real_token = self.token_manager.get_valid_token()
            flow.request.headers["Authorization"] = f"Bearer {real_token}"
```

### 5. Handling id_token

The `id_token` is a JWT containing user identity claims. Some Google APIs may validate it. Options:

1. **Ignore** - Most Gemini API calls only use `access_token`
2. **Pass through** - Include real `id_token` in stub (less secure, but it's only identity info)
3. **Proxy intercept** - Replace `id_token` in request bodies if needed

For credential isolation, option 1 is usually sufficient.

## File Structure

```
api-proxy/
├── Dockerfile
├── entrypoint.sh
├── inject-credentials.py      # Extended for Gemini
├── token-manager-gemini.py    # Gemini-specific token lifecycle
└── stub-oauth-gemini.json     # Stub template

sandbox/
└── .gemini/
    └── oauth_creds.json       # Mounted stub with placeholders
```

## Configuration

### docker-compose.credential-isolation.yml additions

```yaml
services:
  api-proxy:
    volumes:
      # Real credentials (host's OAuth file)
      - ${HOME}/.gemini/oauth_creds.json:/credentials/gemini-oauth.json:ro
    environment:
      - GEMINI_OAUTH_FILE=/credentials/gemini-oauth.json
      # Google OAuth app credentials (for token refresh)
      - GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}

  dev:
    volumes:
      # Stub credentials for sandbox
      - ./api-proxy/stub-oauth-gemini.json:/home/user/.gemini/oauth_creds.json:ro
    environment:
      # Clear any API key env vars
      - GEMINI_API_KEY=
```

## Token Refresh Complexity

**Challenge:** Google OAuth refresh requires `client_id` and `client_secret` from the OAuth application that originally issued the tokens. Gemini CLI uses Google's own OAuth app.

**Options:**

1. **Extract from Gemini CLI** - The client_id/secret may be embedded in Gemini CLI source code (public OAuth apps often have "public" secrets)

2. **Use Google's refresh endpoint directly** - If Gemini CLI's OAuth client allows public refresh (some do)

3. **Re-authenticate periodically** - Accept that tokens expire and require re-auth outside the sandbox

4. **Long-lived tokens** - Some Google OAuth scopes issue long-lived refresh tokens that rarely need client credentials

## Comparison with Other CLIs

| Aspect | Codex | OpenCode | Gemini CLI |
|--------|-------|----------|------------|
| Auth file | `~/.codex/auth.json` | `~/.local/share/opencode/auth.json` | `~/.gemini/oauth_creds.json` |
| Structure | Single nested | Provider-keyed nested | Single flat |
| Expiry format | ISO 8601 | ISO 8601 | Unix ms timestamp |
| Token fields | `access_token`, `refresh_token` | `access`, `refresh` | `access_token`, `refresh_token` |
| Env var alternative | Via `env_key` | `{env:VAR}` syntax | `GEMINI_API_KEY` |
| Refresh complexity | Moderate | Per-provider | Requires client creds |

## Implementation Tasks

1. **Create Gemini token manager**
   - Load oauth_creds.json
   - Handle Unix ms timestamp expiry
   - Implement Google OAuth refresh (if client creds available)

2. **Extend credential injection addon**
   - Google API host detection
   - Bearer token replacement

3. **Create stub oauth_creds.json template**
   - Placeholder tokens
   - Far-future expiry

4. **Research Gemini CLI OAuth client**
   - Determine if client_id/secret are public
   - Test if refresh works without them

5. **Update compose override**
   - Mount real oauth_creds.json to proxy
   - Mount stub to sandbox

## Testing

1. **Token injection** - Verify Gemini requests get real tokens
2. **Token refresh** - Test automatic refresh when expired
3. **API key fallback** - Verify env var approach works
4. **Isolation** - Confirm sandbox cannot access real credentials

## Fallback: API Key Mode

If OAuth complexity is too high, use API key mode:

```yaml
# docker-compose.credential-isolation.yml
services:
  api-proxy:
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}  # Real key

  dev:
    environment:
      - GEMINI_API_KEY=  # Empty in sandbox
```

The proxy injects the API key via `x-goog-api-key` header for Google API requests.

## References

- [Gemini CLI Authentication](https://google-gemini.github.io/gemini-cli/docs/get-started/authentication.html)
- [Google OAuth 2.0 Token Refresh](https://developers.google.com/identity/protocols/oauth2/native-app#offline)
- [Gemini API Documentation](https://ai.google.dev/gemini-api/docs)
