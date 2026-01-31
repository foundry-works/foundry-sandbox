"""
Credential Injection mitmproxy Addon

Injects API credentials into outbound requests based on destination host.
Credentials are read from environment variables and injected as headers.

Provider Credential Map:
- api.anthropic.com: Authorization Bearer from CLAUDE_CODE_OAUTH_TOKEN,
                     or x-api-key from ANTHROPIC_API_KEY
- api2.cursor.sh: Authorization Bearer from CURSOR_API_KEY
- api.openai.com: Authorization Bearer from OPENAI_API_KEY
- generativelanguage.googleapis.com: x-goog-api-key from GOOGLE_API_KEY (or GEMINI_API_KEY)
- api.groq.com: Authorization Bearer from GROQ_API_KEY
- api.mistral.ai: Authorization Bearer from MISTRAL_API_KEY
- api.deepseek.com: Authorization Bearer from DEEPSEEK_API_KEY
- api.together.xyz: Authorization Bearer from TOGETHER_API_KEY
- openrouter.ai: Authorization Bearer from OPENROUTER_API_KEY
- api.fireworks.ai: Authorization Bearer from FIREWORKS_API_KEY
- api.tavily.com: Authorization Bearer from TAVILY_API_KEY
- api.semanticscholar.org: x-api-key from SEMANTIC_SCHOLAR_API_KEY
- api.perplexity.ai: Authorization Bearer from PERPLEXITY_API_KEY

OAuth Support (Codex CLI):
- Detects CREDENTIAL_PROXY_PLACEHOLDER in Authorization header
- Injects real OAuth token from mounted auth.json
- Intercepts token refresh endpoints to return placeholder tokens

OAuth Support (OpenCode CLI):
- Detects CREDENTIAL_PROXY_PLACEHOLDER in Authorization header
- Maps request host to provider (e.g., api.anthropic.com -> "anthropic")
- Injects real OAuth token from multi-provider auth.json

OAuth Support (Gemini CLI):
- Detects CREDENTIAL_PROXY_PLACEHOLDER in Authorization header
- Checks if request is to Gemini API hosts (generativelanguage/aiplatform)
- Injects real OAuth token from mounted oauth_creds.json
"""

import json
import os
import sys
from typing import Optional

# Add the addon directory to Python path for token manager imports
_addon_dir = os.path.dirname(os.path.abspath(__file__))
if _addon_dir not in sys.path:
    sys.path.insert(0, _addon_dir)

from mitmproxy import http, ctx

# Import OAuth token manager (available when CODEX_AUTH_FILE is set)
try:
    from codex_token_manager import OAuthTokenManager
except ImportError:
    OAuthTokenManager = None  # type: ignore[misc, assignment]

# Import multi-provider OAuth token manager (available when OPENCODE_AUTH_FILE is set)
try:
    from opencode_token_manager import MultiProviderTokenManager
except ImportError:
    MultiProviderTokenManager = None  # type: ignore[misc, assignment]

# Import Gemini OAuth token manager (available when GEMINI_OAUTH_FILE is set)
try:
    from gemini_token_manager import GeminiTokenManager
except ImportError:
    GeminiTokenManager = None  # type: ignore[misc, assignment]

# OAuth placeholder token that sandbox sees
OAUTH_PLACEHOLDER = "CREDENTIAL_PROXY_PLACEHOLDER"

# JWT-formatted placeholder for id_token (Gemini validates JWT format locally)
# Contains CREDENTIAL_PROXY_PLACEHOLDER in the azp/aud claims for proxy detection
OAUTH_PLACEHOLDER_JWT = "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwgImF6cCI6ICJDUkVERU5USUFMX1BST1hZX1BMQUNFSE9MREVSIiwgImF1ZCI6ICJDUkVERU5USUFMX1BST1hZX1BMQUNFSE9MREVSIiwgInN1YiI6ICIwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCAiZW1haWwiOiAic2FuZGJveEBjcmVkZW50aWFsLXByb3h5LmxvY2FsIiwgImVtYWlsX3ZlcmlmaWVkIjogdHJ1ZSwgImlhdCI6IDE3MDAwMDAwMDAsICJleHAiOiA0MTAyNDQ0ODAwfQ.CREDENTIAL_PROXY_PLACEHOLDER_SIGNATURE"

# OAuth token refresh endpoints to intercept
REFRESH_ENDPOINTS = [
    ("auth.openai.com", "/oauth/token"),   # Legacy Auth0
    ("auth.openai.com", "/oauth/token"),    # New OpenAI auth
]

# Google OAuth validation endpoints (for placeholder token validation)
GOOGLE_VALIDATION_ENDPOINTS = [
    ("www.googleapis.com", "/oauth2/v1/tokeninfo"),
    ("www.googleapis.com", "/oauth2/v3/tokeninfo"),
    ("oauth2.googleapis.com", "/tokeninfo"),
]

# Google userinfo endpoint (called by Gemini CLI during init to validate user)
GOOGLE_USERINFO_ENDPOINTS = [
    ("www.googleapis.com", "/oauth2/v2/userinfo"),
    ("www.googleapis.com", "/oauth2/v1/userinfo"),
]

# OpenCode host-to-provider mapping
OPENCODE_PROVIDER_HOSTS = {
    "api.anthropic.com": "anthropic",
    "api.openai.com": "openai",
    "generativelanguage.googleapis.com": "google",
    "api.githubcopilot.com": "copilot",
    "copilot-proxy.githubusercontent.com": "copilot",
}

# Gemini API hosts (for OAuth token injection)
GEMINI_API_HOSTS = [
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "cloudcode-pa.googleapis.com",  # Gemini CLI initialization endpoint
]


PROVIDER_MAP = {
    "api.anthropic.com": {
        "header": "x-api-key",
        "env_var": "ANTHROPIC_API_KEY",
        "format": "value",
        # Alternative credential with different header (OAuth token)
        "alt_env_var": "CLAUDE_CODE_OAUTH_TOKEN",
        "alt_header": "Authorization",
        "alt_format": "bearer",
    },
    "api2.cursor.sh": {
        "header": "Authorization",
        "env_var": "CURSOR_API_KEY",
        "format": "bearer",
    },
    "api.openai.com": {
        "header": "Authorization",
        "env_var": "OPENAI_API_KEY",
        "format": "bearer",
    },
    "generativelanguage.googleapis.com": {
        "header": "x-goog-api-key",
        "env_var": "GOOGLE_API_KEY",
        "fallback_env_var": "GEMINI_API_KEY",
        "format": "value",
    },
    "api.groq.com": {
        "header": "Authorization",
        "env_var": "GROQ_API_KEY",
        "format": "bearer",
    },
    "api.mistral.ai": {
        "header": "Authorization",
        "env_var": "MISTRAL_API_KEY",
        "format": "bearer",
    },
    "api.deepseek.com": {
        "header": "Authorization",
        "env_var": "DEEPSEEK_API_KEY",
        "format": "bearer",
    },
    "api.together.xyz": {
        "header": "Authorization",
        "env_var": "TOGETHER_API_KEY",
        "format": "bearer",
    },
    "openrouter.ai": {
        "header": "Authorization",
        "env_var": "OPENROUTER_API_KEY",
        "format": "bearer",
    },
    "api.fireworks.ai": {
        "header": "Authorization",
        "env_var": "FIREWORKS_API_KEY",
        "format": "bearer",
    },
    "api.tavily.com": {
        "header": "Authorization",
        "env_var": "TAVILY_API_KEY",
        "format": "bearer",
    },
    "api.semanticscholar.org": {
        "header": "x-api-key",
        "env_var": "SEMANTIC_SCHOLAR_API_KEY",
        "format": "value",
    },
    "api.perplexity.ai": {
        "header": "Authorization",
        "env_var": "PERPLEXITY_API_KEY",
        "format": "bearer",
    },
}


class CredentialInjector:
    """mitmproxy addon that injects API credentials based on request host."""

    def __init__(self):
        self.credentials_cache = {}
        self.oauth_manager: Optional[OAuthTokenManager] = None
        self.opencode_manager: Optional[MultiProviderTokenManager] = None
        self.gemini_manager: Optional[GeminiTokenManager] = None
        self._load_credentials()
        self._init_oauth_manager()
        self._init_opencode_manager()
        self._init_gemini_manager()

    def _load_credentials(self):
        """Load credentials from environment variables into cache."""
        for host, config in PROVIDER_MAP.items():
            env_var = config["env_var"]
            fallback_env_var = config.get("fallback_env_var")
            alt_env_var = config.get("alt_env_var")

            value = None
            header = config["header"]
            fmt = config["format"]
            used_env_var = None

            # Priority 1: Alternative credential (e.g., CLAUDE_CODE_OAUTH_TOKEN)
            # Uses different header format than primary credential
            if alt_env_var:
                value = os.environ.get(alt_env_var)
                if value:
                    header = config["alt_header"]
                    fmt = config["alt_format"]
                    used_env_var = alt_env_var

            # Priority 2: Primary credential
            if not value:
                value = os.environ.get(env_var)
                used_env_var = env_var

            # Priority 3: Fallback credential (same header as primary)
            if not value and fallback_env_var:
                value = os.environ.get(fallback_env_var)
                used_env_var = fallback_env_var

            if value:
                self.credentials_cache[host] = {
                    "header": header,
                    "value": self._format_value(value, fmt),
                }
                ctx.log.info(f"Loaded credential for {host} from {used_env_var}")
            else:
                # Build list of all possible env vars for warning message
                env_vars = [env_var]
                if fallback_env_var:
                    env_vars.append(fallback_env_var)
                if alt_env_var:
                    env_vars.append(alt_env_var)
                ctx.log.warn(f"No credential for {host}: {' or '.join(env_vars)} not set")

    def _format_value(self, value: str, fmt: str) -> str:
        """Format credential value based on provider requirements."""
        if fmt == "bearer":
            return f"Bearer {value}"
        return value

    def _init_oauth_manager(self) -> None:
        """Initialize OAuth token manager if CODEX_AUTH_FILE is set."""
        codex_auth_file = os.environ.get("CODEX_AUTH_FILE")
        if not codex_auth_file:
            ctx.log.info("CODEX_AUTH_FILE not set, OAuth support disabled")
            return

        if OAuthTokenManager is None:
            ctx.log.warn("OAuth token manager module not available")
            return

        try:
            self.oauth_manager = OAuthTokenManager(codex_auth_file)
            ctx.log.info(f"OAuth token manager initialized from {codex_auth_file}")
        except FileNotFoundError:
            ctx.log.warn(f"OAuth auth file not found: {codex_auth_file}")
        except ValueError as e:
            ctx.log.warn(f"Invalid OAuth auth file: {e}")
        except Exception as e:
            ctx.log.warn(f"Failed to initialize OAuth manager: {e}")

    def _init_opencode_manager(self) -> None:
        """Initialize OpenCode multi-provider token manager if OPENCODE_AUTH_FILE is set."""
        opencode_auth_file = os.environ.get("OPENCODE_AUTH_FILE")
        if not opencode_auth_file:
            ctx.log.info("OPENCODE_AUTH_FILE not set, OpenCode OAuth support disabled")
            return

        if MultiProviderTokenManager is None:
            ctx.log.warn("Multi-provider token manager module not available")
            return

        try:
            self.opencode_manager = MultiProviderTokenManager(opencode_auth_file)
            providers = self.opencode_manager.get_providers()
            ctx.log.info(
                f"OpenCode multi-provider token manager initialized from {opencode_auth_file} "
                f"with providers: {', '.join(providers)}"
            )
        except FileNotFoundError:
            ctx.log.warn(f"OpenCode auth file not found: {opencode_auth_file}")
        except ValueError as e:
            ctx.log.warn(f"Invalid OpenCode auth file: {e}")
        except Exception as e:
            ctx.log.warn(f"Failed to initialize OpenCode manager: {e}")

    def _init_gemini_manager(self) -> None:
        """Initialize Gemini OAuth token manager if GEMINI_OAUTH_FILE is set."""
        gemini_auth_file = os.environ.get("GEMINI_OAUTH_FILE")
        if not gemini_auth_file:
            ctx.log.info("GEMINI_OAUTH_FILE not set, Gemini OAuth support disabled")
            return

        if GeminiTokenManager is None:
            ctx.log.warn("Gemini token manager module not available")
            return

        try:
            self.gemini_manager = GeminiTokenManager(gemini_auth_file)
            ctx.log.info(f"Gemini token manager initialized from {gemini_auth_file}")
        except FileNotFoundError:
            ctx.log.warn(f"Gemini auth file not found: {gemini_auth_file}")
        except ValueError as e:
            ctx.log.warn(f"Invalid Gemini auth file: {e}")
        except Exception as e:
            ctx.log.warn(f"Failed to initialize Gemini manager: {e}")

    def _is_refresh_endpoint(self, flow: http.HTTPFlow) -> bool:
        """Check if request is to an OAuth token refresh endpoint."""
        host = flow.request.host
        path = flow.request.path
        return any(host == h and path.startswith(p) for h, p in REFRESH_ENDPOINTS)

    def _is_gemini_refresh_endpoint(self, flow: http.HTTPFlow) -> bool:
        """Check if request is to Google OAuth token refresh endpoint."""
        host = flow.request.host
        path = flow.request.path
        return host == "oauth2.googleapis.com" and path.startswith("/token")

    def _handle_refresh_intercept(self, flow: http.HTTPFlow) -> bool:
        """
        Intercept OAuth refresh requests and return placeholder tokens.

        Returns True if request was intercepted, False otherwise.
        """
        if not self._is_refresh_endpoint(flow):
            return False

        if not self.oauth_manager:
            return False

        ctx.log.info(f"Intercepting OAuth refresh request to {flow.request.host}")
        placeholder_response = self.oauth_manager.get_placeholder_response()
        flow.response = http.Response.make(
            200,
            json.dumps(placeholder_response).encode(),
            {"Content-Type": "application/json"},
        )
        return True

    def _handle_gemini_refresh_intercept(self, flow: http.HTTPFlow) -> bool:
        """
        Intercept Google OAuth refresh requests for Gemini CLI.

        Returns True if request was intercepted, False otherwise.
        """
        if not self._is_gemini_refresh_endpoint(flow):
            return False

        if not self.gemini_manager:
            return False

        # Verify it's a refresh_token grant
        try:
            content_type = flow.request.headers.get("Content-Type", "")
            body_text = flow.request.get_text()

            if "application/x-www-form-urlencoded" in content_type:
                from urllib.parse import parse_qs
                params = parse_qs(body_text)
                grant_type = params.get("grant_type", [""])[0]
            elif "application/json" in content_type:
                params = json.loads(body_text)
                grant_type = params.get("grant_type", "")
            else:
                return False

            if grant_type != "refresh_token":
                return False
        except Exception:
            return False

        ctx.log.info("Intercepting Google OAuth refresh request for Gemini")

        # Google OAuth returns expires_in (seconds), not expiry_date (ms)
        # id_token must be valid JWT format as Gemini validates it locally
        response_data = {
            "access_token": OAUTH_PLACEHOLDER,
            "expires_in": 3600,
            "scope": self.gemini_manager._scope or "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/generative-language.retriever",
            "token_type": "Bearer",
            "id_token": OAUTH_PLACEHOLDER_JWT,
        }

        flow.response = http.Response.make(
            200,
            json.dumps(response_data).encode(),
            {"Content-Type": "application/json"},
        )
        return True

    def _handle_google_tokeninfo_intercept(self, flow: http.HTTPFlow) -> bool:
        """
        Intercept Google tokeninfo requests to validate placeholder tokens.

        Returns True if request was intercepted, False otherwise.
        """
        host = flow.request.host
        path = flow.request.path

        is_tokeninfo = any(
            host == h and path.startswith(p)
            for h, p in GOOGLE_VALIDATION_ENDPOINTS
        )

        if not is_tokeninfo or not self.gemini_manager:
            return False

        # Check for placeholder token in request (URL, body, or Authorization header)
        # google-auth-library sends token in Authorization header: Bearer <token>
        auth_header = flow.request.headers.get("Authorization", "")
        request_content = flow.request.get_text() + flow.request.url + auth_header
        if OAUTH_PLACEHOLDER not in request_content:
            return False

        ctx.log.info("Intercepting Google tokeninfo for placeholder validation")

        import time
        response_data = {
            "azp": "gemini-cli",
            "aud": "gemini-cli",
            "scope": self.gemini_manager._scope or "https://www.googleapis.com/auth/cloud-platform",
            "exp": str(int(time.time()) + 3600),
            "expires_in": "3600",
            "access_type": "offline",
        }

        flow.response = http.Response.make(
            200,
            json.dumps(response_data).encode(),
            {"Content-Type": "application/json"},
        )
        return True

    def _handle_google_userinfo_intercept(self, flow: http.HTTPFlow) -> bool:
        """
        Intercept Google userinfo requests to validate placeholder tokens.

        Gemini CLI calls this endpoint during initialization to verify the user.
        Returns True if request was intercepted, False otherwise.
        """
        host = flow.request.host
        path = flow.request.path

        is_userinfo = any(
            host == h and path.startswith(p)
            for h, p in GOOGLE_USERINFO_ENDPOINTS
        )

        if not is_userinfo:
            return False

        # Check for placeholder token in Authorization header
        auth_header = flow.request.headers.get("Authorization", "")
        if OAUTH_PLACEHOLDER not in auth_header:
            return False

        ctx.log.info("Intercepting Google userinfo for placeholder validation")

        # Return fake userinfo response matching the stub oauth_creds.json
        response_data = {
            "id": "000000000000000000000",
            "email": "sandbox@credential-proxy.local",
            "verified_email": True,
            "name": "Sandbox User",
            "given_name": "Sandbox",
            "family_name": "User",
            "picture": "",
            "locale": "en",
        }

        flow.response = http.Response.make(
            200,
            json.dumps(response_data).encode(),
            {"Content-Type": "application/json"},
        )
        return True

    def _handle_oauth_injection(self, flow: http.HTTPFlow) -> bool:
        """
        Detect OAuth placeholder and inject real token (Codex CLI only).

        This handler is specifically for Codex CLI which uses OpenAI OAuth.
        Only processes requests to OpenAI endpoints to avoid intercepting
        requests from other tools (like Claude Code) that might also have
        placeholder tokens in their Authorization headers.

        Returns True if OAuth token was injected, False otherwise.
        """
        if not self.oauth_manager:
            return False

        auth_header = flow.request.headers.get("Authorization", "")
        if OAUTH_PLACEHOLDER not in auth_header:
            return False

        # Only handle OpenAI endpoints (Codex CLI)
        # Don't intercept requests to other APIs like Anthropic
        # Codex CLI uses chatgpt.com/backend-api for API calls
        host = flow.request.host
        if host not in ("api.openai.com", "auth.openai.com", "auth.openai.com", "chatgpt.com"):
            return False

        try:
            real_token = self.oauth_manager.get_valid_token()
            flow.request.headers["Authorization"] = f"Bearer {real_token}"
            ctx.log.info(f"Injected real OAuth token for {flow.request.host}")
            return True
        except Exception as e:
            ctx.log.error(f"Failed to get OAuth token: {e}")
            flow.response = http.Response.make(
                500,
                json.dumps({"error": f"OAuth token error: {e}"}).encode(),
                {"Content-Type": "application/json"},
            )
            return True

    def _handle_opencode_oauth_injection(self, flow: http.HTTPFlow) -> bool:
        """
        Detect OpenCode OAuth placeholder and inject real token.

        Maps request host to provider and retrieves the appropriate token.
        Returns True if OAuth token was injected, False otherwise.
        """
        if not self.opencode_manager:
            return False

        auth_header = flow.request.headers.get("Authorization", "")
        if OAUTH_PLACEHOLDER not in auth_header:
            return False

        host = flow.request.host
        provider = OPENCODE_PROVIDER_HOSTS.get(host)
        if not provider:
            return False

        if not self.opencode_manager.has_provider(provider):
            ctx.log.warn(f"OpenCode provider {provider} not configured in auth file")
            return False

        try:
            real_token = self.opencode_manager.get_valid_token(provider)
            flow.request.headers["Authorization"] = f"Bearer {real_token}"
            ctx.log.info(f"Injected real OAuth token for OpenCode provider {provider} ({host})")
            return True
        except Exception as e:
            # Log warning and fall through to host-based injection
            # This allows CLAUDE_CODE_OAUTH_TOKEN to be used as fallback for api.anthropic.com
            ctx.log.warn(f"OpenCode OAuth failed for {provider}, falling back to host-based injection: {e}")
            return False

    def _handle_gemini_oauth_injection(self, flow: http.HTTPFlow) -> bool:
        """
        Detect Gemini OAuth placeholder and inject real token.

        Checks if the request is to a Gemini API host and the Authorization
        header contains the placeholder token.
        Returns True if OAuth token was injected, False otherwise.
        """
        if not self.gemini_manager:
            return False

        auth_header = flow.request.headers.get("Authorization", "")
        if OAUTH_PLACEHOLDER not in auth_header:
            return False

        host = flow.request.host
        if host not in GEMINI_API_HOSTS:
            return False

        try:
            real_token = self.gemini_manager.get_valid_token()
            flow.request.headers["Authorization"] = f"Bearer {real_token}"
            ctx.log.info(f"Injected real OAuth token for Gemini ({host})")
            return True
        except Exception as e:
            ctx.log.error(f"Failed to get Gemini OAuth token: {e}")
            flow.response = http.Response.make(
                500,
                json.dumps({"error": f"Gemini OAuth token error: {e}"}).encode(),
                {"Content-Type": "application/json"},
            )
            return True

    def request(self, flow: http.HTTPFlow) -> None:
        """Process outbound request and inject credentials if applicable."""
        # 1. Intercept Google userinfo requests (for Gemini init validation)
        if self._handle_google_userinfo_intercept(flow):
            return

        # 2. Intercept Google tokeninfo (validation) requests
        if self._handle_google_tokeninfo_intercept(flow):
            return

        # 3. Intercept Gemini OAuth refresh requests
        if self._handle_gemini_refresh_intercept(flow):
            return

        # 4. Intercept Codex OAuth refresh endpoints (return placeholder tokens)
        if self._handle_refresh_intercept(flow):
            return

        # 5. Handle OAuth placeholder injection (Codex CLI)
        if self._handle_oauth_injection(flow):
            return

        # 6. Handle Gemini OAuth placeholder injection (before OpenCode to prioritize Gemini for its API hosts)
        if self._handle_gemini_oauth_injection(flow):
            return

        # 7. Handle OpenCode OAuth placeholder injection
        if self._handle_opencode_oauth_injection(flow):
            return

        # 8. Host-based API key injection (existing behavior)
        host = flow.request.host

        if host not in PROVIDER_MAP:
            return

        if host not in self.credentials_cache:
            ctx.log.error(f"Missing credential for {host}, returning 500")
            flow.response = http.Response.make(
                500,
                b'{"error": "Credential not configured for this provider"}',
                {"Content-Type": "application/json"},
            )
            return

        cred = self.credentials_cache[host]
        header_name = cred["header"]

        # Remove any existing credential headers (may contain placeholders)
        # This ensures we don't send placeholder values to the API
        for header_to_remove in ["x-api-key", "Authorization"]:
            if header_to_remove in flow.request.headers:
                ctx.log.info(f"Removing placeholder {header_to_remove} header for {host}")
                del flow.request.headers[header_to_remove]

        flow.request.headers[header_name] = cred["value"]
        ctx.log.info(f"Injected {header_name} for {host}")


addons = [CredentialInjector()]
