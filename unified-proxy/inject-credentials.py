"""
Credential Injection mitmproxy Addon

Injects API credentials into outbound requests based on destination host.
Credentials are read from environment variables and injected as headers.

Provider Credential Map:
- api.anthropic.com: Authorization Bearer from CLAUDE_CODE_OAUTH_TOKEN,
                     or x-api-key from ANTHROPIC_API_KEY
- api.openai.com: Authorization Bearer from OPENAI_API_KEY
- generativelanguage.googleapis.com: x-goog-api-key from GOOGLE_API_KEY (or GEMINI_API_KEY)
- api.tavily.com: Authorization Bearer from TAVILY_API_KEY (header + body injection)
- api.semanticscholar.org: x-api-key from SEMANTIC_SCHOLAR_API_KEY
- api.perplexity.ai: Authorization Bearer from PERPLEXITY_API_KEY
- api.z.ai: x-api-key from ZHIPU_API_KEY
- api.github.com: Authorization Bearer from GITHUB_TOKEN (or GH_TOKEN)
- uploads.github.com: Authorization Bearer from GITHUB_TOKEN (or GH_TOKEN)

OAuth Support (Codex CLI):
- Detects CREDENTIAL_PROXY_PLACEHOLDER in Authorization header
- Injects real OAuth token from mounted auth.json
- Intercepts token refresh endpoints to return placeholder tokens

OAuth Support (Gemini CLI):
- Detects CREDENTIAL_PROXY_PLACEHOLDER in Authorization header
- Checks if request is to Gemini API hosts (generativelanguage/aiplatform)
- Injects real OAuth token from mounted oauth_creds.json

API Key Support (OpenCode CLI - zai-coding-plan):
- Detects OPENCODE_PLACEHOLDER in Authorization header
- Injects API key for Zhipu AI (open.bigmodel.cn, api.z.ai)
"""

import json
import os
from typing import Optional

from mitmproxy import http, ctx

# Import OAuth token manager (available when CODEX_AUTH_FILE is set)
try:
    from codex_token_manager import OAuthTokenManager
except ImportError:
    OAuthTokenManager = None  # type: ignore[misc, assignment]

# Import OpenCode API key manager (available when OPENCODE_AUTH_FILE is set)
try:
    from opencode_token_manager import OpenCodeKeyManager
except ImportError:
    OpenCodeKeyManager = None  # type: ignore[misc, assignment]

# Import Gemini OAuth token manager (available when GEMINI_OAUTH_FILE is set)
try:
    from gemini_token_manager import GeminiTokenManager
except ImportError:
    GeminiTokenManager = None  # type: ignore[misc, assignment]

# ============================================================================
# HOSTNAME ALLOWLIST (Egress Filtering)
# ============================================================================
# SECURITY: Only allow connections to explicitly allowlisted domains.
# This prevents data exfiltration to arbitrary external services.

ALLOWLIST_DOMAINS: list = []  # Exact domain matches
WILDCARD_DOMAINS: list = []   # Wildcard patterns (e.g., "*.openai.com")


def load_hostname_allowlist():
    """
    Load hostname allowlist from config/firewall-allowlist.generated.

    The allowlist is the single source of truth for domain filtering.
    """
    global ALLOWLIST_DOMAINS, WILDCARD_DOMAINS

    # Try multiple paths (inside container vs development)
    config_paths = [
        "/config/firewall-allowlist.generated",  # Docker volume mount
        "/app/firewall-allowlist.generated",     # Alternative mount
        os.path.join(os.path.dirname(__file__), "..", "config", "firewall-allowlist.generated"),  # Development
    ]

    config_path = None
    for path in config_paths:
        if os.path.exists(path):
            config_path = path
            break

    if not config_path:
        ctx.log.warn("Hostname allowlist not found - blocking all non-provider hosts")
        return

    try:
        import re
        with open(config_path, 'r') as f:
            content = f.read()

        # Parse ALLOWLIST_DOMAINS array from bash syntax
        allowlist_match = re.search(r'ALLOWLIST_DOMAINS=\(\s*(.*?)\s*\)', content, re.DOTALL)
        if allowlist_match:
            domains = re.findall(r'"([^"*][^"]*)"', allowlist_match.group(1))
            ALLOWLIST_DOMAINS = [d.lower() for d in domains]
            ctx.log.info(f"Loaded {len(ALLOWLIST_DOMAINS)} exact domain patterns")

        # Parse WILDCARD_DOMAINS array from bash syntax
        wildcard_match = re.search(r'WILDCARD_DOMAINS=\(\s*(.*?)\s*\)', content, re.DOTALL)
        if wildcard_match:
            wildcards = re.findall(r'"(\*\.[^"]+)"', wildcard_match.group(1))
            WILDCARD_DOMAINS = [w.lower() for w in wildcards]
            ctx.log.info(f"Loaded {len(WILDCARD_DOMAINS)} wildcard domain patterns")

        total = len(ALLOWLIST_DOMAINS) + len(WILDCARD_DOMAINS)
        ctx.log.info(f"Hostname allowlist loaded: {total} entries from {config_path}")

    except Exception as e:
        ctx.log.error(f"Failed to load hostname allowlist: {e}")


def is_hostname_allowed(hostname: str) -> bool:
    """
    Check if hostname is allowed by the egress allowlist.

    Args:
        hostname: The target hostname (e.g., "api.anthropic.com")

    Returns:
        bool: True if allowed, False if blocked
    """
    hostname = hostname.lower().rstrip('.')

    # Check exact domain matches
    if hostname in ALLOWLIST_DOMAINS:
        return True

    # Check wildcard patterns
    for pattern in WILDCARD_DOMAINS:
        pattern = pattern.lower().rstrip('.')
        if pattern.startswith('*.'):
            suffix = pattern[2:]  # "*.example.com" -> "example.com"
            if hostname == suffix or hostname.endswith('.' + suffix):
                return True

    return False


# Load allowlist at module initialization
load_hostname_allowlist()

# OAuth placeholder tokens that sandbox sees
OAUTH_PLACEHOLDER = "CREDENTIAL_PROXY_PLACEHOLDER"
OPENCODE_PLACEHOLDER = "PROXY_PLACEHOLDER_OPENCODE"
GITHUB_PLACEHOLDER_MARKER = "CREDENTIAL_PROXY_PLACEHOLDER"

# OAuth token refresh endpoints to intercept
REFRESH_ENDPOINTS = [
    ("auth.openai.com", "/oauth/token"),
    ("oauth2.googleapis.com", "/token"),
]

# Gemini API hosts (for OAuth token injection)
GEMINI_API_HOSTS = [
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "cloudcode-pa.googleapis.com",
]

# Zhipu AI API hosts (for OpenCode zai-coding-plan provider)
ZHIPU_API_HOSTS = [
    "open.bigmodel.cn",
    "api.z.ai",
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
    "api.z.ai": {
        "header": "x-api-key",
        "env_var": "ZHIPU_API_KEY",
        "format": "value",
    },
    # GitHub API hosts (for gh CLI and API access)
    "api.github.com": {
        "header": "Authorization",
        "env_var": "GITHUB_TOKEN",
        "fallback_env_var": "GH_TOKEN",
        "format": "bearer",
    },
    "uploads.github.com": {
        "header": "Authorization",
        "env_var": "GITHUB_TOKEN",
        "fallback_env_var": "GH_TOKEN",
        "format": "bearer",
    },
}


class CredentialInjector:
    """mitmproxy addon that injects API credentials based on request host."""

    def __init__(self):
        self.credentials_cache = {}
        self.oauth_manager: Optional[OAuthTokenManager] = None
        self.opencode_manager: Optional[OpenCodeKeyManager] = None
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
        """Initialize OpenCode API key manager if OPENCODE_AUTH_FILE is set."""
        opencode_auth_file = os.environ.get("OPENCODE_AUTH_FILE")
        if not opencode_auth_file:
            ctx.log.info("OPENCODE_AUTH_FILE not set, OpenCode API key support disabled")
            return

        if OpenCodeKeyManager is None:
            ctx.log.warn("OpenCode key manager module not available")
            return

        try:
            self.opencode_manager = OpenCodeKeyManager(opencode_auth_file)
            providers = self.opencode_manager.get_providers()
            ctx.log.info(
                f"OpenCode key manager initialized from {opencode_auth_file} "
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

    def _handle_refresh_intercept(self, flow: http.HTTPFlow) -> bool:
        """
        Intercept OAuth refresh requests and return placeholder tokens.

        Supports multiple OAuth providers:
        - auth.openai.com: Codex CLI (uses oauth_manager)
        - oauth2.googleapis.com: Gemini CLI (uses gemini_manager)

        Returns True if request was intercepted, False otherwise.
        """
        if not self._is_refresh_endpoint(flow):
            return False

        host = flow.request.host
        placeholder_response = None

        # Route to appropriate token manager based on endpoint
        if host == "auth.openai.com" and self.oauth_manager:
            ctx.log.info(f"Intercepting Codex OAuth refresh request to {host}")
            placeholder_response = self.oauth_manager.get_placeholder_response()
        elif host == "oauth2.googleapis.com" and self.gemini_manager:
            ctx.log.info(f"Intercepting Gemini OAuth refresh request to {host}")
            placeholder_response = self.gemini_manager.get_placeholder_response()

        if placeholder_response is None:
            return False

        flow.response = http.Response.make(
            200,
            json.dumps(placeholder_response).encode(),
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

        # Only handle OpenAI/ChatGPT endpoints (Codex CLI)
        # Don't intercept requests to other APIs like Anthropic
        host = flow.request.host
        if host not in ("api.openai.com", "auth.openai.com", "chatgpt.com"):
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

    def _handle_opencode_api_key_injection(self, flow: http.HTTPFlow) -> bool:
        """
        Detect OpenCode placeholder and inject API key for Zhipu AI.

        Checks if request is to Zhipu API hosts (open.bigmodel.cn, api.z.ai)
        and injects the API key from the zai-coding-plan provider.
        Falls back to ZHIPU_API_KEY env var if auth file not available.
        Returns True if API key was injected, False otherwise.
        """
        auth_header = flow.request.headers.get("Authorization", "")
        if OPENCODE_PLACEHOLDER not in auth_header:
            return False

        host = flow.request.host
        if host not in ZHIPU_API_HOSTS:
            return False

        api_key = None

        # Try to get API key from OpenCode auth file first
        if self.opencode_manager:
            if self.opencode_manager.has_provider("zai-coding-plan"):
                try:
                    api_key = self.opencode_manager.get_api_key("zai-coding-plan")
                    ctx.log.info(f"Got API key from OpenCode auth file for zai-coding-plan")
                except Exception as e:
                    ctx.log.warn(f"Failed to get API key from OpenCode auth file: {e}")
            else:
                ctx.log.warn("OpenCode zai-coding-plan provider not configured in auth file")
        else:
            ctx.log.info("OpenCode manager not available, trying ZHIPU_API_KEY env var")

        # Fall back to ZHIPU_API_KEY env var if auth file didn't work
        if not api_key:
            api_key = os.environ.get("ZHIPU_API_KEY")
            if api_key:
                ctx.log.info(f"Got API key from ZHIPU_API_KEY env var for OpenCode")
            else:
                ctx.log.error("No API key available: neither OpenCode auth file nor ZHIPU_API_KEY env var")
                flow.response = http.Response.make(
                    500,
                    json.dumps({"error": "Credential not configured: ZHIPU_API_KEY not set and OpenCode auth file not available"}).encode(),
                    {"Content-Type": "application/json"},
                )
                return True

        flow.request.headers["Authorization"] = f"Bearer {api_key}"
        ctx.log.info(f"Injected API key for OpenCode zai-coding-plan ({host})")
        return True

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

    def _handle_tavily_body_injection(self, flow: http.HTTPFlow) -> bool:
        """
        Inject Tavily API key into JSON request body.

        The Tavily MCP sends the API key in both the Authorization header AND
        the request body (api_key field). The header injection is handled by
        the standard host-based injection, but we also need to replace the
        placeholder in the body.

        Returns True if body was modified, False otherwise.
        """
        host = flow.request.host
        if host != "api.tavily.com":
            return False

        # Only process JSON requests
        content_type = flow.request.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            return False

        # Get the real API key from environment
        tavily_api_key = os.environ.get("TAVILY_API_KEY")
        if not tavily_api_key:
            ctx.log.warn("TAVILY_API_KEY not set, cannot inject into body")
            return False

        # Try to parse and modify the request body
        try:
            body = flow.request.get_text()
            if not body:
                return False

            data = json.loads(body)

            # Check if api_key field exists and contains placeholder
            if "api_key" not in data:
                return False

            current_key = data.get("api_key", "")
            if current_key == tavily_api_key:
                # Already has the real key, no modification needed
                return False

            # Replace placeholder with real API key
            data["api_key"] = tavily_api_key
            flow.request.set_text(json.dumps(data))
            ctx.log.info(f"Injected api_key into request body for {host}")
            return True

        except json.JSONDecodeError as e:
            ctx.log.warn(f"Failed to parse Tavily request body as JSON: {e}")
            return False
        except Exception as e:
            ctx.log.error(f"Error injecting Tavily API key into body: {e}")
            return False

    def request(self, flow: http.HTTPFlow) -> None:
        """Process outbound request and inject credentials if applicable."""
        host = flow.request.host

        # 0. SECURITY: Validate hostname against allowlist (egress filtering)
        # Block connections to non-allowlisted domains to prevent data exfiltration
        if not is_hostname_allowed(host):
            ctx.log.warn(f"BLOCKED: Request to non-allowlisted host: {host}")
            flow.response = http.Response.make(
                403,
                json.dumps({
                    "error": "Hostname not in allowlist",
                    "message": f"The destination host '{host}' is not permitted by the egress policy",
                    "host": host,
                }).encode(),
                {"Content-Type": "application/json"},
            )
            return

        # 1. Intercept OAuth refresh endpoints (return placeholder tokens)
        if self._handle_refresh_intercept(flow):
            return

        # 2. Handle OpenCode API key injection (zai-coding-plan / Zhipu AI)
        # Must run before Codex CLI handler because the OpenCode placeholder
        # contains "OPENCODE" which could cause matching issues.
        if self._handle_opencode_api_key_injection(flow):
            return

        # 3. Handle OAuth placeholder injection (Codex CLI)
        if self._handle_oauth_injection(flow):
            return

        # 4. Handle Gemini OAuth placeholder injection
        if self._handle_gemini_oauth_injection(flow):
            return

        # 5. Handle Tavily body-based credential injection
        # Tavily MCP sends api_key in both header AND body, so we need to
        # inject into the body as well. This runs before host-based injection
        # so headers are handled separately below.
        self._handle_tavily_body_injection(flow)

        # 6. Host-based API key injection (existing behavior)
        if host not in PROVIDER_MAP:
            return

        if host not in self.credentials_cache:
            if host in ("api.github.com", "uploads.github.com"):
                # Allow unauthenticated GitHub API requests when no token is available
                self._strip_github_placeholder(flow)
                ctx.log.info(f"No GitHub token available; allowing unauthenticated request to {host}")
                return
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

    def _strip_github_placeholder(self, flow: http.HTTPFlow) -> None:
        """Remove placeholder GitHub Authorization header to allow anonymous access."""
        auth_header = flow.request.headers.get("Authorization", "")
        if GITHUB_PLACEHOLDER_MARKER in auth_header:
            del flow.request.headers["Authorization"]
            ctx.log.info("Removed placeholder GitHub Authorization header")


addons = [CredentialInjector()]
