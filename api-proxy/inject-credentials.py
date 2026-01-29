"""
Credential Injection mitmproxy Addon

Injects API credentials into outbound requests based on destination host.
Credentials are read from environment variables and injected as headers.

Provider Credential Map:
- api.anthropic.com: x-api-key from ANTHROPIC_API_KEY
- api.openai.com: Authorization Bearer from OPENAI_API_KEY
- generativelanguage.googleapis.com: x-goog-api-key from GOOGLE_API_KEY
- api.groq.com: Authorization Bearer from GROQ_API_KEY
- api.mistral.ai: Authorization Bearer from MISTRAL_API_KEY
- api.deepseek.com: Authorization Bearer from DEEPSEEK_API_KEY
- api.together.xyz: Authorization Bearer from TOGETHER_API_KEY
- openrouter.ai: Authorization Bearer from OPENROUTER_API_KEY
- api.fireworks.ai: Authorization Bearer from FIREWORKS_API_KEY
"""

import os
from mitmproxy import http, ctx


PROVIDER_MAP = {
    "api.anthropic.com": {
        "header": "x-api-key",
        "env_var": "ANTHROPIC_API_KEY",
        "format": "value",
    },
    "api.openai.com": {
        "header": "Authorization",
        "env_var": "OPENAI_API_KEY",
        "format": "bearer",
    },
    "generativelanguage.googleapis.com": {
        "header": "x-goog-api-key",
        "env_var": "GOOGLE_API_KEY",
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
}


class CredentialInjector:
    """mitmproxy addon that injects API credentials based on request host."""

    def __init__(self):
        self.credentials_cache = {}
        self._load_credentials()

    def _load_credentials(self):
        """Load credentials from environment variables into cache."""
        for host, config in PROVIDER_MAP.items():
            env_var = config["env_var"]
            value = os.environ.get(env_var)
            if value:
                self.credentials_cache[host] = {
                    "header": config["header"],
                    "value": self._format_value(value, config["format"]),
                }
                ctx.log.info(f"Loaded credential for {host} from {env_var}")
            else:
                ctx.log.warn(f"No credential for {host}: {env_var} not set")

    def _format_value(self, value: str, fmt: str) -> str:
        """Format credential value based on provider requirements."""
        if fmt == "bearer":
            return f"Bearer {value}"
        return value

    def request(self, flow: http.HTTPFlow) -> None:
        """Process outbound request and inject credentials if applicable."""
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

        if header_name in flow.request.headers:
            ctx.log.info(f"Replacing existing {header_name} header for {host}")
            del flow.request.headers[header_name]

        flow.request.headers[header_name] = cred["value"]
        ctx.log.info(f"Injected {header_name} for {host}")


addons = [CredentialInjector()]
