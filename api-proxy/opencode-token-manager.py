"""
Multi-Provider OAuth Token Manager for OpenCode CLI Authentication

Manages OAuth token lifecycle for OpenCode's multi-provider authentication:
- Loads auth.json from mounted credentials path (provider-keyed structure)
- Parses ISO8601 expiry timestamps
- Per-provider token validation and refresh
- Supports both OAuth (type: "oauth") and API key (type: "api") credentials
- Thread-safe with per-provider locks

Uses httpx with proxy=None to bypass mitmproxy for token refresh.
"""

import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional

import httpx

# Token expiry buffer - refresh tokens that expire within this window
TOKEN_EXPIRY_BUFFER_SECONDS = 300  # 5 minutes

# Provider-specific refresh configurations
# Note: OpenAI client_id is public (installed app OAuth pattern)
# Source: https://github.com/openai/codex/blob/main/codex-rs/core/src/auth.rs
PROVIDER_REFRESH_CONFIG = {
    "anthropic": {
        "token_url": "https://auth.anthropic.com/oauth/token",
        "client_id": None,  # Anthropic uses different auth flow
    },
    "openai": {
        "token_url": "https://auth.openai.com/oauth/token",
        "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
    },
    "google": {
        "token_url": "https://oauth2.googleapis.com/token",
        "client_id": None,  # Requires client_id from auth file or env
    },
    "copilot": {
        "token_url": "https://github.com/login/oauth/access_token",
        "client_id": None,  # GitHub Copilot uses device flow
    },
}


class MultiProviderTokenManager:
    """Manages OAuth token lifecycle for OpenCode's multi-provider authentication."""

    def __init__(self, auth_file_path: str):
        """
        Initialize token manager with path to OpenCode auth.json.

        Args:
            auth_file_path: Path to the auth.json file (e.g., /credentials/opencode-auth.json)
        """
        self.auth_file_path = auth_file_path
        self._global_lock = threading.Lock()
        self._provider_locks: dict[str, threading.Lock] = {}
        self._providers: dict[str, dict] = {}

        # Load initial tokens
        self._load_tokens()

    def _get_provider_lock(self, provider: str) -> threading.Lock:
        """Get or create a lock for a specific provider."""
        with self._global_lock:
            if provider not in self._provider_locks:
                self._provider_locks[provider] = threading.Lock()
            return self._provider_locks[provider]

    def _load_tokens(self) -> None:
        """Load tokens from OpenCode auth.json file."""
        if not os.path.exists(self.auth_file_path):
            raise FileNotFoundError(f"Auth file not found: {self.auth_file_path}")

        with open(self.auth_file_path, "r") as f:
            data = json.load(f)

        # OpenCode auth.json has provider-keyed structure
        for provider, creds in data.items():
            if not isinstance(creds, dict):
                continue

            self._providers[provider] = {
                "access": creds.get("access"),
                "refresh": creds.get("refresh"),
                "expires": self._parse_expiry(creds.get("expires")),
                "type": creds.get("type", "oauth"),
                "key": creds.get("key"),  # For API key type
                # Preserve additional fields
                "accountId": creds.get("accountId"),
                "email": creds.get("email"),
                "projectId": creds.get("projectId"),
            }

    def _parse_expiry(self, expires: Optional[str]) -> float:
        """
        Parse ISO8601 expiry timestamp to Unix timestamp.

        Args:
            expires: ISO8601 formatted datetime string or None

        Returns:
            Unix timestamp as float, or 0 if parsing fails
        """
        if not expires:
            return 0

        try:
            # Parse ISO8601 format (e.g., "2099-12-31T23:59:59Z")
            dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            return dt.timestamp()
        except (ValueError, AttributeError):
            return 0

    def _format_expiry(self, timestamp: float) -> str:
        """
        Format Unix timestamp as ISO8601 string.

        Args:
            timestamp: Unix timestamp

        Returns:
            ISO8601 formatted datetime string
        """
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _is_token_expired(self, provider: str) -> bool:
        """Check if provider's token is expired or will expire within buffer period."""
        if provider not in self._providers:
            return True

        creds = self._providers[provider]

        # API keys don't expire
        if creds.get("type") == "api":
            return False

        expires = creds.get("expires", 0)
        import time

        return time.time() >= (expires - TOKEN_EXPIRY_BUFFER_SECONDS)

    def _refresh_access_token(self, provider: str) -> None:
        """
        Refresh the access token for a specific provider.

        Args:
            provider: Provider name (anthropic, openai, google, copilot)
        """
        if provider not in self._providers:
            raise ValueError(f"Unknown provider: {provider}")

        creds = self._providers[provider]
        refresh_token = creds.get("refresh")

        if not refresh_token:
            raise ValueError(f"No refresh token available for {provider}")

        config = PROVIDER_REFRESH_CONFIG.get(provider)
        if not config or not config.get("token_url"):
            raise ValueError(f"No refresh configuration for {provider}")

        # Use proxy=None to bypass mitmproxy for this request
        with httpx.Client(proxy=None, timeout=30.0) as client:
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }

            # Add client_id if configured
            if config.get("client_id"):
                payload["client_id"] = config["client_id"]

            headers = {"Content-Type": "application/json"}

            # GitHub requires Accept header for JSON response
            if provider == "copilot":
                headers["Accept"] = "application/json"

            response = client.post(
                config["token_url"],
                json=payload,
                headers=headers,
            )

        if response.status_code != 200:
            raise RuntimeError(
                f"Token refresh failed for {provider}: {response.status_code} - {response.text}"
            )

        data = response.json()

        # Update tokens - handle different response formats
        import time

        if "access_token" in data:
            creds["access"] = data["access_token"]
        elif "access" in data:
            creds["access"] = data["access"]

        if "refresh_token" in data:
            creds["refresh"] = data["refresh_token"]
        elif "refresh" in data:
            creds["refresh"] = data["refresh"]

        # Calculate expiry
        if "expires_in" in data:
            creds["expires"] = time.time() + data["expires_in"]
        elif "expires" in data:
            creds["expires"] = self._parse_expiry(data["expires"])
        else:
            # Default to 1 hour if no expiry info
            creds["expires"] = time.time() + 3600

        # Persist updated tokens
        self._save_tokens()

    def _save_tokens(self) -> None:
        """Save updated tokens back to auth.json file."""
        try:
            data = {}
            for provider, creds in self._providers.items():
                provider_data = {
                    "type": creds.get("type", "oauth"),
                }

                if creds.get("type") == "api":
                    provider_data["key"] = creds.get("key")
                else:
                    provider_data["access"] = creds.get("access")
                    provider_data["refresh"] = creds.get("refresh")
                    provider_data["expires"] = self._format_expiry(creds.get("expires", 0))

                # Include additional fields if present
                for field in ["accountId", "email", "projectId"]:
                    if creds.get(field):
                        provider_data[field] = creds[field]

                data[provider] = provider_data

            with open(self.auth_file_path, "w") as f:
                json.dump(data, f, indent=2)
        except OSError:
            # File might be read-only mounted; don't fail
            pass

    def get_providers(self) -> list[str]:
        """Get list of configured providers."""
        return list(self._providers.keys())

    def has_provider(self, provider: str) -> bool:
        """Check if a provider is configured."""
        return provider in self._providers

    def get_credential_type(self, provider: str) -> Optional[str]:
        """Get the credential type for a provider (oauth or api)."""
        if provider not in self._providers:
            return None
        return self._providers[provider].get("type", "oauth")

    def get_valid_token(self, provider: str) -> str:
        """
        Get a valid access token for a provider, refreshing if necessary.

        Args:
            provider: Provider name (anthropic, openai, google, copilot)

        Returns:
            Valid OAuth access token or API key

        Raises:
            ValueError: If provider not configured or no valid token available
            RuntimeError: If token refresh fails
        """
        if provider not in self._providers:
            raise ValueError(f"Provider not configured: {provider}")

        creds = self._providers[provider]

        # For API key type, return the key directly
        if creds.get("type") == "api":
            key = creds.get("key")
            if not key:
                raise ValueError(f"No API key configured for {provider}")
            return key

        # For OAuth type, check expiry and refresh if needed
        lock = self._get_provider_lock(provider)
        with lock:
            if self._is_token_expired(provider):
                self._refresh_access_token(provider)

            access_token = creds.get("access")
            if not access_token:
                raise ValueError(f"No valid access token for {provider}")
            return access_token

    def get_placeholder_response(self, provider: str) -> dict:
        """
        Generate a placeholder token response for intercepted refresh requests.

        Args:
            provider: Provider name

        Returns:
            Dict mimicking OAuth token response with placeholder values
        """
        return {
            "access_token": "CREDENTIAL_PROXY_PLACEHOLDER",
            "refresh_token": "CREDENTIAL_PROXY_PLACEHOLDER",
            "expires_in": 86400,
            "token_type": "Bearer",
        }
