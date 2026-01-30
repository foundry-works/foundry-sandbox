"""
OAuth Token Manager for Codex CLI Authentication

Manages OAuth token lifecycle for ChatGPT authentication:
- Loads auth.json from mounted credentials path
- Checks token expiry with configurable buffer
- Refreshes tokens via Auth0 endpoint
- Thread-safe token access

Uses httpx with proxy=None to bypass mitmproxy for token refresh.
"""

import json
import os
import time
import threading
from typing import Optional

import httpx

# OAuth configuration
OAUTH_TOKEN_URL = "https://auth0.openai.com/oauth/token"
OPENAI_CLIENT_ID = "REDACTED_CLIENT_ID"  # Codex CLI client ID
TOKEN_EXPIRY_BUFFER_SECONDS = 300  # 5 minutes


class OAuthTokenManager:
    """Manages OAuth token lifecycle for Codex CLI authentication."""

    def __init__(self, auth_file_path: str):
        """
        Initialize token manager with path to auth.json.

        Args:
            auth_file_path: Path to the auth.json file (e.g., /credentials/codex-auth.json)
        """
        self.auth_file_path = auth_file_path
        self._lock = threading.Lock()
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._expires_at: float = 0

        # Load initial tokens
        self._load_tokens()

    def _load_tokens(self) -> None:
        """Load tokens from auth.json file."""
        if not os.path.exists(self.auth_file_path):
            raise FileNotFoundError(f"Auth file not found: {self.auth_file_path}")

        with open(self.auth_file_path, "r") as f:
            data = json.load(f)

        # Handle both flat and nested token structures
        # Nested format (Codex CLI): {"tokens": {"access_token": ..., "refresh_token": ...}}
        # Flat format: {"access_token": ..., "refresh_token": ...}
        tokens = data.get("tokens", data)

        self._access_token = tokens.get("access_token")
        self._refresh_token = tokens.get("refresh_token")
        # Ensure expires_at is numeric (may be stored as string in some formats)
        expires_at_raw = data.get("expires_at") or data.get("last_refresh", 0)
        self._expires_at = float(expires_at_raw) if expires_at_raw else 0

        if not self._access_token or not self._refresh_token:
            raise ValueError("Invalid auth.json: missing access_token or refresh_token")

    def _is_token_expired(self) -> bool:
        """Check if token is expired or will expire within buffer period."""
        return time.time() >= (self._expires_at - TOKEN_EXPIRY_BUFFER_SECONDS)

    def _refresh_access_token(self) -> None:
        """Refresh the access token using the refresh token."""
        # Use proxy=None to bypass mitmproxy for this request
        # This avoids a loop where the proxy needs a token to proxy the token refresh
        with httpx.Client(proxy=None, timeout=30.0) as client:
            response = client.post(
                OAUTH_TOKEN_URL,
                json={
                    "grant_type": "refresh_token",
                    "client_id": OPENAI_CLIENT_ID,
                    "refresh_token": self._refresh_token,
                },
                headers={
                    "Content-Type": "application/json",
                },
            )

        if response.status_code != 200:
            raise RuntimeError(
                f"Token refresh failed: {response.status_code} - {response.text}"
            )

        data = response.json()
        self._access_token = data["access_token"]

        # Update refresh token if a new one was issued
        if "refresh_token" in data:
            self._refresh_token = data["refresh_token"]

        # Calculate expiry from expires_in (seconds from now)
        expires_in = data.get("expires_in", 3600)
        self._expires_at = time.time() + expires_in

        # Persist updated tokens to file for future sessions
        self._save_tokens()

    def _save_tokens(self) -> None:
        """Save updated tokens back to auth.json file."""
        try:
            data = {
                "access_token": self._access_token,
                "refresh_token": self._refresh_token,
                "expires_at": int(self._expires_at),
            }
            with open(self.auth_file_path, "w") as f:
                json.dump(data, f, indent=2)
        except OSError:
            # File might be read-only mounted; log but don't fail
            pass

    def get_valid_token(self) -> str:
        """
        Get a valid access token, refreshing if necessary.

        Returns:
            Valid OAuth access token

        Raises:
            RuntimeError: If token refresh fails
            ValueError: If no valid token available
        """
        with self._lock:
            if self._is_token_expired():
                self._refresh_access_token()
            if self._access_token is None:
                raise ValueError("No valid access token available")
            return self._access_token

    def get_placeholder_response(self) -> dict:
        """
        Generate a placeholder token response for intercepted refresh requests.

        Returns:
            Dict mimicking OAuth token response with placeholder values
        """
        return {
            "access_token": "CREDENTIAL_PROXY_PLACEHOLDER",
            "refresh_token": "CREDENTIAL_PROXY_PLACEHOLDER",
            "expires_in": 86400,
            "token_type": "Bearer",
        }
