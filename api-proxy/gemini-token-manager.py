"""
Gemini CLI OAuth Token Manager

Manages OAuth token lifecycle for Gemini CLI authentication:
- Loads oauth_creds.json from mounted credentials path
- Parses expiry_date as Unix milliseconds (divide by 1000)
- Token expiry check with 300-second buffer
- Thread-safe with single lock (like Codex, not per-provider)
- Automatic token refresh using embedded Gemini CLI OAuth credentials

Uses httpx with proxy=None to bypass mitmproxy for token operations.
"""

import json
import os
import time
import threading
from typing import Optional

import httpx

# Token expiry buffer - consider token expired if within this window
TOKEN_EXPIRY_BUFFER_SECONDS = 300  # 5 minutes

# Gemini CLI OAuth credentials (embedded in CLI source, safe to use)
# https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/code_assist/oauth2.ts
GEMINI_CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
GEMINI_CLIENT_SECRET = "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"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


class GeminiTokenManager:
    """Manages OAuth token lifecycle for Gemini CLI authentication."""

    def __init__(self, auth_file_path: str):
        """
        Initialize token manager with path to oauth_creds.json.

        Args:
            auth_file_path: Path to the oauth_creds.json file
                           (e.g., /credentials/gemini-oauth.json)
        """
        self.auth_file_path = auth_file_path
        self._lock = threading.Lock()
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._id_token: Optional[str] = None
        self._expires_at: float = 0
        self._scope: Optional[str] = None
        self._token_type: str = "Bearer"

        # Load initial tokens
        self._load_tokens()

    def _load_tokens(self) -> None:
        """Load tokens from oauth_creds.json file."""
        if not os.path.exists(self.auth_file_path):
            raise FileNotFoundError(f"Auth file not found: {self.auth_file_path}")

        with open(self.auth_file_path, "r") as f:
            data = json.load(f)

        self._access_token = data.get("access_token")
        self._refresh_token = data.get("refresh_token")
        self._id_token = data.get("id_token")
        self._scope = data.get("scope")
        self._token_type = data.get("token_type", "Bearer")

        # Critical: expiry_date is in Unix milliseconds, convert to seconds
        expiry_ms = data.get("expiry_date", 0)
        self._expires_at = expiry_ms / 1000.0 if expiry_ms else 0

        if not self._access_token:
            raise ValueError("Invalid oauth_creds.json: missing access_token")

    def _is_token_expired(self) -> bool:
        """Check if token is expired or will expire within buffer period."""
        return time.time() >= (self._expires_at - TOKEN_EXPIRY_BUFFER_SECONDS)

    def _refresh_access_token(self) -> None:
        """
        Refresh the access token using the refresh token.

        Uses Gemini CLI's embedded OAuth credentials to refresh the token.
        """
        if not self._refresh_token:
            raise RuntimeError(
                "Gemini OAuth token expired and no refresh token available. "
                "Please run 'gemini login' outside the sandbox."
            )

        # Use httpx with proxy=None to bypass mitmproxy
        try:
            response = httpx.post(
                GOOGLE_TOKEN_URL,
                data={
                    "client_id": GEMINI_CLIENT_ID,
                    "client_secret": GEMINI_CLIENT_SECRET,
                    "refresh_token": self._refresh_token,
                    "grant_type": "refresh_token",
                },
                proxy=None,  # Bypass mitmproxy
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()

            # Update tokens
            self._access_token = data.get("access_token")
            self._id_token = data.get("id_token")

            # Calculate expiry from expires_in (seconds)
            expires_in = data.get("expires_in", 3600)
            self._expires_at = time.time() + expires_in

            # Update scope if provided
            if "scope" in data:
                self._scope = data["scope"]

        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"Failed to refresh Gemini OAuth token: {e.response.status_code} - "
                f"{e.response.text}"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to refresh Gemini OAuth token: {e}")

    def get_valid_token(self) -> str:
        """
        Get a valid access token, refreshing if necessary.

        Automatically refreshes the token using Gemini CLI's embedded
        OAuth credentials if the current token is expired.

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
        # Use far-future expiry (Jan 1, 2100 in milliseconds) to prevent
        # client-side refresh attempts
        return {
            "access_token": "CREDENTIAL_PROXY_PLACEHOLDER",
            "refresh_token": "CREDENTIAL_PROXY_PLACEHOLDER",
            "expiry_date": 4102444800000,  # Jan 1, 2100 in milliseconds
            "id_token": "CREDENTIAL_PROXY_PLACEHOLDER",
            "scope": self._scope or "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/generative-language.retriever",
            "token_type": "Bearer",
        }
