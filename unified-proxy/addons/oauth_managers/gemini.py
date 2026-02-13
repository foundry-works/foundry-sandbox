"""
Gemini CLI OAuth Token Manager

Manages OAuth token lifecycle for Gemini CLI authentication:
- Loads oauth_creds.json from mounted credentials path
- Parses expiry_date as Unix milliseconds (divide by 1000)
- Token expiry check with 300-second buffer
- Thread-safe with single lock (like Codex, not per-provider)

Uses httpx with proxy=None to bypass mitmproxy for token operations.

Note: Token refresh requires client_id and client_secret from Gemini CLI.
For this implementation, automatic refresh is skipped - tokens from
`gemini login` are long-lived and manual re-authentication is required
when they expire.
"""

import base64
import json
import os
import secrets
import time
import threading
from typing import Optional

# Token expiry buffer - consider token expired if within this window
TOKEN_EXPIRY_BUFFER_SECONDS = 300  # 5 minutes


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

        Note: Google OAuth refresh requires client_id and client_secret.
        Since we don't have access to Gemini CLI's OAuth credentials,
        this method raises an error indicating manual re-authentication
        is required.
        """
        # Token refresh requires client credentials we don't have
        # The user needs to run `gemini login` again outside the sandbox
        raise RuntimeError(
            "Gemini OAuth token expired. Please run 'gemini login' "
            "outside the sandbox to refresh your credentials."
        )

    def get_valid_token(self) -> str:
        """
        Get the access token for injection.

        For Gemini, we don't check expiry here - we just return the token
        and let the API call fail if it's expired. This gives clearer error
        messages to the user than a proxy-side check.

        Returns:
            OAuth access token

        Raises:
            ValueError: If no token available
        """
        with self._lock:
            if self._access_token is None:
                raise ValueError("No valid access token available")
            return self._access_token

    def get_placeholder_response(self) -> dict:
        """
        Generate a placeholder token response for intercepted refresh requests.

        Returns:
            Dict mimicking Google OAuth token response with per-request
            randomized placeholder values. Contains CREDENTIAL_PROXY_PLACEHOLDER
            marker for detection by credential injector.
        """
        nonce = secrets.token_hex(8)
        # Build a per-request id_token JWT with random jti and signature
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": "https://accounts.google.com",
            "azp": "CREDENTIAL_PROXY_PLACEHOLDER",
            "aud": "CREDENTIAL_PROXY_PLACEHOLDER",
            "sub": "00000000000000000000",
            "email": "sandbox@credential-proxy.local",
            "email_verified": True,
            "iat": int(time.time()),
            "exp": 4102444800,
            "jti": secrets.token_hex(16),
        }
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        s = secrets.token_urlsafe(32)
        return {
            "access_token": f"ya29.CREDENTIAL_PROXY_PLACEHOLDER_{nonce}",
            "refresh_token": f"1//CREDENTIAL_PROXY_PLACEHOLDER_{nonce}",
            "expires_in": 2147483647,  # Max int32 seconds (~68 years)
            "id_token": f"{h}.{p}.{s}",
            "scope": self._scope or "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/generative-language.retriever",
            "token_type": "Bearer",
        }
