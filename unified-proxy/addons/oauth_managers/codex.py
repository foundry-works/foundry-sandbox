"""
OAuth Token Manager for Codex CLI Authentication

Manages OAuth token lifecycle for ChatGPT authentication:
- Loads auth.json from mounted credentials path
- Checks token expiry with configurable buffer
- Refreshes tokens via OpenAI OAuth endpoint
- Thread-safe token access

Uses httpx with proxy=None to bypass mitmproxy for token refresh.
"""

import base64
import json
import os
import secrets
import time
import threading
from datetime import datetime
from typing import Optional

import httpx

# OAuth configuration (matches official Codex CLI)
OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
OPENAI_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"  # Codex CLI client ID
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
        # Extract expiry from JWT access_token (most reliable source)
        # Falls back to expires_at field or last_refresh if JWT parsing fails
        self._expires_at = self._extract_jwt_expiry(self._access_token)
        if self._expires_at == 0:
            expires_at_raw = data.get("expires_at") or data.get("last_refresh", 0)
            self._expires_at = self._parse_expiry(expires_at_raw)

        if not self._access_token or not self._refresh_token:
            raise ValueError("Invalid auth.json: missing access_token or refresh_token")

    def _extract_jwt_expiry(self, token: Optional[str]) -> float:
        """
        Extract the exp claim from a JWT token.

        Args:
            token: JWT token string (header.payload.signature)

        Returns:
            Unix timestamp of expiry, or 0 if extraction fails
        """
        if not token:
            return 0

        try:
            # JWT format: header.payload.signature
            parts = token.split(".")
            if len(parts) != 3:
                return 0

            # Decode payload (base64url encoded)
            payload_b64 = parts[1]
            # Add padding if needed
            padding = 4 - len(payload_b64) % 4
            if padding < 4:
                payload_b64 += "=" * padding

            payload_json = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_json)

            # Extract exp claim
            exp = payload.get("exp")
            if isinstance(exp, (int, float)):
                return float(exp)
        except Exception:
            pass

        return 0

    def _parse_expiry(self, value) -> float:
        """
        Parse expiry time from various formats.

        Supports:
        - Numeric Unix timestamp (int or float)
        - Numeric string ("1700000000")
        - ISO 8601 date string ("2026-01-26T00:33:39.106494452Z")

        Returns:
            Unix timestamp as float, or 0 if parsing fails
        """
        if not value:
            return 0

        # Already numeric
        if isinstance(value, (int, float)):
            return float(value)

        # String - try numeric first, then ISO date
        if isinstance(value, str):
            # Try parsing as numeric string
            try:
                return float(value)
            except ValueError:
                pass

            # Try parsing as ISO date string
            try:
                # Handle various ISO formats with optional microseconds and Z suffix
                value = value.rstrip("Z")
                # Truncate nanoseconds to microseconds (Python only supports microseconds)
                if "." in value:
                    base, frac = value.rsplit(".", 1)
                    frac = frac[:6]  # Keep only 6 digits for microseconds
                    value = f"{base}.{frac}"
                dt = datetime.fromisoformat(value)
                return dt.timestamp()
            except ValueError:
                pass

        return 0

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
            Dict mimicking OAuth token response with per-request randomized
            placeholder values. access_token is valid JWT format to pass Codex
            CLI validation. Contains CREDENTIAL_PROXY_PLACEHOLDER marker for
            detection by credential injector.
        """
        # Build a per-request JWT with random jti and signature to prevent
        # fingerprinting. The sub claim contains the detection marker.
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": "https://auth.openai.com/",
            "sub": "CREDENTIAL_PROXY_PLACEHOLDER",
            "aud": OPENAI_CLIENT_ID,
            "exp": 4102444800,  # 2100-01-01
            "iat": int(time.time()),
            "jti": secrets.token_hex(16),
        }
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        # Signature contains the detection marker so _has_credential_placeholder()
        # can find it as a literal substring in the Authorization header value.
        s = f"CREDENTIAL_PROXY_PLACEHOLDER_{secrets.token_hex(8)}"
        nonce = secrets.token_hex(8)
        return {
            "access_token": f"{h}.{p}.{s}",
            "refresh_token": f"rt_CREDENTIAL_PROXY_PLACEHOLDER.{nonce}",
            "expires_in": 86400,
            "token_type": "Bearer",
        }
