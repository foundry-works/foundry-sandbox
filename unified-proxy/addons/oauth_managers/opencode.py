"""
OpenCode API Key Manager for zai-coding-plan Provider

Simple API key reader for OpenCode's auth.json file.
Supports API key credentials (type: "api") for providers like zai-coding-plan.
"""

import json
import os


class OpenCodeKeyManager:
    """Manages API key credentials for OpenCode providers."""

    def __init__(self, auth_file_path: str):
        """
        Initialize key manager with path to OpenCode auth.json.

        Args:
            auth_file_path: Path to the auth.json file (e.g., /credentials/opencode/auth.json)
        """
        self.auth_file_path = auth_file_path
        self._providers: dict[str, dict] = {}

        # Load credentials
        self._load_credentials()

    def _load_credentials(self) -> None:
        """Load credentials from OpenCode auth.json file."""
        if not os.path.exists(self.auth_file_path):
            raise FileNotFoundError(f"Auth file not found: {self.auth_file_path}")

        with open(self.auth_file_path, "r") as f:
            data = json.load(f)

        # OpenCode auth.json has provider-keyed structure
        for provider, creds in data.items():
            if not isinstance(creds, dict):
                continue

            self._providers[provider] = {
                "type": creds.get("type", "api"),
                "key": creds.get("key"),
            }

    def get_providers(self) -> list[str]:
        """Get list of configured providers."""
        return list(self._providers.keys())

    def has_provider(self, provider: str) -> bool:
        """Check if a provider is configured."""
        return provider in self._providers

    def get_api_key(self, provider: str) -> str:
        """
        Get the API key for a provider.

        Args:
            provider: Provider name (e.g., "zai-coding-plan")

        Returns:
            API key string

        Raises:
            ValueError: If provider not configured or no API key available
        """
        if provider not in self._providers:
            raise ValueError(f"Provider not configured: {provider}")

        creds = self._providers[provider]

        if creds.get("type") != "api":
            raise ValueError(f"Provider {provider} is not an API key type")

        key = creds.get("key")
        if not key:
            raise ValueError(f"No API key configured for {provider}")

        return key
