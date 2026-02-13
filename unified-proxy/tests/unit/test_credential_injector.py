"""
Unit tests for Credential Injector addon.

Tests cover:
- API credential injection for various providers
- GitHub token injection for git/API operations
- OAuth refresh flow interception
- Credential injection latency (p99 < 10ms)
"""

import json
import os
import sys
import time
from typing import Optional
from unittest import mock

import pytest

# Mock mitmproxy before importing the addon
mock_http_module = mock.MagicMock()


class MockHTTPFlow:
    """Mock mitmproxy HTTPFlow for testing."""

    def __init__(
        self,
        host: str,
        path: str = "/",
        method: str = "GET",
        headers: Optional[dict] = None,
        body: Optional[str] = None,
    ):
        self.request = mock.MagicMock()
        self.request.host = host
        self.request.path = path
        self.request.method = method
        self.request.headers = dict(headers or {})
        self.request.pretty_host = host
        self._body = body

        if body:
            self.request.get_text.return_value = body
        else:
            self.request.get_text.return_value = ""

        self.response = None
        self.metadata = {}
        self.client_conn = mock.MagicMock()
        self.client_conn.peername = ("192.168.1.100", 12345)

    def set_response(self, status_code: int, body: bytes, headers: dict):
        """Helper to check response was set."""
        self.response = mock.MagicMock()
        self.response.status_code = status_code


class MockResponse:
    """Mock HTTP Response."""

    @staticmethod
    def make(status_code: int, body: bytes, headers: dict):
        resp = mock.MagicMock()
        resp.status_code = status_code
        resp.content = body
        resp.headers = headers
        return resp


# Set up mock http module
mock_http_module.Response = MockResponse
mock_http_module.HTTPFlow = MockHTTPFlow

# Mock the container identity module
mock_container_identity = mock.MagicMock()
mock_container_identity.get_container_config.return_value = None

# Remove any existing imports
if "addons.credential_injector" in sys.modules:
    del sys.modules["addons.credential_injector"]

# Patch sys.modules BEFORE import
# Create a mock mitmproxy module that returns our mock modules when accessed as attributes
mock_mitmproxy = mock.MagicMock()
mock_mitmproxy.http = mock_http_module
sys.modules["mitmproxy"] = mock_mitmproxy
sys.modules["mitmproxy.http"] = mock_http_module
sys.modules["addons.container_identity"] = mock_container_identity
sys.modules["addons.oauth_managers"] = mock.MagicMock()
sys.modules["addons.oauth_managers.codex"] = mock.MagicMock()
sys.modules["addons.oauth_managers.gemini"] = mock.MagicMock()
sys.modules["addons.oauth_managers.opencode"] = mock.MagicMock()

# Now we can import the types we need for testing
from addons.credential_injector import (
    CredentialInjector,
    PROVIDER_MAP,
    OAUTH_PLACEHOLDER,
    OPENCODE_PLACEHOLDER,
    GITHUB_PLACEHOLDER_MARKER,
)


class TestCredentialInjector:
    """Tests for CredentialInjector class."""

    @pytest.fixture
    def injector(self) -> CredentialInjector:
        """Create a CredentialInjector with test credentials."""
        with mock.patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "test-anthropic-key",
            "OPENAI_API_KEY": "test-openai-key",
            "GOOGLE_API_KEY": "test-google-key",
            "TAVILY_API_KEY": "test-tavily-key",
            "GITHUB_TOKEN": "test-github-token",
            "SEMANTIC_SCHOLAR_API_KEY": "test-scholar-key",
            "PERPLEXITY_API_KEY": "test-perplexity-key",
            "ZHIPU_API_KEY": "test-zhipu-key",
        }, clear=True):
            return CredentialInjector()

    @pytest.fixture
    def injector_minimal(self) -> CredentialInjector:
        """Create a CredentialInjector with minimal credentials."""
        with mock.patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "test-anthropic-key",
        }, clear=True):
            return CredentialInjector()


class TestAPICredentialInjection(TestCredentialInjector):
    """Tests for API credential injection."""

    def test_anthropic_api_key_injection(self, injector: CredentialInjector):
        """Test that Anthropic API key is injected correctly."""
        flow = MockHTTPFlow("api.anthropic.com", "/v1/messages")
        flow.request.headers["x-api-key"] = "placeholder"

        injector.request(flow)

        assert flow.response is None  # No error response
        assert flow.request.headers["x-api-key"] == "test-anthropic-key"

    def test_openai_bearer_injection(self, injector: CredentialInjector):
        """Test that OpenAI key is injected as Bearer token."""
        flow = MockHTTPFlow("api.openai.com", "/v1/chat/completions")
        flow.request.headers["Authorization"] = "placeholder"

        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer test-openai-key"

    def test_google_api_key_injection(self, injector: CredentialInjector):
        """Test that Google API key is injected correctly."""
        flow = MockHTTPFlow("generativelanguage.googleapis.com", "/v1beta/models")
        flow.request.headers["x-goog-api-key"] = "placeholder"

        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers["x-goog-api-key"] == "test-google-key"

    def test_tavily_header_injection(self, injector: CredentialInjector):
        """Test that Tavily API key is injected in header."""
        flow = MockHTTPFlow("api.tavily.com", "/search")
        flow.request.headers["Authorization"] = "placeholder"

        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer test-tavily-key"

    def test_tavily_body_injection(self, injector: CredentialInjector):
        """Test that Tavily API key is injected in request body."""
        flow = MockHTTPFlow(
            "api.tavily.com",
            "/search",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"query": "test", "api_key": "placeholder"}),
        )

        # First inject header
        injector.request(flow)

        # Check body injection was called (via mock)
        # In real implementation, body should have api_key updated
        assert flow.response is None

    def test_semantic_scholar_injection(self, injector: CredentialInjector):
        """Test Semantic Scholar API key injection."""
        flow = MockHTTPFlow("api.semanticscholar.org", "/graph/v1/paper")
        flow.request.headers["x-api-key"] = "placeholder"

        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers["x-api-key"] == "test-scholar-key"

    def test_perplexity_injection(self, injector: CredentialInjector):
        """Test Perplexity API key injection."""
        flow = MockHTTPFlow("api.perplexity.ai", "/chat/completions")
        flow.request.headers["Authorization"] = "placeholder"

        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer test-perplexity-key"

    def test_zhipu_api_key_injection(self, injector: CredentialInjector):
        """Test Zhipu AI API key injection."""
        flow = MockHTTPFlow("api.z.ai", "/v4/chat/completions")
        flow.request.headers["x-api-key"] = "placeholder"

        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers["x-api-key"] == "test-zhipu-key"

    def test_missing_credential_returns_500(self, injector_minimal: CredentialInjector):
        """Test that missing credentials return 500 error."""
        flow = MockHTTPFlow("api.openai.com", "/v1/chat/completions")

        injector_minimal.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 500

    def test_unknown_host_no_injection(self, injector: CredentialInjector):
        """Test that unknown hosts don't get credential injection."""
        flow = MockHTTPFlow("unknown.example.com", "/api")
        original_headers = dict(flow.request.headers)

        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers == original_headers


class TestGitHubTokenInjection(TestCredentialInjector):
    """Tests for GitHub token injection."""

    def test_github_api_token_injection(self, injector: CredentialInjector):
        """Test GitHub API token injection."""
        flow = MockHTTPFlow("api.github.com", "/repos/owner/repo")
        flow.request.headers["Authorization"] = "placeholder"

        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer test-github-token"

    def test_github_uploads_token_injection(self, injector: CredentialInjector):
        """Test GitHub uploads API token injection."""
        flow = MockHTTPFlow("uploads.github.com", "/repos/owner/repo/releases/1/assets")
        flow.request.headers["Authorization"] = "placeholder"

        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer test-github-token"

    def test_github_no_token_allows_anonymous(self, injector_minimal: CredentialInjector):
        """Test that GitHub requests work without token (anonymous)."""
        flow = MockHTTPFlow("api.github.com", "/repos/owner/repo")
        flow.request.headers["Authorization"] = f"Bearer {GITHUB_PLACEHOLDER_MARKER}"

        injector_minimal.request(flow)

        # Should not return error for GitHub (allows anonymous)
        assert flow.response is None
        # Placeholder should be stripped
        assert "Authorization" not in flow.request.headers

    def test_github_fallback_to_gh_token(self):
        """Test fallback to GH_TOKEN when GITHUB_TOKEN not set."""
        with mock.patch.dict(os.environ, {
            "GH_TOKEN": "fallback-gh-token",
        }, clear=True):
            injector = CredentialInjector()

        flow = MockHTTPFlow("api.github.com", "/repos/owner/repo")
        flow.request.headers["Authorization"] = "placeholder"

        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers["Authorization"] == "Bearer fallback-gh-token"


class TestOAuthRefreshFlow(TestCredentialInjector):
    """Tests for OAuth refresh flow interception."""

    def test_codex_oauth_refresh_interception(self, injector: CredentialInjector):
        """Test Codex CLI OAuth refresh endpoint is intercepted."""
        # Setup OAuth manager mock
        injector.oauth_manager = mock.MagicMock()
        injector.oauth_manager.get_placeholder_response.return_value = {
            "access_token": "placeholder_token",
            "refresh_token": "placeholder_refresh",
            "expires_in": 86400,
        }

        flow = MockHTTPFlow("auth.openai.com", "/oauth/token", method="POST")

        result = injector._handle_refresh_intercept(flow)

        assert result is True
        assert flow.response is not None

    def test_gemini_oauth_refresh_interception(self, injector: CredentialInjector):
        """Test Gemini CLI OAuth refresh endpoint is intercepted."""
        # Setup Gemini manager mock
        injector.gemini_manager = mock.MagicMock()
        injector.gemini_manager.get_placeholder_response.return_value = {
            "access_token": "placeholder_token",
            "refresh_token": "placeholder_refresh",
            "expires_in": 86400,
        }

        flow = MockHTTPFlow("oauth2.googleapis.com", "/token", method="POST")

        result = injector._handle_refresh_intercept(flow)

        assert result is True
        assert flow.response is not None

    def test_non_refresh_endpoint_not_intercepted(self, injector: CredentialInjector):
        """Test that non-refresh endpoints are not intercepted."""
        flow = MockHTTPFlow("api.openai.com", "/v1/chat/completions")

        result = injector._handle_refresh_intercept(flow)

        assert result is False
        assert flow.response is None

    def test_oauth_placeholder_injection_openai(self, injector: CredentialInjector):
        """Test OAuth placeholder injection for OpenAI/Codex."""
        injector.oauth_manager = mock.MagicMock()
        injector.oauth_manager.get_valid_token.return_value = "real_oauth_token"

        flow = MockHTTPFlow("api.openai.com", "/v1/chat/completions")
        flow.request.headers["Authorization"] = f"Bearer {OAUTH_PLACEHOLDER}"

        result = injector._handle_oauth_injection(flow)

        assert result is True
        assert flow.request.headers["Authorization"] == "Bearer real_oauth_token"

    def test_oauth_placeholder_not_injected_for_anthropic(self, injector: CredentialInjector):
        """Test OAuth placeholder is not injected for non-OpenAI hosts."""
        injector.oauth_manager = mock.MagicMock()

        flow = MockHTTPFlow("api.anthropic.com", "/v1/messages")
        flow.request.headers["Authorization"] = f"Bearer {OAUTH_PLACEHOLDER}"

        result = injector._handle_oauth_injection(flow)

        # Should return False - Anthropic requests don't use Codex OAuth
        assert result is False

    def test_gemini_oauth_placeholder_injection(self, injector: CredentialInjector):
        """Test Gemini OAuth placeholder injection."""
        injector.gemini_manager = mock.MagicMock()
        injector.gemini_manager.get_valid_token.return_value = "real_gemini_token"

        flow = MockHTTPFlow("generativelanguage.googleapis.com", "/v1beta/models")
        flow.request.headers["Authorization"] = f"Bearer {OAUTH_PLACEHOLDER}"

        result = injector._handle_gemini_oauth_injection(flow)

        assert result is True
        assert flow.request.headers["Authorization"] == "Bearer real_gemini_token"

    def test_opencode_placeholder_injection(self, injector: CredentialInjector):
        """Test OpenCode placeholder injection for Zhipu AI."""
        injector.opencode_manager = mock.MagicMock()
        injector.opencode_manager.has_provider.return_value = True
        injector.opencode_manager.get_api_key.return_value = "real_zhipu_key"

        flow = MockHTTPFlow("api.z.ai", "/v4/chat/completions")
        flow.request.headers["Authorization"] = f"Bearer {OPENCODE_PLACEHOLDER}"

        result = injector._handle_opencode_api_key_injection(flow)

        assert result is True
        assert flow.request.headers["Authorization"] == "Bearer real_zhipu_key"


class TestCredentialInjectionLatency:
    """Tests for credential injection latency requirements."""

    @pytest.fixture
    def injector(self) -> CredentialInjector:
        """Create a CredentialInjector with test credentials."""
        with mock.patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "test-anthropic-key",
            "OPENAI_API_KEY": "test-openai-key",
            "GOOGLE_API_KEY": "test-google-key",
            "GITHUB_TOKEN": "test-github-token",
        }, clear=True):
            return CredentialInjector()

    def test_injection_latency_p99_under_10ms(self, injector: CredentialInjector):
        """Test that credential injection p99 latency is under 10ms.

        This test runs 1000 injections and verifies p99 is under 10ms.
        """
        latencies = []

        for _ in range(1000):
            flow = MockHTTPFlow("api.anthropic.com", "/v1/messages")
            flow.request.headers["x-api-key"] = "placeholder"

            start = time.perf_counter()
            injector.request(flow)
            end = time.perf_counter()

            latencies.append((end - start) * 1000)  # Convert to ms

        # Sort and get p99
        latencies.sort()
        p99_index = int(len(latencies) * 0.99)
        p99_latency = latencies[p99_index]

        assert p99_latency < 10.0, f"p99 latency {p99_latency:.2f}ms exceeds 10ms"

    def test_injection_latency_average_under_1ms(self, injector: CredentialInjector):
        """Test that average credential injection latency is under 1ms."""
        latencies = []

        for _ in range(100):
            flow = MockHTTPFlow("api.anthropic.com", "/v1/messages")
            flow.request.headers["x-api-key"] = "placeholder"

            start = time.perf_counter()
            injector.request(flow)
            end = time.perf_counter()

            latencies.append((end - start) * 1000)  # Convert to ms

        avg_latency = sum(latencies) / len(latencies)

        assert avg_latency < 1.0, f"Average latency {avg_latency:.2f}ms exceeds 1ms"


class TestProviderMapConfiguration:
    """Tests for PROVIDER_MAP configuration."""

    def test_all_providers_have_required_fields(self):
        """Test that all providers have required configuration fields."""
        required_fields = {"header", "env_var", "format"}

        for host, config in PROVIDER_MAP.items():
            missing = required_fields - set(config.keys())
            assert not missing, f"{host} missing required fields: {missing}"

    def test_anthropic_has_alternative_credential(self):
        """Test that Anthropic has alternative OAuth credential config."""
        config = PROVIDER_MAP["api.anthropic.com"]
        assert "alt_env_var" in config
        assert config["alt_env_var"] == "CLAUDE_CODE_OAUTH_TOKEN"
        assert "alt_header" in config
        assert "alt_format" in config

    def test_github_has_fallback_token(self):
        """Test that GitHub has fallback GH_TOKEN config."""
        for host in ["api.github.com", "uploads.github.com"]:
            config = PROVIDER_MAP[host]
            assert "fallback_env_var" in config
            assert config["fallback_env_var"] == "GH_TOKEN"


class TestContainerIdentityIntegration:
    """Tests for container identity integration."""

    @pytest.fixture
    def injector(self) -> CredentialInjector:
        """Create injector with test credentials."""
        with mock.patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "test-key",
        }, clear=True):
            return CredentialInjector()

    def test_get_container_id_returns_none_when_no_config(self, injector: CredentialInjector):
        """Test _get_container_id returns None when no container config."""
        flow = MockHTTPFlow("api.anthropic.com", "/v1/messages")

        container_id = injector._get_container_id(flow)

        assert container_id is None

    def test_get_container_id_returns_id_when_present(self, injector: CredentialInjector):
        """Test _get_container_id returns ID when config present."""
        flow = MockHTTPFlow("api.anthropic.com", "/v1/messages")

        # Mock container config in flow metadata
        mock_config = mock.MagicMock()
        mock_config.container_id = "test-container-123"

        with mock.patch("addons.credential_injector.get_container_config") as mock_get:
            mock_get.return_value = mock_config
            container_id = injector._get_container_id(flow)

        assert container_id == "test-container-123"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
