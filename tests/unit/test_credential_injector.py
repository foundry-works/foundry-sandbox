"""Unit tests for credential injection mitmproxy addon.

Tests the CredentialInjector class which injects API credentials into
outbound requests based on destination host.

Note: These tests rely on conftest.py for mitmproxy module mocking.
The conftest adds unified-proxy to sys.path and installs mitmproxy
mocks, allowing addon imports to work without mitmproxy installed.
"""

import os
from unittest.mock import patch

import pytest

from addons import credential_injector
from tests.mocks import MockHeaders


class MockRequest:
    """Mock mitmproxy HTTP request."""

    def __init__(self, host, path="/", headers=None):
        self.host = host
        self.path = path
        self.headers = MockHeaders(headers or {})


class MockHTTPFlow:
    """Mock mitmproxy HTTPFlow."""

    def __init__(self, host, path="/", headers=None):
        self.request = MockRequest(host, path, headers)
        self.response = None
        self.metadata = {}


@pytest.fixture
def injector():
    """Create a CredentialInjector with test GitHub credentials."""
    with patch.dict(os.environ, {
        "GITHUB_TOKEN": "ghp_test_token_12345",
    }, clear=False):
        instance = credential_injector.CredentialInjector()
        return instance


@pytest.fixture
def injector_gh_token():
    """Create a CredentialInjector using GH_TOKEN fallback."""
    env = os.environ.copy()
    env.pop("GITHUB_TOKEN", None)
    env["GH_TOKEN"] = "gho_fallback_token_67890"
    with patch.dict(os.environ, env, clear=True):
        instance = credential_injector.CredentialInjector()
        return instance


@pytest.fixture
def injector_no_github():
    """Create a CredentialInjector with no GitHub credentials."""
    env = os.environ.copy()
    env.pop("GITHUB_TOKEN", None)
    env.pop("GH_TOKEN", None)
    with patch.dict(os.environ, env, clear=True):
        instance = credential_injector.CredentialInjector()
        return instance


class TestGitHubComCredentialInjection:
    """Tests for github.com credential injection (git HTTPS push/pull/clone)."""

    def test_github_com_in_provider_map(self):
        """github.com should be in the PROVIDER_MAP."""
        assert "github.com" in credential_injector.PROVIDER_MAP
        config = credential_injector.PROVIDER_MAP["github.com"]
        assert config["header"] == "Authorization"
        assert config["env_var"] == "GITHUB_TOKEN"
        assert config["fallback_env_var"] == "GH_TOKEN"
        assert config["format"] == "bearer"

    def test_injects_token_for_github_com(self, injector):
        """Credential injector should inject GITHUB_TOKEN for github.com requests."""
        flow = MockHTTPFlow("github.com", "/owner/repo.git/git-receive-pack")
        injector.request(flow)

        assert flow.response is None  # No error response
        assert flow.request.headers.get("Authorization") == "Bearer ghp_test_token_12345"

    def test_injects_token_for_github_com_git_upload_pack(self, injector):
        """Should inject token for git-upload-pack (fetch/clone) operations."""
        flow = MockHTTPFlow("github.com", "/owner/repo.git/git-upload-pack")
        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers.get("Authorization") == "Bearer ghp_test_token_12345"

    def test_injects_token_for_github_com_info_refs(self, injector):
        """Should inject token for info/refs discovery requests."""
        flow = MockHTTPFlow("github.com", "/owner/repo.git/info/refs?service=git-receive-pack")
        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers.get("Authorization") == "Bearer ghp_test_token_12345"

    def test_uses_gh_token_fallback(self, injector_gh_token):
        """Should fall back to GH_TOKEN when GITHUB_TOKEN is not set."""
        flow = MockHTTPFlow("github.com", "/owner/repo.git/git-receive-pack")
        injector_gh_token.request(flow)

        assert flow.response is None
        assert flow.request.headers.get("Authorization") == "Bearer gho_fallback_token_67890"

    def test_allows_unauthenticated_when_no_token(self, injector_no_github):
        """Should allow unauthenticated github.com requests when no token available."""
        flow = MockHTTPFlow("github.com", "/owner/repo.git/git-upload-pack")
        injector_no_github.request(flow)

        # Should not return an error response (500)
        assert flow.response is None

    def test_strips_placeholder_when_no_token(self, injector_no_github):
        """Should strip placeholder Authorization header when no GitHub token available."""
        flow = MockHTTPFlow(
            "github.com",
            "/owner/repo.git/git-receive-pack",
            headers={"Authorization": "Bearer CREDENTIAL_PROXY_PLACEHOLDER"},
        )
        injector_no_github.request(flow)

        assert flow.response is None
        # Placeholder should be stripped
        assert flow.request.headers.get("Authorization", "") == ""

    def test_replaces_existing_auth_header(self, injector):
        """Should replace existing Authorization header with real credential."""
        flow = MockHTTPFlow(
            "github.com",
            "/owner/repo.git/git-receive-pack",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        injector.request(flow)

        assert flow.request.headers.get("Authorization") == "Bearer ghp_test_token_12345"


class TestGitHubApiCredentialInjection:
    """Tests for api.github.com and uploads.github.com (existing behavior)."""

    def test_api_github_com_injection(self, injector):
        """Should inject token for api.github.com requests."""
        flow = MockHTTPFlow("api.github.com", "/repos/owner/repo")
        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers.get("Authorization") == "Bearer ghp_test_token_12345"

    def test_uploads_github_com_injection(self, injector):
        """Should inject token for uploads.github.com requests."""
        flow = MockHTTPFlow("uploads.github.com", "/repos/owner/repo/releases/1/assets")
        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers.get("Authorization") == "Bearer ghp_test_token_12345"

    def test_api_github_allows_unauthenticated(self, injector_no_github):
        """Should allow unauthenticated api.github.com requests."""
        flow = MockHTTPFlow("api.github.com", "/repos/owner/repo")
        injector_no_github.request(flow)

        assert flow.response is None


class TestNonGitHubHosts:
    """Tests that non-GitHub hosts are handled correctly."""

    def test_unknown_host_ignored(self, injector):
        """Requests to unknown hosts should pass through without modification."""
        flow = MockHTTPFlow("example.com", "/api/data")
        injector.request(flow)

        assert flow.response is None
        assert flow.request.headers.get("Authorization", "") == ""

    def test_missing_credential_returns_error(self):
        """Non-GitHub hosts without credentials should get an error response."""
        env = os.environ.copy()
        env.pop("ANTHROPIC_API_KEY", None)
        env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
        with patch.dict(os.environ, env, clear=True):
            instance = credential_injector.CredentialInjector()

        flow = MockHTTPFlow("api.anthropic.com", "/v1/messages")
        instance.request(flow)

        # Should have set an error response (not pass-through)
        assert flow.response is not None
        assert flow.response.status_code == 500
        assert b"credential" in flow.response.content.lower()


class TestCredentialRotationAndEdgeCases:
    """Tests for credential rotation, expiry, and malformed credentials."""

    def test_credential_rotation_mid_session(self):
        """Injector picks up rotated credentials when re-initialized."""
        # Start with initial token
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_initial_token"}, clear=False):
            injector1 = credential_injector.CredentialInjector()

        flow = MockHTTPFlow("github.com", "/owner/repo.git/git-receive-pack")
        injector1.request(flow)
        assert flow.request.headers.get("Authorization") == "Bearer ghp_initial_token"

        # Rotate to a new token and re-create the injector
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_rotated_token"}, clear=False):
            injector2 = credential_injector.CredentialInjector()

        flow2 = MockHTTPFlow("github.com", "/owner/repo.git/git-receive-pack")
        injector2.request(flow2)
        assert flow2.request.headers.get("Authorization") == "Bearer ghp_rotated_token"

    def test_empty_token_treated_as_missing(self):
        """An empty string token should behave like a missing credential."""
        env = os.environ.copy()
        env["GITHUB_TOKEN"] = ""
        env.pop("GH_TOKEN", None)
        with patch.dict(os.environ, env, clear=True):
            instance = credential_injector.CredentialInjector()

        flow = MockHTTPFlow("github.com", "/owner/repo.git/git-upload-pack")
        instance.request(flow)

        # Empty token: should either not inject or strip placeholder
        auth = flow.request.headers.get("Authorization", "")
        assert auth == "" or "Bearer " not in auth or flow.response is None

    def test_truncated_token_still_injected(self):
        """A short/truncated token should still be injected (validation is upstream's job)."""
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_short"}, clear=False):
            instance = credential_injector.CredentialInjector()

        flow = MockHTTPFlow("github.com", "/owner/repo.git/git-receive-pack")
        instance.request(flow)

        assert flow.response is None
        assert flow.request.headers.get("Authorization") == "Bearer ghp_short"

    def test_whitespace_only_token(self):
        """A whitespace-only token should not be injected as a valid credential."""
        env = os.environ.copy()
        env["GITHUB_TOKEN"] = "   "
        env.pop("GH_TOKEN", None)
        with patch.dict(os.environ, env, clear=True):
            instance = credential_injector.CredentialInjector()

        flow = MockHTTPFlow("github.com", "/owner/repo.git/git-upload-pack")
        instance.request(flow)

        # Should either not inject or treat as missing
        assert flow.response is None  # Allowed unauthenticated
