"""Unit tests for policy engine addon.

Tests the PolicyEngine class including:
- PolicyDecision dataclass
- Default deny behavior
- Allowlist matching
- Blocklist override
- Evaluation order
- Conflict resolution
"""

import os
import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

# Mock mitmproxy before imports
sys.modules["mitmproxy"] = MagicMock()
sys.modules["mitmproxy.http"] = MagicMock()
sys.modules["mitmproxy.ctx"] = MagicMock()
sys.modules["mitmproxy.flow"] = MagicMock()

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from addons.policy_engine import (
    POLICY_DECISION_KEY,
    PolicyDecision,
    PolicyEngine,
    get_policy_decision,
)


def make_mock_response(*args, **kwargs):
    """Create a mock response with status_code=403.

    Args:
        *args: Accepts status_code, body, headers (matches http.Response.make signature)
        **kwargs: Additional keyword arguments
    """
    response = Mock()
    response.status_code = args[0] if args else 403
    return response


class TestPolicyDecision:
    """Tests for PolicyDecision dataclass."""

    def test_init_with_all_fields(self):
        """Test PolicyDecision initialization with all fields."""
        decision = PolicyDecision(
            allowed=True,
            reason="Test reason",
            policy_type="allowlist",
            container_id="test-container",
        )
        assert decision.allowed is True
        assert decision.reason == "Test reason"
        assert decision.policy_type == "allowlist"
        assert decision.container_id == "test-container"

    def test_init_without_container_id(self):
        """Test PolicyDecision initialization without container_id."""
        decision = PolicyDecision(
            allowed=False,
            reason="Denied",
            policy_type="identity",
        )
        assert decision.allowed is False
        assert decision.reason == "Denied"
        assert decision.policy_type == "identity"
        assert decision.container_id is None

    def test_to_dict(self):
        """Test PolicyDecision to_dict conversion."""
        decision = PolicyDecision(
            allowed=True,
            reason="Test reason",
            policy_type="blocklist",
            container_id="container-123",
        )
        result = decision.to_dict()
        assert result == {
            "allowed": True,
            "reason": "Test reason",
            "policy_type": "blocklist",
            "container_id": "container-123",
        }

    def test_to_dict_without_container_id(self):
        """Test PolicyDecision to_dict with None container_id."""
        decision = PolicyDecision(
            allowed=False,
            reason="No identity",
            policy_type="identity",
            container_id=None,
        )
        result = decision.to_dict()
        assert result["container_id"] is None
        assert result["allowed"] is False


class TestDefaultDeny:
    """Tests for default deny behavior when container is not identified."""

    @pytest.fixture
    def policy_engine(self):
        """Create PolicyEngine instance."""
        return PolicyEngine()

    @pytest.fixture
    def mock_flow(self):
        """Create mock HTTP flow."""
        flow = Mock()
        flow.request = Mock()
        flow.request.method = "GET"
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/user"
        flow.metadata = {}
        flow.response = None
        return flow

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_unidentified_container_denied(
        self, mock_ctx, mock_get_config, policy_engine, mock_flow
    ):
        """Test that unidentified containers are denied."""
        # Setup: container_identity returned None (no identity)
        mock_get_config.return_value = None

        # Execute
        policy_engine.request(mock_flow)

        # Verify: decision stored in metadata
        assert POLICY_DECISION_KEY in mock_flow.metadata
        decision = mock_flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert decision["policy_type"] == "identity"
        assert decision["container_id"] is None
        assert "verification failed" in decision["reason"].lower()

        # Verify: no response created (container_identity addon handles this)
        assert mock_flow.response is None

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_identity_failure_logged(
        self, mock_ctx, mock_get_config, policy_engine, mock_flow
    ):
        """Test that identity verification failure is logged."""
        mock_get_config.return_value = None
        mock_ctx.log = Mock()

        policy_engine.request(mock_flow)

        # Verify logging was called
        assert mock_ctx.log.warn.called


class TestAllowlistMatching:
    """Tests for allowlist matching - identified containers allowed if domain in allowlist."""

    @pytest.fixture
    def policy_engine(self):
        """Create PolicyEngine instance with test allowlist."""
        engine = PolicyEngine()
        # Set up allowlist directly for testing (simulating loaded config)
        engine._domains = [
            "api.github.com",
            "github.com",
            "*.github.com",
            "pypi.org",
            "*.pypi.org",
            "registry.npmjs.org",
            "*.npmjs.org",
            "api.anthropic.com",
        ]
        return engine

    @pytest.fixture
    def mock_flow(self):
        """Create mock HTTP flow with allowed domain."""
        flow = Mock()
        flow.request = Mock()
        flow.request.method = "GET"
        flow.request.pretty_host = "api.github.com"  # In allowlist
        flow.request.path = "/user"
        flow.metadata = {}
        flow.response = None
        return flow

    @pytest.fixture
    def mock_container_config(self):
        """Create mock container config."""
        config = Mock()
        config.container_id = "test-container-123"
        return config

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_identified_container_allowed(
        self, mock_ctx, mock_get_config, policy_engine, mock_flow, mock_container_config
    ):
        """Test that identified containers are allowed for allowlisted domains."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        policy_engine.request(mock_flow)

        # Verify: decision is allow
        assert POLICY_DECISION_KEY in mock_flow.metadata
        decision = mock_flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True
        assert decision["policy_type"] == "allowlist"
        assert decision["container_id"] == "test-container-123"

        # Verify: no response created (request proceeds)
        assert mock_flow.response is None

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_allowed_request_logged(
        self, mock_ctx, mock_get_config, policy_engine, mock_flow, mock_container_config
    ):
        """Test that allowed requests are logged."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        policy_engine.request(mock_flow)

        # Verify info logging
        assert mock_ctx.log.info.called

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_allowlisted_hosts_allowed(
        self, mock_ctx, mock_get_config, policy_engine, mock_container_config
    ):
        """Test that allowlisted hosts are allowed for identified containers."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        # Test various allowlisted hosts
        hosts = [
            "api.github.com",  # Exact match
            "registry.npmjs.org",  # Exact match
            "pypi.org",  # Exact match
        ]

        for host in hosts:
            flow = Mock()
            flow.request = Mock()
            flow.request.method = "GET"
            flow.request.pretty_host = host
            flow.request.path = "/some/path"
            flow.metadata = {}
            flow.response = None

            policy_engine.request(flow)

            decision = flow.metadata[POLICY_DECISION_KEY]
            assert decision["allowed"] is True, f"Host {host} should be allowed"
            assert flow.response is None

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_non_allowlisted_hosts_denied(
        self, mock_ctx, mock_get_config, mock_response_make, policy_engine, mock_container_config
    ):
        """Test that non-allowlisted hosts are denied (default-deny)."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        # Test non-allowlisted hosts
        hosts = [
            "evil.com",
            "malware.net",
            "unknown-service.org",
        ]

        for host in hosts:
            flow = Mock()
            flow.request = Mock()
            flow.request.method = "GET"
            flow.request.pretty_host = host
            flow.request.path = "/some/path"
            flow.metadata = {}
            flow.response = None

            policy_engine.request(flow)

            decision = flow.metadata[POLICY_DECISION_KEY]
            assert decision["allowed"] is False, f"Host {host} should be denied"
            assert decision["policy_type"] == "allowlist"
            assert "not in allowlist" in decision["reason"]
            assert flow.response is not None
            assert flow.response.status_code == 403


class TestBlocklistOverride:
    """Tests for blocklist override - GitHub security policies."""

    @pytest.fixture
    def policy_engine(self):
        """Create PolicyEngine instance with GitHub in allowlist."""
        engine = PolicyEngine()
        engine._domains = ["api.github.com", "*.github.com"]
        return engine

    @pytest.fixture
    def mock_container_config(self):
        """Create mock container config."""
        config = Mock()
        config.container_id = "blocked-container"
        return config

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_github_pr_merge_blocked(
        self, mock_ctx, mock_get_config, mock_response_make, policy_engine, mock_container_config
    ):
        """Test that GitHub PR merge operations are blocked."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        # Test PR merge endpoint
        flow = Mock()
        flow.request = Mock()
        flow.request.method = "PUT"
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/repos/owner/repo/pulls/123/merge"
        flow.metadata = {}
        flow.response = None

        policy_engine.request(flow)

        # Verify: decision is deny
        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert decision["policy_type"] == "blocklist"
        assert decision["container_id"] == "blocked-container"
        assert "PR merge" in decision["reason"]

        # Verify: 403 response created
        assert flow.response is not None
        assert flow.response.status_code == 403

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_github_release_creation_blocked(
        self, mock_ctx, mock_get_config, mock_response_make, policy_engine, mock_container_config
    ):
        """Test that GitHub release creation is blocked."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        flow = Mock()
        flow.request = Mock()
        flow.request.method = "POST"
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/repos/owner/repo/releases"
        flow.metadata = {}
        flow.response = None

        policy_engine.request(flow)

        # Verify: decision is deny
        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert decision["policy_type"] == "blocklist"
        assert "release creation" in decision["reason"]

        # Verify: 403 response created
        assert flow.response is not None
        assert flow.response.status_code == 403

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_github_pr_merge_variations_blocked(
        self, mock_ctx, mock_get_config, mock_response_make, policy_engine, mock_container_config
    ):
        """Test various PR merge path patterns are blocked."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        merge_paths = [
            "/repos/user/project/pulls/1/merge",
            "/repos/org-name/repo-name/pulls/999/merge",
            "/repos/a/b/pulls/42/merge",
        ]

        for path in merge_paths:
            flow = Mock()
            flow.request = Mock()
            flow.request.method = "PUT"
            flow.request.pretty_host = "api.github.com"
            flow.request.path = path
            flow.metadata = {}
            flow.response = None

            policy_engine.request(flow)

            decision = flow.metadata[POLICY_DECISION_KEY]
            assert decision["allowed"] is False, f"Path {path} should be blocked"
            assert flow.response.status_code == 403

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_github_similar_paths_not_blocked(
        self, mock_ctx, mock_get_config, policy_engine, mock_container_config
    ):
        """Test that similar but different GitHub paths are not blocked."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        # These paths should NOT match the blocklist patterns (domain is in allowlist)
        allowed_paths = [
            ("/repos/owner/repo/pulls/123", "GET"),  # Get PR details
            ("/repos/owner/repo/pulls", "GET"),  # List PRs
            ("/repos/owner/repo/pulls", "POST"),  # Create PR
            ("/repos/owner/repo/releases/123", "GET"),  # Get release
            ("/repos/owner/repo/releases", "GET"),  # List releases
        ]

        for path, method in allowed_paths:
            flow = Mock()
            flow.request = Mock()
            flow.request.method = method
            flow.request.pretty_host = "api.github.com"  # In policy_engine._domains
            flow.request.path = path
            flow.metadata = {}
            flow.response = None

            policy_engine.request(flow)

            decision = flow.metadata[POLICY_DECISION_KEY]
            assert (
                decision["allowed"] is True
            ), f"Path {method} {path} should be allowed"
            assert flow.response is None

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_blocklist_logged_as_warning(
        self, mock_ctx, mock_get_config, policy_engine, mock_container_config
    ):
        """Test that blocklist denials are logged as warnings."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        flow = Mock()
        flow.request = Mock()
        flow.request.method = "PUT"
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/repos/owner/repo/pulls/1/merge"
        flow.metadata = {}
        flow.response = None

        policy_engine.request(flow)

        # Verify warning logged
        assert mock_ctx.log.warn.called


class TestEvaluationOrder:
    """Tests for policy evaluation order."""

    @pytest.fixture
    def policy_engine(self):
        """Create PolicyEngine instance with GitHub in allowlist."""
        engine = PolicyEngine()
        engine._domains = ["api.github.com", "*.github.com"]
        return engine

    @pytest.fixture
    def mock_container_config(self):
        """Create mock container config."""
        config = Mock()
        config.container_id = "test-container"
        return config

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_identity_checked_first(
        self, mock_ctx, mock_get_config, policy_engine
    ):
        """Test that identity verification is checked before other policies."""
        mock_get_config.return_value = None
        mock_ctx.log = Mock()

        # Even for a blocked GitHub endpoint, identity check fails first
        flow = Mock()
        flow.request = Mock()
        flow.request.method = "PUT"
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/repos/owner/repo/pulls/1/merge"
        flow.metadata = {}
        flow.response = None

        policy_engine.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["policy_type"] == "identity"
        assert decision["allowed"] is False

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_blocklist_checked_after_identity(
        self, mock_ctx, mock_get_config, policy_engine, mock_container_config
    ):
        """Test that blocklist is checked after identity verification."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        # Container is identified, so blocklist check happens
        flow = Mock()
        flow.request = Mock()
        flow.request.method = "PUT"
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/repos/owner/repo/pulls/1/merge"
        flow.metadata = {}
        flow.response = None

        policy_engine.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["policy_type"] == "blocklist"
        assert decision["allowed"] is False
        assert decision["container_id"] == "test-container"

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_allowlist_checked_after_blocklist(
        self, mock_ctx, mock_get_config, policy_engine, mock_container_config
    ):
        """Test that allowlist applies if blocklist doesn't match."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        # Non-blocked GitHub request
        flow = Mock()
        flow.request = Mock()
        flow.request.method = "GET"
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/repos/owner/repo/pulls/1"
        flow.metadata = {}
        flow.response = None

        policy_engine.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["policy_type"] == "allowlist"
        assert decision["allowed"] is True


class TestConflictResolution:
    """Tests for conflict resolution - blocklist overrides allowlist."""

    @pytest.fixture
    def policy_engine(self):
        """Create PolicyEngine instance with GitHub in allowlist."""
        engine = PolicyEngine()
        engine._domains = ["api.github.com", "*.github.com"]
        return engine

    @pytest.fixture
    def mock_container_config(self):
        """Create mock container config."""
        config = Mock()
        config.container_id = "conflict-test"
        return config

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_blocklist_overrides_identity_allowlist(
        self, mock_ctx, mock_get_config, policy_engine, mock_container_config
    ):
        """Test that blocklist overrides identity-based allowlist."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        # Container is identified (would normally be allowed)
        # But requests blocked GitHub endpoint
        flow = Mock()
        flow.request = Mock()
        flow.request.method = "POST"
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/repos/owner/repo/releases"
        flow.metadata = {}
        flow.response = None

        policy_engine.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert decision["policy_type"] == "blocklist"
        assert decision["container_id"] == "conflict-test"

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_identified_but_blocked_creates_403(
        self, mock_ctx, mock_get_config, mock_response_make, policy_engine, mock_container_config
    ):
        """Test that identified containers still get 403 for blocked requests."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        flow = Mock()
        flow.request = Mock()
        flow.request.method = "PUT"
        flow.request.pretty_host = "api.github.com"
        flow.request.path = "/repos/owner/repo/pulls/999/merge"
        flow.metadata = {}
        flow.response = None

        policy_engine.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_multiple_requests_from_same_container(
        self, mock_ctx, mock_get_config, mock_response_make, policy_engine, mock_container_config
    ):
        """Test conflict resolution across multiple requests from same container."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()

        requests = [
            ("GET", "/repos/owner/repo", True, "allowlist"),  # Allowed
            ("PUT", "/repos/owner/repo/pulls/1/merge", False, "blocklist"),  # Blocked
            ("GET", "/user", True, "allowlist"),  # Allowed
            ("POST", "/repos/owner/repo/releases", False, "blocklist"),  # Blocked
        ]

        for method, path, should_allow, expected_policy in requests:
            flow = Mock()
            flow.request = Mock()
            flow.request.method = method
            flow.request.pretty_host = "api.github.com"
            flow.request.path = path
            flow.metadata = {}
            flow.response = None

            policy_engine.request(flow)

            decision = flow.metadata[POLICY_DECISION_KEY]
            assert (
                decision["allowed"] is should_allow
            ), f"{method} {path} should be {'allowed' if should_allow else 'blocked'}"
            assert decision["policy_type"] == expected_policy
            assert decision["container_id"] == "conflict-test"

            if should_allow:
                assert flow.response is None
            else:
                assert flow.response is not None
                assert flow.response.status_code == 403


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_policy_decision_exists(self):
        """Test get_policy_decision returns decision when present."""
        flow = Mock()
        flow.metadata = {
            POLICY_DECISION_KEY: {
                "allowed": True,
                "reason": "Test",
                "policy_type": "allowlist",
            }
        }

        result = get_policy_decision(flow)
        assert result is not None
        assert result["allowed"] is True

    def test_get_policy_decision_missing(self):
        """Test get_policy_decision returns None when not present."""
        flow = Mock()
        flow.metadata = {}

        result = get_policy_decision(flow)
        assert result is None

    def test_get_policy_decision_empty_metadata(self):
        """Test get_policy_decision handles empty metadata."""
        flow = Mock()
        flow.metadata = {}

        result = get_policy_decision(flow)
        assert result is None


class TestDenyRequest:
    """Tests for _deny_request method."""

    @pytest.fixture
    def policy_engine(self):
        """Create PolicyEngine instance."""
        return PolicyEngine()

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    def test_deny_request_creates_403_response(self, mock_response_make, policy_engine):
        """Test that _deny_request creates a 403 response."""
        flow = Mock()
        flow.metadata = {}

        decision = PolicyDecision(
            allowed=False,
            reason="Test denial",
            policy_type="blocklist",
            container_id="test",
        )

        policy_engine._deny_request(flow, decision)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_deny_request_stores_decision(self, policy_engine):
        """Test that _deny_request stores decision in metadata."""
        flow = Mock()
        flow.metadata = {}

        decision = PolicyDecision(
            allowed=False,
            reason="Test denial",
            policy_type="blocklist",
            container_id="test",
        )

        policy_engine._deny_request(flow, decision)

        assert POLICY_DECISION_KEY in flow.metadata
        stored = flow.metadata[POLICY_DECISION_KEY]
        assert stored["allowed"] is False
        assert stored["reason"] == "Test denial"


class TestIsGithubRequest:
    """Tests for _is_github_request method."""

    @pytest.fixture
    def policy_engine(self):
        """Create PolicyEngine instance."""
        return PolicyEngine()

    def test_is_github_request_true(self, policy_engine):
        """Test detection of GitHub API requests."""
        assert policy_engine._is_github_request("api.github.com") is True

    def test_is_github_request_false(self, policy_engine):
        """Test detection of non-GitHub requests."""
        non_github_hosts = [
            "github.com",
            "raw.githubusercontent.com",
            "api.example.com",
            "example.com",
        ]

        for host in non_github_hosts:
            assert (
                policy_engine._is_github_request(host) is False
            ), f"{host} should not be detected as GitHub API"


class TestCheckGithubBlocklist:
    """Tests for _check_github_blocklist method."""

    @pytest.fixture
    def policy_engine(self):
        """Create PolicyEngine instance."""
        return PolicyEngine()

    def test_check_github_blocklist_pr_merge(self, policy_engine):
        """Test PR merge detection."""
        result = policy_engine._check_github_blocklist(
            "PUT", "/repos/owner/repo/pulls/1/merge"
        )
        assert result is not None
        assert "PR merge" in result

    def test_check_github_blocklist_release_creation(self, policy_engine):
        """Test release creation detection."""
        result = policy_engine._check_github_blocklist(
            "POST", "/repos/owner/repo/releases"
        )
        assert result is not None
        assert "release creation" in result

    def test_check_github_blocklist_no_match(self, policy_engine):
        """Test that non-blocked requests return None."""
        safe_requests = [
            ("GET", "/repos/owner/repo/pulls/1"),
            ("GET", "/user"),
            ("POST", "/repos/owner/repo/pulls"),
            ("GET", "/repos/owner/repo/releases"),
        ]

        for method, path in safe_requests:
            result = policy_engine._check_github_blocklist(method, path)
            assert (
                result is None
            ), f"{method} {path} should not match blocklist"

    def test_check_github_blocklist_wrong_method(self, policy_engine):
        """Test that wrong HTTP method doesn't match."""
        # GET on merge endpoint - should not match (must be PUT)
        result = policy_engine._check_github_blocklist(
            "GET", "/repos/owner/repo/pulls/1/merge"
        )
        assert result is None

        # GET on releases endpoint - should not match (must be POST)
        result = policy_engine._check_github_blocklist(
            "GET", "/repos/owner/repo/releases"
        )
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
