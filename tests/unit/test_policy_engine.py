"""Unit tests for policy engine addon.

Tests the PolicyEngine class including:
- PolicyDecision dataclass
- Default deny behavior
- Allowlist matching
- Blocklist override
- Evaluation order
- Conflict resolution
"""

from unittest.mock import Mock, patch

import pytest

# mitmproxy mocks and sys.path setup handled by conftest.py

from addons.policy_engine import (
    GITHUB_PATCH_ISSUE_PATTERN,
    GITHUB_PATCH_PR_PATTERN,
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

    def test_is_github_request_case_insensitive(self, policy_engine):
        """Test GitHub API detection is case-insensitive."""
        assert policy_engine._is_github_request("API.GITHUB.COM") is True

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

    def test_check_github_blocklist_git_ref_creation(self, policy_engine):
        """Test git ref creation endpoint is blocked."""
        result = policy_engine._check_github_blocklist(
            "POST", "/repos/owner/repo/git/refs"
        )
        assert result is not None
        assert "ref creation" in result

    def test_check_github_blocklist_git_ref_mutation(self, policy_engine):
        """Test git ref update/delete endpoints are blocked."""
        for method in ("PATCH", "DELETE"):
            result = policy_engine._check_github_blocklist(
                method, "/repos/owner/repo/git/refs/heads/main"
            )
            assert result is not None
            assert "ref mutation" in result

    def test_check_github_blocklist_no_match(self, policy_engine):
        """Test that non-blocked requests return None."""
        safe_requests = [
            ("GET", "/repos/owner/repo/pulls/1"),
            ("GET", "/user"),
            ("POST", "/repos/owner/repo/pulls"),
            ("GET", "/repos/owner/repo/releases"),
            ("GET", "/repos/owner/repo/git/refs/heads/main"),
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

    def test_check_github_blocklist_auto_merge_enable(self, policy_engine):
        """Test auto-merge enablement is blocked."""
        result = policy_engine._check_github_blocklist(
            "PUT", "/repos/owner/repo/pulls/1/auto-merge"
        )
        assert result is not None
        assert "auto-merge" in result

    def test_check_github_blocklist_auto_merge_disable(self, policy_engine):
        """Test auto-merge disablement is blocked."""
        result = policy_engine._check_github_blocklist(
            "DELETE", "/repos/owner/repo/pulls/1/auto-merge"
        )
        assert result is not None
        assert "auto-merge" in result

    def test_check_github_blocklist_review_deletion(self, policy_engine):
        """Test review deletion is blocked."""
        result = policy_engine._check_github_blocklist(
            "DELETE", "/repos/owner/repo/pulls/1/reviews/123"
        )
        assert result is not None
        assert "review" in result.lower()


class TestPRReviewBodyPolicies:
    """Tests for PR review body inspection policies."""

    @pytest.fixture
    def policy_engine(self):
        """Create PolicyEngine instance."""
        return PolicyEngine()

    def test_blocked_pr_review_approve(self, policy_engine):
        """Test POST /pulls/1/reviews with event:APPROVE is blocked."""
        import json

        body = json.dumps({"event": "APPROVE"}).encode()
        result = policy_engine._check_github_body_policies(
            "POST", "/repos/owner/repo/pulls/1/reviews", body, "application/json", ""
        )
        assert result is not None
        assert "approv" in result.lower()

    def test_allowed_pr_review_comment(self, policy_engine):
        """Test POST /pulls/1/reviews with event:COMMENT is allowed."""
        import json

        body = json.dumps({"event": "COMMENT"}).encode()
        result = policy_engine._check_github_body_policies(
            "POST", "/repos/owner/repo/pulls/1/reviews", body, "application/json", ""
        )
        assert result is None

    def test_allowed_pr_review_request_changes(self, policy_engine):
        """Test POST /pulls/1/reviews with event:REQUEST_CHANGES is allowed."""
        import json

        body = json.dumps({"event": "REQUEST_CHANGES"}).encode()
        result = policy_engine._check_github_body_policies(
            "POST", "/repos/owner/repo/pulls/1/reviews", body, "application/json", ""
        )
        assert result is None


class TestNormalizePath:
    """Tests for normalize_path function."""

    def test_basic_path(self):
        from addons.policy_engine import normalize_path
        assert normalize_path("/repos/owner/repo") == "/repos/owner/repo"

    def test_strip_query_string(self):
        from addons.policy_engine import normalize_path
        assert normalize_path("/repos/owner/repo?page=1&per_page=30") == "/repos/owner/repo"

    def test_strip_trailing_slash(self):
        from addons.policy_engine import normalize_path
        assert normalize_path("/repos/owner/repo/") == "/repos/owner/repo"

    def test_collapse_repeated_slashes(self):
        from addons.policy_engine import normalize_path
        assert normalize_path("/repos//owner///repo") == "/repos/owner/repo"

    def test_resolve_dot_dot(self):
        from addons.policy_engine import normalize_path
        assert normalize_path("/repos/owner/repo/../other") == "/repos/owner/other"

    def test_url_decode(self):
        from addons.policy_engine import normalize_path
        # %2F decodes to / — single encoding is fine
        assert normalize_path("/repos/owner%2Frepo") == "/repos/owner/repo"

    def test_double_encoding_rejected(self):
        from addons.policy_engine import normalize_path
        # %252F decodes to %2F — % still present → rejected
        assert normalize_path("/repos/%252F/evil") is None

    def test_triple_encoding_rejected(self):
        from addons.policy_engine import normalize_path
        # %25252F decodes to %252F — % still present → rejected
        assert normalize_path("/repos/%25252F/evil") is None

    def test_encoded_dot_dot_rejected(self):
        from addons.policy_engine import normalize_path
        # %252e%252e decodes to %2e%2e — % still present → rejected
        assert normalize_path("/repos/%252e%252e/evil") is None

    def test_bare_slash(self):
        from addons.policy_engine import normalize_path
        assert normalize_path("/") == "/"

    def test_empty_path(self):
        from addons.policy_engine import normalize_path
        assert normalize_path("") == "/"

    def test_legitimate_no_encoding(self):
        from addons.policy_engine import normalize_path
        assert normalize_path("/repos/owner/repo/pulls/123") == "/repos/owner/repo/pulls/123"


class TestEndpointPathEnforcement:
    """Tests for endpoint path enforcement (Step 2b)."""

    @pytest.fixture
    def policy_engine_with_config(self):
        """Create PolicyEngine with full allowlist config including endpoints."""
        from config import AllowlistConfig, HttpEndpointConfig, BlockedPathConfig

        engine = PolicyEngine()
        engine._domains = ["api.github.com", "pypi.org"]
        engine._allowlist = AllowlistConfig(
            version="1.0",
            domains=["api.github.com", "pypi.org"],
            http_endpoints=[
                HttpEndpointConfig(
                    host="api.github.com",
                    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                    paths=[
                        "/repos/*/*",
                        "/repos/*/*/pulls",
                        "/repos/*/*/pulls/*",
                        "/repos/*/*/issues",
                        "/repos/*/*/issues/*",
                        "/repos/*/*/issues/*/comments",
                        "/repos/*/*/issues/*/comments/*",
                        "/repos/*/*/issues/comments",
                        "/repos/*/*/issues/comments/*",
                        "/repos/*/*/branches",
                        "/repos/*/*/branches/**",
                        "/repos/*/*/git/**",
                        "/repos/*/*/contents",
                        "/repos/*/*/contents/**",
                        "/repos/*/*/compare/**",
                        "/repos/*/*/commits",
                        "/repos/*/*/commits/*",
                        "/repos/*/*/releases",
                        "/repos/*/*/releases/*",
                        "/repos/*/*/pulls/*/comments",
                        "/repos/*/*/pulls/*/comments/*",
                        "/repos/*/*/pulls/comments",
                        "/repos/*/*/pulls/comments/*",
                        "/repos/*/*/pulls/*/reviews",
                        "/repos/*/*/pulls/*/reviews/*",
                        "/repos/*/*/pulls/*/reviews/**",
                        "/user/*",
                        "/rate_limit",
                    ],
                ),
            ],
            blocked_paths=[
                BlockedPathConfig(
                    host="api.github.com",
                    patterns=[
                        "/repos/*/*/hooks",
                        "/repos/*/*/hooks/*",
                        "/repos/*/*/keys",
                        "/repos/*/*/keys/*",
                        "/repos/*/*/actions/secrets",
                        "/repos/*/*/actions/secrets/*",
                        "/repos/*/*/branches/**/protection",
                        "/repos/*/*/branches/**/protection/**",
                        "/repos/*/*/branches/**/rename",
                    ],
                ),
            ],
        )
        return engine

    @pytest.fixture
    def mock_container_config(self):
        config = Mock()
        config.container_id = "test-container"
        return config

    def _make_flow(self, method, host, path):
        flow = Mock()
        flow.request = Mock()
        flow.request.method = method
        flow.request.pretty_host = host
        flow.request.path = path
        flow.metadata = {}
        flow.response = None
        return flow

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_allowed_repo_path(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """GET /repos/owner/repo is allowed."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("GET", "api.github.com", "/repos/owner/repo")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_disallowed_method_denied(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """HEAD method is denied when endpoint methods do not include HEAD."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("HEAD", "api.github.com", "/repos/owner/repo")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert decision["policy_type"] == "endpoint_path"
        assert "method" in decision["reason"].lower()

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_blocked_hooks_path(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """POST /repos/owner/repo/hooks is denied (not in allowed paths)."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("POST", "api.github.com", "/repos/owner/repo/hooks")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert decision["policy_type"] == "endpoint_path"

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_blocked_actions_secrets(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """POST /repos/owner/repo/actions/secrets is denied (not in allowed paths)."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("POST", "api.github.com", "/repos/owner/repo/actions/secrets")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert decision["policy_type"] == "endpoint_path"

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_path_traversal_blocked(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Path traversal with .. resolves and is checked against allowed paths."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        # /repos/owner/repo/../../../admin resolves to /admin — not in allowed paths
        flow = self._make_flow("GET", "api.github.com", "/repos/owner/repo/../../../admin")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert "not in allowed paths" in decision["reason"]

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_double_encoded_path_rejected(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """%252F double-encoded path is rejected."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("GET", "api.github.com", "/repos/%252e%252e/evil")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert "double-encoding" in decision["reason"]

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_repeated_separators_normalized(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Repeated slashes are collapsed before matching."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        # /repos//owner///repo → /repos/owner/repo (matches /repos/*/*)
        flow = self._make_flow("GET", "api.github.com", "/repos//owner///repo")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_trailing_slash_normalized(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Trailing slashes are stripped before matching."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("GET", "api.github.com", "/repos/owner/repo/")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_non_endpoint_host_domain_level_only(
        self, mock_ctx, mock_get_config,
        policy_engine_with_config, mock_container_config
    ):
        """Hosts without endpoint config use domain-level allowlisting only."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        # pypi.org is in domains but has no http_endpoints entry
        flow = self._make_flow("GET", "pypi.org", "/any/path/here")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_unmatched_path_denied(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Paths not matching any allowed pattern are denied."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("GET", "api.github.com", "/admin/something")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert "not in allowed paths" in decision["reason"]

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_mixed_case_encoding_normalized(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Mixed-case %2f/%2F both normalize to /."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        # %2f and %2F both decode to / — should match /repos/*/*
        flow = self._make_flow("GET", "api.github.com", "/repos/owner%2frepo")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        # After decode: /repos/owner/repo — matches /repos/*/*
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_legitimate_path_no_encoding(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Legitimate path with no encoding is allowed."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("GET", "api.github.com", "/repos/owner/repo/pulls/123")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_compare_path_with_encoded_slash_allowed(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Compare refs with encoded slashes should remain allowed."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "GET",
            "api.github.com",
            "/repos/owner/repo/compare/main...feature%2Fone",
        )

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_git_ref_mutation_path_blocked(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Git ref update endpoints are blocked even when endpoint paths allow /git/**."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "PATCH",
            "api.github.com",
            "/repos/owner/repo/git/refs/heads/main",
        )

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert decision["policy_type"] == "blocklist"
        assert "ref mutation" in decision["reason"].lower()

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_git_ref_read_path_allowed(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Git ref read endpoints remain allowed."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "GET",
            "api.github.com",
            "/repos/owner/repo/git/refs/heads/main",
        )

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_contents_path_with_nested_file_allowed(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Nested file paths in contents endpoint should remain allowed."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "GET",
            "api.github.com",
            "/repos/owner/repo/contents/src%2Fpkg%2Ffile.py",
        )

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_contents_root_path_allowed(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Contents root endpoint should remain allowed."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "GET",
            "api.github.com",
            "/repos/owner/repo/contents",
        )

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_uppercase_host_still_enforces_github_blocklist(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Mixed-case host headers must not bypass GitHub blocklist checks."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "PATCH",
            "API.GITHUB.COM",
            "/repos/owner/repo/git/refs/heads/main",
        )

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert decision["policy_type"] == "blocklist"
        assert "ref mutation" in decision["reason"].lower()

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_issue_comment_path_allowed(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Issue comment endpoints remain allowed."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "POST",
            "api.github.com",
            "/repos/owner/repo/issues/1/comments",
        )

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_pull_review_path_allowed(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Pull request review endpoints remain allowed for non-APPROVE events."""
        import json

        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "POST",
            "api.github.com",
            "/repos/owner/repo/pulls/1/reviews",
        )
        # Body inspection requires proper headers and a non-APPROVE body
        flow.request.headers = {"content-type": "application/json"}
        flow.request.content = json.dumps({"event": "COMMENT", "body": "LGTM"}).encode()

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_pull_review_subpath_allowed(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Nested review subpaths remain allowed via ** matching."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "GET",
            "api.github.com",
            "/repos/owner/repo/pulls/1/reviews/2/events",
        )

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_branch_protection_path_blocked(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Branch protection mutation endpoint is blocked."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "PUT",
            "api.github.com",
            "/repos/owner/repo/branches/main/protection",
        )

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert "blocked by policy" in decision["reason"]

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_branch_protection_nested_branch_blocked(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Branch protection endpoint with encoded slash branch is blocked."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "PUT",
            "api.github.com",
            "/repos/owner/repo/branches/feature%2Fone/protection",
        )

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert "blocked by policy" in decision["reason"]

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_branch_rename_path_blocked(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """Branch rename endpoint is blocked."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "POST",
            "api.github.com",
            "/repos/owner/repo/branches/main/rename",
        )

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert "blocked by policy" in decision["reason"]

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_blocked_hooks_subpath(
        self, mock_ctx, mock_get_config, mock_response_make,
        policy_engine_with_config, mock_container_config
    ):
        """GET /repos/owner/repo/hooks/456 is denied (not in allowed paths)."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("GET", "api.github.com", "/repos/owner/repo/hooks/456")

        policy_engine_with_config.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert decision["policy_type"] == "endpoint_path"


class TestBlockedPathsDefenseInDepth:
    """Tests for blocked_paths as defense-in-depth when paths match allowed patterns."""

    @pytest.fixture
    def engine_with_broad_allow(self):
        """Engine with broad allowed paths to test blocked_paths layer."""
        from config import AllowlistConfig, HttpEndpointConfig, BlockedPathConfig

        engine = PolicyEngine()
        engine._domains = ["api.github.com"]
        engine._allowlist = AllowlistConfig(
            version="1.0",
            domains=["api.github.com"],
            http_endpoints=[
                HttpEndpointConfig(
                    host="api.github.com",
                    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                    paths=[
                        "/repos/*/*",
                        "/repos/*/*/hooks",
                        "/repos/*/*/hooks/*",
                        "/repos/*/*/actions/secrets",
                        "/repos/*/*/actions/secrets/*",
                        "/repos/*/*/branches/**",
                        "/repos/*/*/pulls",
                        "/repos/*/*/pulls/*",
                    ],
                ),
            ],
            blocked_paths=[
                BlockedPathConfig(
                    host="api.github.com",
                    patterns=[
                        "/repos/*/*/hooks",
                        "/repos/*/*/hooks/*",
                        "/repos/*/*/actions/secrets",
                        "/repos/*/*/actions/secrets/*",
                        "/repos/*/*/branches/**/protection",
                        "/repos/*/*/branches/**/protection/**",
                        "/repos/*/*/branches/**/rename",
                    ],
                ),
            ],
        )
        return engine

    @pytest.fixture
    def mock_container_config(self):
        config = Mock()
        config.container_id = "test"
        return config

    def _make_flow(self, method, host, path):
        flow = Mock()
        flow.request = Mock()
        flow.request.method = method
        flow.request.pretty_host = host
        flow.request.path = path
        flow.metadata = {}
        flow.response = None
        return flow

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_hooks_blocked_even_if_allowed(
        self, mock_ctx, mock_get_config, mock_response_make,
        engine_with_broad_allow, mock_container_config
    ):
        """blocked_paths denies hooks even when the pattern appears in allowed paths."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("POST", "api.github.com", "/repos/owner/repo/hooks")

        engine_with_broad_allow.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert "blocked by policy" in decision["reason"]

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_secrets_blocked_even_if_allowed(
        self, mock_ctx, mock_get_config, mock_response_make,
        engine_with_broad_allow, mock_container_config
    ):
        """blocked_paths denies actions/secrets even when pattern is allowed."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("GET", "api.github.com", "/repos/owner/repo/actions/secrets/MY_SECRET")

        engine_with_broad_allow.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert "blocked by policy" in decision["reason"]

    @patch("addons.policy_engine.http.Response.make", side_effect=make_mock_response)
    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_branch_protection_blocked_even_if_allowed(
        self, mock_ctx, mock_get_config, mock_response_make,
        engine_with_broad_allow, mock_container_config
    ):
        """blocked_paths denies branch protection endpoints even with broad allow patterns."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow(
            "PUT",
            "api.github.com",
            "/repos/owner/repo/branches/main/protection",
        )

        engine_with_broad_allow.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is False
        assert "blocked by policy" in decision["reason"]

    @patch("addons.policy_engine.get_container_config")
    @patch("addons.policy_engine.ctx")
    def test_pulls_allowed_not_in_blocked(
        self, mock_ctx, mock_get_config,
        engine_with_broad_allow, mock_container_config
    ):
        """Pulls are allowed because they're in allowed paths and not in blocked_paths."""
        mock_get_config.return_value = mock_container_config
        mock_ctx.log = Mock()
        flow = self._make_flow("GET", "api.github.com", "/repos/owner/repo/pulls/123")

        engine_with_broad_allow.request(flow)

        decision = flow.metadata[POLICY_DECISION_KEY]
        assert decision["allowed"] is True


class TestSegmentMatch:
    """Tests for segment_match function."""

    def test_exact_path(self):
        from config import segment_match
        assert segment_match("/rate_limit", "/rate_limit") is True

    def test_single_wildcard(self):
        from config import segment_match
        assert segment_match("/user/*", "/user/repos") is True

    def test_wildcard_no_span(self):
        from config import segment_match
        assert segment_match("/user/*", "/user/repos/extra") is False

    def test_double_wildcard(self):
        from config import segment_match
        assert segment_match("/repos/*/*", "/repos/owner/repo") is True

    def test_double_wildcard_no_span(self):
        from config import segment_match
        assert segment_match("/repos/*/*", "/repos/owner/repo/extra") is False

    def test_wildcard_empty_segment(self):
        from config import segment_match
        # * requires at least one character
        assert segment_match("/repos/*/hooks", "/repos//hooks") is False

    def test_no_match(self):
        from config import segment_match
        assert segment_match("/repos/*/*/pulls", "/repos/owner/repo/issues") is False

    def test_double_star_matches_multi_segment(self):
        from config import segment_match
        assert segment_match(
            "/repos/*/*/contents/**", "/repos/owner/repo/contents/src/pkg/main.py"
        ) is True

    def test_single_star_does_not_match_multi_segment(self):
        from config import segment_match
        assert segment_match(
            "/repos/*/*/contents/*", "/repos/owner/repo/contents/src/pkg/main.py"
        ) is False


class TestCheckGithubBodyPolicies:
    """Tests for _check_github_body_policies method."""

    @pytest.fixture
    def policy_engine(self):
        """Create PolicyEngine instance."""
        return PolicyEngine()

    def test_patch_pr_title_edit_allowed(self, policy_engine):
        """Test PATCH /pulls/1 with title edit is allowed."""
        import json

        body = json.dumps({"title": "new title"}).encode()
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "application/json", ""
        )
        assert result is None

    def test_patch_pr_state_closed_blocked(self, policy_engine):
        """Test PATCH /pulls/1 with state:closed is blocked."""
        import json

        body = json.dumps({"state": "closed"}).encode()
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "application/json", ""
        )
        assert result is not None
        assert "pull request" in result.lower() or "Closing" in result

    def test_patch_pr_state_open_allowed(self, policy_engine):
        """Test PATCH /pulls/1 with state:open is allowed (reopen)."""
        import json

        body = json.dumps({"state": "open"}).encode()
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "application/json", ""
        )
        assert result is None

    def test_patch_pr_state_closed_with_title_blocked(self, policy_engine):
        """Test PATCH /pulls/1 with state:closed + title is still blocked."""
        import json

        body = json.dumps({"state": "closed", "title": "new title"}).encode()
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "application/json", ""
        )
        assert result is not None
        assert "Closing" in result

    def test_malformed_json_blocked(self, policy_engine):
        """Test malformed JSON body is blocked."""
        body = b"{not valid json"
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "application/json", ""
        )
        assert result is not None
        assert "Malformed" in result

    def test_streaming_mode_blocked(self, policy_engine):
        """Test streaming mode (content=None) is blocked."""
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", None, "application/json", ""
        )
        assert result is not None
        assert "Streaming" in result

    def test_patch_issue_state_closed_blocked(self, policy_engine):
        """Test PATCH /issues/1 with state:closed is blocked."""
        import json

        body = json.dumps({"state": "closed"}).encode()
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/issues/1", body, "application/json", ""
        )
        assert result is not None
        assert "issue" in result.lower() or "Closing" in result

    def test_existing_merge_block_still_works(self, policy_engine):
        """Test that existing merge block is not affected by body policies."""
        # Merge block is in _check_github_blocklist, not body policies
        result = policy_engine._check_github_blocklist(
            "PUT", "/repos/owner/repo/pulls/1/merge"
        )
        assert result is not None
        assert "merge" in result.lower()

    def test_missing_content_type_rejected(self, policy_engine):
        """Test missing Content-Type header is rejected."""
        import json

        body = json.dumps({"title": "new"}).encode()
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "", ""
        )
        assert result is not None
        assert "Content-Type" in result

    def test_wrong_content_type_rejected(self, policy_engine):
        """Test Content-Type text/plain is rejected."""
        import json

        body = json.dumps({"title": "new"}).encode()
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "text/plain", ""
        )
        assert result is not None
        assert "Content-Type" in result
        assert "text/plain" in result

    def test_duplicate_keys_last_value_wins_blocked(self, policy_engine):
        """Test duplicate keys: {state:open, state:closed} blocked (last value wins)."""
        # json.loads uses last value for duplicate keys
        # Manually craft JSON with duplicate keys
        body = b'{"state": "open", "state": "closed"}'
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "application/json", ""
        )
        assert result is not None
        assert "Closing" in result

    def test_unicode_escape_state_blocked(self, policy_engine):
        """Test unicode escape state resolved and blocked."""
        # json.loads resolves unicode escapes: \u0063losed -> closed
        body = b'{"state": "\\u0063losed"}'
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "application/json", ""
        )
        assert result is not None
        assert "Closing" in result

    def test_non_patch_method_ignored(self, policy_engine):
        """Test that non-PATCH methods are not inspected."""
        import json

        body = json.dumps({"state": "closed"}).encode()
        result = policy_engine._check_github_body_policies(
            "GET", "/repos/owner/repo/pulls/1", body, "application/json", ""
        )
        assert result is None

    def test_non_matching_path_ignored(self, policy_engine):
        """Test that non-PR/issue paths are not inspected."""
        import json

        body = json.dumps({"state": "closed"}).encode()
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/labels/1", body, "application/json", ""
        )
        assert result is None

    def test_compressed_body_rejected(self, policy_engine):
        """Test compressed request bodies are rejected."""
        import json

        body = json.dumps({"title": "new"}).encode()
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "application/json", "gzip"
        )
        assert result is not None
        assert "Compressed" in result

    def test_bom_stripped_before_parsing(self, policy_engine):
        """Test UTF-8 BOM is stripped before JSON parsing."""
        import json

        body = b"\xef\xbb\xbf" + json.dumps({"title": "new"}).encode()
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "application/json", ""
        )
        assert result is None

    def test_content_type_with_charset_allowed(self, policy_engine):
        """Test Content-Type with charset parameter is accepted."""
        import json

        body = json.dumps({"title": "new"}).encode()
        result = policy_engine._check_github_body_policies(
            "PATCH",
            "/repos/owner/repo/pulls/1",
            body,
            "application/json; charset=utf-8",
            "",
        )
        assert result is None

    def test_non_object_body_rejected(self, policy_engine):
        """Test non-object JSON body (e.g., array) is rejected."""
        body = b'["state", "closed"]'
        result = policy_engine._check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body, "application/json", ""
        )
        assert result is not None
        assert "JSON object" in result

    def test_pattern_matches_pr_endpoint(self):
        """Test GITHUB_PATCH_PR_PATTERN matches PR endpoints."""
        assert GITHUB_PATCH_PR_PATTERN.match("/repos/owner/repo/pulls/1")
        assert GITHUB_PATCH_PR_PATTERN.match("/repos/org/my-repo/pulls/42")
        assert not GITHUB_PATCH_PR_PATTERN.match("/repos/owner/repo/pulls/1/merge")
        assert not GITHUB_PATCH_PR_PATTERN.match("/repos/owner/repo/pulls")

    def test_pattern_matches_issue_endpoint(self):
        """Test GITHUB_PATCH_ISSUE_PATTERN matches issue endpoints."""
        assert GITHUB_PATCH_ISSUE_PATTERN.match("/repos/owner/repo/issues/1")
        assert GITHUB_PATCH_ISSUE_PATTERN.match("/repos/org/my-repo/issues/99")
        assert not GITHUB_PATCH_ISSUE_PATTERN.match("/repos/owner/repo/issues")
        assert not GITHUB_PATCH_ISSUE_PATTERN.match(
            "/repos/owner/repo/issues/1/comments"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
