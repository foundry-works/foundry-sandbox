"""Dual-layer consistency tests for GitHub API security.

Enforces the maintenance contract: when a new security-critical endpoint is
blocked, it must be blocked in BOTH github-api-filter.py (first line, pattern
matching) and policy_engine.py (second line, can inspect bodies).

Adding a new operation to BLOCKED_OPERATIONS without implementing it in both
layers causes a test failure.

Documented asymmetries (e.g., GraphQL vs REST review blocking) are explicitly
handled and must be justified in KNOWN_ASYMMETRIES.
"""

import importlib
import json
from unittest.mock import Mock, patch, MagicMock

import pytest

# Import modules using importlib to get the actual module names
github_api_filter = importlib.import_module("github-api-filter")
GitHubAPIFilter = github_api_filter.GitHubAPIFilter

from addons.policy_engine import PolicyEngine


# Operations that MUST be blocked in both layers
# Each entry: operation_name -> { method, path, description }
BLOCKED_OPERATIONS = {
    "merge_pr": {
        "method": "PUT",
        "path": "/repos/owner/repo/pulls/1/merge",
        "description": "Merge pull request",
    },
    "auto_merge_enable": {
        "method": "PUT",
        "path": "/repos/owner/repo/pulls/1/auto-merge",
        "description": "Enable auto-merge",
    },
    "auto_merge_disable": {
        "method": "DELETE",
        "path": "/repos/owner/repo/pulls/1/auto-merge",
        "description": "Disable auto-merge",
    },
    "delete_review": {
        "method": "DELETE",
        "path": "/repos/owner/repo/pulls/1/reviews/123",
        "description": "Delete pull request review",
    },
}

# Operations with documented asymmetries between the two layers
# These are tested separately with layer-specific assertions
KNOWN_ASYMMETRIES = {
    "graphql_add_review": {
        "description": (
            "GitHubAPIFilter blocks addPullRequestReview entirely at GraphQL level "
            "(cannot inspect GraphQL arguments for APPROVE-only filtering). "
            "PolicyEngine blocks only APPROVE events via REST body inspection."
        ),
        "api_filter_blocks": True,  # Blocks GraphQL mutation entirely
        "policy_engine_blocks_approve": True,  # Blocks REST APPROVE only
        "policy_engine_allows_comment": True,  # Allows COMMENT
    },
}


class TestDualLayerConsistency:
    """Verify both security layers block the same operations."""

    @pytest.fixture
    def api_filter(self):
        return GitHubAPIFilter()

    @pytest.fixture
    def policy_engine(self):
        engine = PolicyEngine()
        engine._domains = ["api.github.com"]
        return engine

    def _make_api_filter_flow(self, method, path):
        """Create mock flow for GitHubAPIFilter (uses flow.request.host)."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = method
        flow.request.path = path
        flow.request.get_text = Mock(return_value="")
        flow.response = None
        return flow

    def _make_policy_engine_flow(self, method, path, body=None, content_type=""):
        """Create mock flow for PolicyEngine (uses flow.request.pretty_host)."""
        flow = Mock()
        flow.request = Mock()
        flow.request.method = method
        flow.request.pretty_host = "api.github.com"
        flow.request.path = path
        flow.request.headers = Mock()
        flow.request.headers.get = Mock(return_value=content_type)
        flow.request.content = body
        flow.metadata = {}
        flow.response = None
        return flow

    @pytest.mark.parametrize("op_name,op_spec", BLOCKED_OPERATIONS.items())
    @patch.object(github_api_filter, "ctx")
    def test_api_filter_blocks(self, mock_ctx, op_name, op_spec, api_filter):
        """Test that GitHubAPIFilter blocks each operation."""
        mock_ctx.log = Mock()
        flow = self._make_api_filter_flow(op_spec["method"], op_spec["path"])

        api_filter.request(flow)

        assert flow.response is not None, (
            f"GitHubAPIFilter did NOT block {op_name}: "
            f"{op_spec['method']} {op_spec['path']} ({op_spec['description']})"
        )
        assert flow.response.status_code == 403, (
            f"GitHubAPIFilter response status is {flow.response.status_code}, "
            f"expected 403 for {op_name}"
        )

    @pytest.mark.parametrize("op_name,op_spec", BLOCKED_OPERATIONS.items())
    def test_policy_engine_blocks(self, op_name, op_spec, policy_engine):
        """Test that PolicyEngine blocks each operation."""
        method = op_spec["method"]
        path = op_spec["path"]

        result = policy_engine._check_github_blocklist(method, path)

        assert result is not None, (
            f"PolicyEngine did NOT block {op_name}: "
            f"{method} {path} ({op_spec['description']})"
        )

    @pytest.mark.parametrize("op_name,op_spec", BLOCKED_OPERATIONS.items())
    def test_both_layers_block(self, op_name, op_spec, api_filter, policy_engine):
        """Test that BOTH layers block each operation.

        This is the core maintenance contract: every critical operation
        must be blocked in both layers to ensure defense-in-depth.
        """
        method = op_spec["method"]
        path = op_spec["path"]

        # Layer 1: GitHubAPIFilter
        api_filter_flow = self._make_api_filter_flow(method, path)
        with patch.object(github_api_filter, "ctx"):
            api_filter.request(api_filter_flow)

        # Layer 2: PolicyEngine
        policy_engine_blocks = policy_engine._check_github_blocklist(method, path)

        # Both layers must block
        api_filter_blocks = api_filter_flow.response is not None
        assert api_filter_blocks and policy_engine_blocks, (
            f"Operation {op_name} ({method} {path}) is not blocked by both layers:\n"
            f"  - GitHubAPIFilter: {'BLOCKS' if api_filter_blocks else 'ALLOWS'}\n"
            f"  - PolicyEngine: {'BLOCKS' if policy_engine_blocks else 'ALLOWS'}"
        )


class TestKnownAsymmetries:
    """Test documented asymmetries between the two layers.

    These tests verify that asymmetries are intentional and well-documented,
    preventing accidental divergence while allowing necessary differences.
    """

    @pytest.fixture
    def api_filter(self):
        return GitHubAPIFilter()

    @pytest.fixture
    def policy_engine(self):
        engine = PolicyEngine()
        engine._domains = ["api.github.com"]
        return engine

    @patch.object(github_api_filter, "ctx")
    def test_graphql_add_review_blocked_in_api_filter(self, mock_ctx, api_filter):
        """GitHubAPIFilter blocks addPullRequestReview at GraphQL level.

        Documented asymmetry: Cannot inspect GraphQL arguments to selectively
        allow COMMENT/REQUEST_CHANGES while blocking APPROVE. Blocks entirely.
        """
        mock_ctx.log = Mock()
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "POST"
        flow.request.path = "/graphql"
        flow.request.get_text = Mock(return_value=json.dumps({
            "query": (
                "mutation { "
                "addPullRequestReview("
                "input: {pullRequestId: \"PR_1\", event: APPROVE}) "
                "{ pullRequestReview { id } } }"
            )
        }))
        flow.response = None

        api_filter.request(flow)

        assert flow.response is not None, (
            "GitHubAPIFilter should block addPullRequestReview GraphQL mutation"
        )
        assert KNOWN_ASYMMETRIES["graphql_add_review"]["api_filter_blocks"]

    def test_policy_engine_blocks_rest_review_approve(self, policy_engine):
        """PolicyEngine blocks REST review with APPROVE event.

        Documented asymmetry: REST layer can inspect body and block selectively.
        Blocks APPROVE to prevent self-approval via REST API.
        """
        body = json.dumps({"event": "APPROVE"}).encode()
        result = policy_engine._check_github_body_policies(
            "POST", "/repos/owner/repo/pulls/1/reviews",
            body, "application/json", ""
        )
        assert result is not None, (
            "PolicyEngine should block REST review APPROVE"
        )
        assert KNOWN_ASYMMETRIES["graphql_add_review"]["policy_engine_blocks_approve"]

    def test_policy_engine_allows_rest_review_comment(self, policy_engine):
        """PolicyEngine allows REST review with COMMENT event.

        Documented asymmetry: COMMENT reviews are allowed at REST layer
        while being collaterally blocked at GraphQL layer.
        """
        body = json.dumps({"event": "COMMENT"}).encode()
        result = policy_engine._check_github_body_policies(
            "POST", "/repos/owner/repo/pulls/1/reviews",
            body, "application/json", ""
        )
        assert result is None, (
            "PolicyEngine should allow REST review COMMENT"
        )
        assert KNOWN_ASYMMETRIES["graphql_add_review"]["policy_engine_allows_comment"]

    def test_policy_engine_allows_rest_review_request_changes(self, policy_engine):
        """PolicyEngine allows REST review with REQUEST_CHANGES event.

        Documented asymmetry: REQUEST_CHANGES reviews are allowed at REST layer.
        """
        body = json.dumps({"event": "REQUEST_CHANGES"}).encode()
        result = policy_engine._check_github_body_policies(
            "POST", "/repos/owner/repo/pulls/1/reviews",
            body, "application/json", ""
        )
        assert result is None, (
            "PolicyEngine should allow REST review REQUEST_CHANGES"
        )


class TestBlocklistPatternCoverage:
    """Verify that all critical operations in BLOCKED_PATTERNS are also in _check_github_blocklist."""

    @pytest.fixture
    def policy_engine(self):
        engine = PolicyEngine()
        engine._domains = ["api.github.com"]
        return engine

    def test_merge_pr_in_both_layers(self, policy_engine):
        """Merge PR (PUT /repos/.../pulls/.../merge) must be blocked in both layers."""
        # GitHubAPIFilter has it in BLOCKED_PATTERNS
        # PolicyEngine must have it in _check_github_blocklist via GITHUB_MERGE_PR_PATTERN
        result = policy_engine._check_github_blocklist(
            "PUT", "/repos/owner/repo/pulls/1/merge"
        )
        assert result is not None, "PolicyEngine must block PR merge via _check_github_blocklist"

    def test_auto_merge_put_in_both_layers(self, policy_engine):
        """Auto-merge PUT (PUT /repos/.../pulls/.../auto-merge) must be blocked in both layers."""
        result = policy_engine._check_github_blocklist(
            "PUT", "/repos/owner/repo/pulls/1/auto-merge"
        )
        assert result is not None, "PolicyEngine must block auto-merge PUT via _check_github_blocklist"

    def test_auto_merge_delete_in_both_layers(self, policy_engine):
        """Auto-merge DELETE (DELETE /repos/.../pulls/.../auto-merge) must be blocked in both layers."""
        result = policy_engine._check_github_blocklist(
            "DELETE", "/repos/owner/repo/pulls/1/auto-merge"
        )
        assert result is not None, "PolicyEngine must block auto-merge DELETE via _check_github_blocklist"

    def test_delete_review_in_both_layers(self, policy_engine):
        """Review deletion (DELETE /repos/.../pulls/.../reviews/...) must be blocked in both layers."""
        result = policy_engine._check_github_blocklist(
            "DELETE", "/repos/owner/repo/pulls/1/reviews/123"
        )
        assert result is not None, "PolicyEngine must block review deletion via _check_github_blocklist"


class TestAPIFilterBlockedPatterns:
    """Verify GitHubAPIFilter blocks all critical operations."""

    @pytest.fixture
    def api_filter(self):
        return GitHubAPIFilter()

    @patch.object(github_api_filter, "ctx")
    def test_api_filter_has_blocklist(self, mock_ctx, api_filter):
        """GitHubAPIFilter must have BLOCKED_PATTERNS defined."""
        mock_ctx.log = Mock()
        # Access the module's BLOCKED_PATTERNS to verify it exists
        assert hasattr(github_api_filter, "BLOCKED_PATTERNS"), (
            "github-api-filter.py must export BLOCKED_PATTERNS"
        )
        assert len(github_api_filter.BLOCKED_PATTERNS) > 0, (
            "BLOCKED_PATTERNS must not be empty"
        )

    @patch.object(github_api_filter, "ctx")
    def test_api_filter_repo_delete_blocked(self, mock_ctx, api_filter):
        """Repository deletion must be blocked."""
        mock_ctx.log = Mock()
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "DELETE"
        flow.request.path = "/repos/owner/repo"
        flow.request.get_text = Mock(return_value="")
        flow.response = None

        api_filter.request(flow)
        assert flow.response is not None, "GitHubAPIFilter should block repo deletion"

    @patch.object(github_api_filter, "ctx")
    def test_api_filter_release_delete_blocked(self, mock_ctx, api_filter):
        """Release deletion must be blocked."""
        mock_ctx.log = Mock()
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "DELETE"
        flow.request.path = "/repos/owner/repo/releases/1"
        flow.request.get_text = Mock(return_value="")
        flow.response = None

        api_filter.request(flow)
        assert flow.response is not None, "GitHubAPIFilter should block release deletion"


class TestPolicyEngineBlocklistCompleteness:
    """Verify PolicyEngine blocks all critical GitHub operations."""

    @pytest.fixture
    def policy_engine(self):
        engine = PolicyEngine()
        engine._domains = ["api.github.com"]
        return engine

    def test_policy_engine_has_github_patterns(self, policy_engine):
        """PolicyEngine must have GitHub pattern constants defined."""
        from addons.policy_engine import (
            GITHUB_MERGE_PR_PATTERN,
            GITHUB_AUTO_MERGE_PATTERN,
            GITHUB_DELETE_REVIEW_PATTERN,
        )
        assert GITHUB_MERGE_PR_PATTERN is not None, (
            "policy_engine.py must have GITHUB_MERGE_PR_PATTERN"
        )
        assert GITHUB_AUTO_MERGE_PATTERN is not None, (
            "policy_engine.py must have GITHUB_AUTO_MERGE_PATTERN"
        )
        assert GITHUB_DELETE_REVIEW_PATTERN is not None, (
            "policy_engine.py must have GITHUB_DELETE_REVIEW_PATTERN"
        )

    def test_policy_engine_merge_pr_pattern(self, policy_engine):
        """GITHUB_MERGE_PR_PATTERN must match PR merge endpoints."""
        from addons.policy_engine import GITHUB_MERGE_PR_PATTERN
        assert GITHUB_MERGE_PR_PATTERN.match("/repos/owner/repo/pulls/1/merge")
        assert GITHUB_MERGE_PR_PATTERN.match("/repos/o/r/pulls/123/merge")
        assert not GITHUB_MERGE_PR_PATTERN.match("/repos/owner/repo/pulls/1/merge/something")
        assert not GITHUB_MERGE_PR_PATTERN.match("/repos/owner/repo/pulls/1/comments")

    def test_policy_engine_auto_merge_pattern(self, policy_engine):
        """GITHUB_AUTO_MERGE_PATTERN must match auto-merge endpoints."""
        from addons.policy_engine import GITHUB_AUTO_MERGE_PATTERN
        assert GITHUB_AUTO_MERGE_PATTERN.match("/repos/owner/repo/pulls/1/auto-merge")
        assert GITHUB_AUTO_MERGE_PATTERN.match("/repos/o/r/pulls/999/auto-merge")
        assert not GITHUB_AUTO_MERGE_PATTERN.match("/repos/owner/repo/pulls/1/auto-merge/something")

    def test_policy_engine_delete_review_pattern(self, policy_engine):
        """GITHUB_DELETE_REVIEW_PATTERN must match review deletion endpoints."""
        from addons.policy_engine import GITHUB_DELETE_REVIEW_PATTERN
        assert GITHUB_DELETE_REVIEW_PATTERN.match("/repos/owner/repo/pulls/1/reviews/123")
        assert GITHUB_DELETE_REVIEW_PATTERN.match("/repos/o/r/pulls/99/reviews/42")
        assert not GITHUB_DELETE_REVIEW_PATTERN.match("/repos/owner/repo/pulls/1/reviews")
        assert not GITHUB_DELETE_REVIEW_PATTERN.match("/repos/owner/repo/issues/1/reviews/123")


class TestLayerIsolation:
    """Verify that blocking in one layer doesn't prevent testing the other."""

    @pytest.fixture
    def api_filter(self):
        return GitHubAPIFilter()

    @pytest.fixture
    def policy_engine(self):
        engine = PolicyEngine()
        engine._domains = ["api.github.com"]
        return engine

    @patch.object(github_api_filter, "ctx")
    def test_api_filter_blocks_independently(self, mock_ctx, api_filter):
        """GitHubAPIFilter blocks requests even if PolicyEngine is not in chain."""
        mock_ctx.log = Mock()
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "PUT"
        flow.request.path = "/repos/owner/repo/pulls/1/merge"
        flow.request.get_text = Mock(return_value="")
        flow.response = None

        api_filter.request(flow)
        assert flow.response is not None

    def test_policy_engine_blocks_independently(self, policy_engine):
        """PolicyEngine blocks requests independently of GitHubAPIFilter."""
        result = policy_engine._check_github_blocklist(
            "PUT", "/repos/owner/repo/pulls/1/merge"
        )
        assert result is not None


class TestDefenseInDepth:
    """Verify defense-in-depth: operations blocked at multiple levels."""

    @pytest.fixture
    def api_filter(self):
        return GitHubAPIFilter()

    @pytest.fixture
    def policy_engine(self):
        engine = PolicyEngine()
        engine._domains = ["api.github.com"]
        return engine

    @patch.object(github_api_filter, "ctx")
    def test_merge_pr_blocked_at_both_levels(self, mock_ctx, api_filter, policy_engine):
        """PR merge is blocked at both filter (pattern) and policy (pattern) levels."""
        mock_ctx.log = Mock()
        method = "PUT"
        path = "/repos/owner/repo/pulls/1/merge"

        # Level 1: GitHubAPIFilter
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = method
        flow.request.path = path
        flow.request.get_text = Mock(return_value="")
        flow.response = None

        api_filter.request(flow)
        assert flow.response is not None, "Level 1 (GitHubAPIFilter) blocks PR merge"

        # Level 2: PolicyEngine
        policy_block = policy_engine._check_github_blocklist(method, path)
        assert policy_block is not None, "Level 2 (PolicyEngine) blocks PR merge"

    @patch.object(github_api_filter, "ctx")
    def test_auto_merge_blocked_at_both_levels(self, mock_ctx, api_filter, policy_engine):
        """Auto-merge is blocked at both filter (pattern) and policy (pattern) levels."""
        mock_ctx.log = Mock()

        # Level 1: GitHubAPIFilter (PUT)
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "PUT"
        flow.request.path = "/repos/owner/repo/pulls/1/auto-merge"
        flow.request.get_text = Mock(return_value="")
        flow.response = None

        api_filter.request(flow)
        assert flow.response is not None, "Level 1 blocks auto-merge PUT"

        # Level 2: PolicyEngine (PUT)
        policy_block = policy_engine._check_github_blocklist(
            "PUT", "/repos/owner/repo/pulls/1/auto-merge"
        )
        assert policy_block is not None, "Level 2 blocks auto-merge PUT"

        # Level 1: GitHubAPIFilter (DELETE)
        flow2 = Mock()
        flow2.request = Mock()
        flow2.request.host = "api.github.com"
        flow2.request.method = "DELETE"
        flow2.request.path = "/repos/owner/repo/pulls/1/auto-merge"
        flow2.request.get_text = Mock(return_value="")
        flow2.response = None

        api_filter.request(flow2)
        assert flow2.response is not None, "Level 1 blocks auto-merge DELETE"

        # Level 2: PolicyEngine (DELETE)
        policy_block = policy_engine._check_github_blocklist(
            "DELETE", "/repos/owner/repo/pulls/1/auto-merge"
        )
        assert policy_block is not None, "Level 2 blocks auto-merge DELETE"

    @patch.object(github_api_filter, "ctx")
    def test_review_deletion_blocked_at_both_levels(self, mock_ctx, api_filter, policy_engine):
        """Review deletion is blocked at both filter (pattern) and policy (pattern) levels."""
        mock_ctx.log = Mock()
        method = "DELETE"
        path = "/repos/owner/repo/pulls/1/reviews/123"

        # Level 1: GitHubAPIFilter
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = method
        flow.request.path = path
        flow.request.get_text = Mock(return_value="")
        flow.response = None

        api_filter.request(flow)
        assert flow.response is not None, "Level 1 blocks review deletion"

        # Level 2: PolicyEngine
        policy_block = policy_engine._check_github_blocklist(method, path)
        assert policy_block is not None, "Level 2 blocks review deletion"
