"""Unit tests for GitHub API filter addon — coverage gaps.

Supplements the existing tests/unit/test_github_api_filter.py with tests
for blocked operations, conditional PR operations, default-deny behavior,
and allowlist completeness.

Module under test: unified-proxy/github-api-filter.py
"""

import importlib
import json
from unittest.mock import Mock, patch

import pytest

# Import module with hyphenated name using importlib
github_api_filter = importlib.import_module("github-api-filter")
GitHubAPIFilter = github_api_filter.GitHubAPIFilter


def _make_flow(method, path, body=None):
    """Create a mock flow object for testing."""
    flow = Mock()
    flow.request = Mock()
    flow.request.host = "api.github.com"
    flow.request.method = method
    flow.request.path = path
    flow.response = None
    if body is not None:
        flow.request.get_text = Mock(return_value=json.dumps(body))
    return flow


class TestBlockedOperations:
    """Tests for explicitly blocked operations."""

    @pytest.fixture
    def api_filter(self):
        return GitHubAPIFilter()

    def test_delete_repo_blocked(self, api_filter):
        """Test DELETE /repos/owner/repo (repo deletion) is blocked."""
        flow = _make_flow("DELETE", "/repos/owner/repo")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_delete_release_blocked(self, api_filter):
        """Test DELETE /repos/owner/repo/releases/123 is blocked."""
        flow = _make_flow("DELETE", "/repos/owner/repo/releases/123")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_get_secrets_blocked(self, api_filter):
        """Test GET /repos/owner/repo/actions/secrets is blocked."""
        flow = _make_flow("GET", "/repos/owner/repo/actions/secrets")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_put_secrets_blocked(self, api_filter):
        """Test PUT /repos/owner/repo/actions/secrets/MY_SECRET is blocked."""
        flow = _make_flow("PUT", "/repos/owner/repo/actions/secrets/MY_SECRET")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_delete_secrets_blocked(self, api_filter):
        """Test DELETE /repos/owner/repo/actions/secrets/MY_SECRET is blocked."""
        flow = _make_flow("DELETE", "/repos/owner/repo/actions/secrets/MY_SECRET")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_post_variables_blocked(self, api_filter):
        """Test POST /repos/owner/repo/actions/variables is blocked."""
        flow = _make_flow("POST", "/repos/owner/repo/actions/variables")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_delete_branch_protection_blocked(self, api_filter):
        """Test DELETE /repos/owner/repo/branches/main/protection is blocked."""
        flow = _make_flow("DELETE", "/repos/owner/repo/branches/main/protection")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_put_branch_protection_blocked(self, api_filter):
        """Test PUT /repos/owner/repo/branches/main/protection is blocked."""
        flow = _make_flow("PUT", "/repos/owner/repo/branches/main/protection")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_post_git_refs_blocked(self, api_filter):
        """Test POST /repos/owner/repo/git/refs is blocked."""
        flow = _make_flow("POST", "/repos/owner/repo/git/refs")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_post_merges_blocked(self, api_filter):
        """Test POST /repos/owner/repo/merges is blocked."""
        flow = _make_flow("POST", "/repos/owner/repo/merges")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403


class TestConditionalPROperations:
    """Tests for PR operations controlled by ALLOW_PR_OPERATIONS."""

    @pytest.fixture
    def api_filter(self):
        return GitHubAPIFilter()

    def test_post_pulls_blocked_by_default(self, api_filter):
        """Test POST /repos/owner/repo/pulls is blocked when PR ops disabled."""
        with patch.object(github_api_filter, "ALLOW_PR_OPERATIONS", False):
            flow = _make_flow("POST", "/repos/owner/repo/pulls")
            api_filter.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 403

    @patch.object(github_api_filter, "logger")
    def test_post_pulls_allowed_with_flag(self, mock_logger, api_filter):
        """Test POST /repos/owner/repo/pulls is allowed when PR ops enabled."""
        with patch.object(github_api_filter, "ALLOW_PR_OPERATIONS", True):
            flow = _make_flow("POST", "/repos/owner/repo/pulls")
            api_filter.request(flow)
            assert flow.response is None

    def test_pr_comments_blocked_by_default(self, api_filter):
        """Test POST /repos/owner/repo/pulls/1/comments is blocked by default."""
        with patch.object(github_api_filter, "ALLOW_PR_OPERATIONS", False):
            flow = _make_flow("POST", "/repos/owner/repo/pulls/1/comments")
            api_filter.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 403

    def test_pr_reviews_blocked_by_default(self, api_filter):
        """Test POST /repos/owner/repo/pulls/1/reviews is blocked by default."""
        with patch.object(github_api_filter, "ALLOW_PR_OPERATIONS", False):
            flow = _make_flow("POST", "/repos/owner/repo/pulls/1/reviews")
            api_filter.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 403

    def test_patch_pulls_blocked_by_default(self, api_filter):
        """Test PATCH /repos/owner/repo/pulls/1 is blocked by default."""
        with patch.object(github_api_filter, "ALLOW_PR_OPERATIONS", False):
            flow = _make_flow("PATCH", "/repos/owner/repo/pulls/1")
            # Need get_text for reopen check
            flow.request.get_text = Mock(return_value=json.dumps({"title": "new title"}))
            api_filter.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 403

    @patch.object(github_api_filter, "logger")
    def test_patch_pulls_allowed_with_flag(self, mock_logger, api_filter):
        """Test PATCH /repos/owner/repo/pulls/1 is allowed when PR ops enabled."""
        with patch.object(github_api_filter, "ALLOW_PR_OPERATIONS", True):
            flow = _make_flow("PATCH", "/repos/owner/repo/pulls/1")
            flow.request.get_text = Mock(return_value=json.dumps({"title": "new title"}))
            api_filter.request(flow)
            assert flow.response is None

    def test_graphql_create_pr_blocked_by_default(self, api_filter):
        """Test createPullRequest GraphQL mutation is blocked when PR ops disabled."""
        with patch.object(github_api_filter, "ALLOW_PR_OPERATIONS", False):
            flow = Mock()
            flow.request = Mock()
            flow.request.host = "api.github.com"
            flow.request.method = "POST"
            flow.request.path = "/graphql"
            flow.request.get_text = Mock(return_value=json.dumps({
                "query": "mutation { createPullRequest(input: {}) { pullRequest { id } } }"
            }))
            flow.response = None
            api_filter.request(flow)
            assert flow.response is not None
            assert flow.response.status_code == 403

    @patch.object(github_api_filter, "logger")
    def test_graphql_create_pr_allowed_with_flag(self, mock_logger, api_filter):
        """Test createPullRequest GraphQL mutation is allowed when PR ops enabled."""
        with patch.object(github_api_filter, "ALLOW_PR_OPERATIONS", True):
            flow = Mock()
            flow.request = Mock()
            flow.request.host = "api.github.com"
            flow.request.method = "POST"
            flow.request.path = "/graphql"
            flow.request.get_text = Mock(return_value=json.dumps({
                "query": "mutation { createPullRequest(input: {}) { pullRequest { id } } }"
            }))
            flow.response = None
            api_filter.request(flow)
            assert flow.response is None


class TestDefaultDenyBehavior:
    """Tests for default-deny of requests not in allowlist or blocklist."""

    @pytest.fixture
    def api_filter(self):
        return GitHubAPIFilter()

    def test_unknown_endpoint_blocked(self, api_filter):
        """Test unknown endpoint returns 403."""
        flow = _make_flow("GET", "/unknown/endpoint/here")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_post_to_unknown_path_blocked(self, api_filter):
        """Test POST to unknown path is blocked."""
        flow = _make_flow("POST", "/some/random/path")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_response_body_contains_error_blocked(self, api_filter):
        """Test blocked response body contains error: BLOCKED."""
        flow = _make_flow("DELETE", "/repos/owner/repo")
        api_filter.request(flow)
        assert flow.response is not None
        # The response is created by http.Response.make with JSON body
        # Verify through the mock call args
        body = json.loads(flow.response.content)
        assert body["error"] == "BLOCKED"

    def test_response_has_sandbox_blocked_header(self, api_filter):
        """Test blocked response has X-Sandbox-Blocked header."""
        flow = _make_flow("DELETE", "/repos/owner/repo")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.headers["X-Sandbox-Blocked"] == "true"


class TestAllowlistCompleteness:
    """Spot-check key allowlist entries."""

    @pytest.fixture
    def api_filter(self):
        return GitHubAPIFilter()

    @patch.object(github_api_filter, "logger")
    def test_post_issues_allowed(self, mock_logger, api_filter):
        """Test POST /repos/owner/repo/issues is allowed."""
        flow = _make_flow("POST", "/repos/owner/repo/issues")
        api_filter.request(flow)
        assert flow.response is None

    @patch.object(github_api_filter, "logger")
    def test_post_releases_allowed(self, mock_logger, api_filter):
        """Test POST /repos/owner/repo/releases is allowed."""
        flow = _make_flow("POST", "/repos/owner/repo/releases")
        api_filter.request(flow)
        assert flow.response is None

    @patch.object(github_api_filter, "logger")
    def test_post_check_runs_allowed(self, mock_logger, api_filter):
        """Test POST /repos/owner/repo/check-runs is allowed."""
        flow = _make_flow("POST", "/repos/owner/repo/check-runs")
        api_filter.request(flow)
        assert flow.response is None

    @patch.object(github_api_filter, "logger")
    def test_get_rate_limit_allowed(self, mock_logger, api_filter):
        """Test GET /rate_limit is allowed."""
        flow = _make_flow("GET", "/rate_limit")
        api_filter.request(flow)
        assert flow.response is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
