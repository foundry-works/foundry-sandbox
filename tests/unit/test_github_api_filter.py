"""Unit tests for GitHub API filter addon (github-api-filter.py).

Tests the GitHubAPIFilter class for blocking:
- REST merge, auto-merge, and review deletion operations
- GraphQL mutation blocking for self-merge prevention
"""

import importlib
import json
from unittest.mock import Mock, patch, MagicMock

import pytest

# Import module with hyphenated name using importlib
github_api_filter = importlib.import_module("github-api-filter")
GitHubAPIFilter = github_api_filter.GitHubAPIFilter


class TestSelfMergePreventionREST:
    """REST API blocking tests for self-merge prevention."""

    @pytest.fixture
    def api_filter(self):
        """Create GitHubAPIFilter instance."""
        return GitHubAPIFilter()

    def _make_flow(self, method, path):
        """Create a mock flow object for testing.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            path: Request path (e.g., /repos/owner/repo/pulls/123/merge)

        Returns:
            Mock flow object configured for API filtering
        """
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = method
        flow.request.path = path
        flow.response = None
        return flow

    def test_blocked_merge_rest(self, api_filter):
        """Test that PUT /repos/owner/repo/pulls/123/merge is blocked (regression).

        The merge endpoint is explicitly blocked in BLOCKED_PATTERNS to prevent
        PR merges that modify branch state and create merge commits.
        """
        # Create flow for merge request
        flow = self._make_flow("PUT", "/repos/owner/repo/pulls/123/merge")

        # Execute: filter the request
        api_filter.request(flow)

        # Verify: request is blocked (flow.response is set)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_blocked_auto_merge_rest(self, api_filter):
        """Test that PUT /repos/owner/repo/pulls/1/auto-merge is blocked.

        The auto-merge endpoint is explicitly blocked to prevent automatic merges
        that would require human approval.
        """
        # Create flow for auto-merge enable request
        flow = self._make_flow("PUT", "/repos/owner/repo/pulls/1/auto-merge")

        # Execute: filter the request
        api_filter.request(flow)

        # Verify: request is blocked
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_blocked_delete_auto_merge_rest(self, api_filter):
        """Test that DELETE /repos/owner/repo/pulls/1/auto-merge is blocked.

        The auto-merge disable endpoint is blocked as a precaution, treating
        all auto-merge operations as requiring human approval.
        """
        # Create flow for auto-merge disable request
        flow = self._make_flow("DELETE", "/repos/owner/repo/pulls/1/auto-merge")

        # Execute: filter the request
        api_filter.request(flow)

        # Verify: request is blocked
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_blocked_delete_review_rest(self, api_filter):
        """Test that DELETE /repos/owner/repo/pulls/1/reviews/123 is blocked.

        Review deletion is blocked because it removes important approval records
        and requires human intervention.
        """
        # Create flow for review deletion request
        flow = self._make_flow("DELETE", "/repos/owner/repo/pulls/1/reviews/123")

        # Execute: filter the request
        api_filter.request(flow)

        # Verify: request is blocked
        assert flow.response is not None
        assert flow.response.status_code == 403


class TestSelfMergePreventionGraphQL:
    """GraphQL mutation blocking tests for self-merge prevention."""

    @pytest.fixture
    def api_filter(self):
        """Create GitHubAPIFilter instance."""
        return GitHubAPIFilter()

    def _make_graphql_flow(self, mutation_name, mutation_args="pullRequestId: \"PR_123\""):
        """Create a mock flow object for GraphQL mutation testing.

        Args:
            mutation_name: GraphQL mutation name (e.g., "mergePullRequest")
            mutation_args: Arguments to pass to the mutation

        Returns:
            Mock flow object configured for GraphQL API filtering
        """
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "POST"
        flow.request.path = "/graphql"
        flow.request.get_text = Mock(return_value=json.dumps({
            "query": f"mutation {{ {mutation_name}(input: {{{mutation_args}}}) {{ pullRequest {{ id }} }} }}"
        }))
        flow.response = None
        return flow

    def test_blocked_merge_graphql(self, api_filter):
        """Test that mergePullRequest mutation is blocked (regression).

        The mergePullRequest mutation is in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS
        to prevent PR merges via GraphQL.
        """
        # Create flow for mergePullRequest mutation
        flow = self._make_graphql_flow("mergePullRequest")

        # Execute: filter the request
        api_filter.request(flow)

        # Verify: request is blocked
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_blocked_auto_merge_graphql(self, api_filter):
        """Test that enablePullRequestAutoMerge mutation is blocked.

        The enablePullRequestAutoMerge mutation is in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS
        to prevent automatic PR merges.
        """
        # Create flow for enablePullRequestAutoMerge mutation
        flow = self._make_graphql_flow("enablePullRequestAutoMerge")

        # Execute: filter the request
        api_filter.request(flow)

        # Verify: request is blocked
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_blocked_disable_auto_merge_graphql(self, api_filter):
        """Test that disablePullRequestAutoMerge mutation is blocked.

        The disablePullRequestAutoMerge mutation is in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS
        as a conservative measure for all auto-merge operations.
        """
        # Create flow for disablePullRequestAutoMerge mutation
        flow = self._make_graphql_flow("disablePullRequestAutoMerge")

        # Execute: filter the request
        api_filter.request(flow)

        # Verify: request is blocked
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_blocked_add_review_graphql(self, api_filter):
        """Test that addPullRequestReview mutation is blocked (all events).

        The addPullRequestReview mutation is in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS
        because the regex-based parser cannot inspect GraphQL arguments to
        distinguish between APPROVE and other review events. REST reviews are
        NOT blocked (body inspection in policy_engine.py handles APPROVE blocking).
        This GraphQL blocking is a conservative approach due to AST parsing limitations.
        """
        # Create flow for addPullRequestReview mutation
        flow = self._make_graphql_flow("addPullRequestReview")

        # Execute: filter the request
        api_filter.request(flow)

        # Verify: request is blocked
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_blocked_dismiss_review_graphql(self, api_filter):
        """Test that dismissPullRequestReview mutation is blocked.

        The dismissPullRequestReview mutation is in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS
        to prevent removal of important review records.
        """
        # Create flow for dismissPullRequestReview mutation
        flow = self._make_graphql_flow("dismissPullRequestReview")

        # Execute: filter the request
        api_filter.request(flow)

        # Verify: request is blocked
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_blocked_update_branch_graphql(self, api_filter):
        """Test that updatePullRequestBranch mutation is blocked.

        The updatePullRequestBranch mutation is in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS
        because it performs a server-side merge operation that modifies branch state.
        """
        # Create flow for updatePullRequestBranch mutation
        flow = self._make_graphql_flow("updatePullRequestBranch")

        # Execute: filter the request
        api_filter.request(flow)

        # Verify: request is blocked
        assert flow.response is not None
        assert flow.response.status_code == 403


class TestNonBlockedRequests:
    """Tests for requests that should NOT be blocked."""

    @pytest.fixture
    def api_filter(self):
        """Create GitHubAPIFilter instance."""
        return GitHubAPIFilter()

    def _make_flow(self, method, path):
        """Create a mock flow object for testing."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = method
        flow.request.path = path
        flow.response = None
        return flow

    @patch.object(github_api_filter, "ctx")
    def test_allowed_get_pr(self, mock_ctx, api_filter):
        """Test that GET /repos/owner/repo/pulls/123 is allowed."""
        flow = self._make_flow("GET", "/repos/owner/repo/pulls/123")

        api_filter.request(flow)

        # Should not be blocked (response is None)
        assert flow.response is None
        assert mock_ctx.log.info.called

    @patch.object(github_api_filter, "ctx")
    def test_allowed_get_user(self, mock_ctx, api_filter):
        """Test that GET /user is allowed."""
        flow = self._make_flow("GET", "/user")

        api_filter.request(flow)

        # Should not be blocked
        assert flow.response is None
        assert mock_ctx.log.info.called

    @patch.object(github_api_filter, "ctx")
    def test_allowed_graphql_query(self, mock_ctx, api_filter):
        """Test that GraphQL query (not mutation) is allowed."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "POST"
        flow.request.path = "/graphql"
        flow.request.get_text = Mock(return_value=json.dumps({
            "query": "query { repository(owner: \"owner\", name: \"repo\") { name } }"
        }))
        flow.response = None

        api_filter.request(flow)

        # Should not be blocked (queries are allowed, only mutations)
        assert flow.response is None
        assert mock_ctx.log.info.called

    @patch.object(github_api_filter, "ctx")
    def test_non_github_request_not_filtered(self, mock_ctx, api_filter):
        """Test that non-GitHub requests pass through unfiltered."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "example.com"  # Not a GitHub host
        flow.request.method = "DELETE"
        flow.request.path = "/admin/something"
        flow.response = None

        api_filter.request(flow)

        # Should not be filtered (not a GitHub host)
        assert flow.response is None
        # No logging should occur for non-GitHub requests
        assert not mock_ctx.log.warn.called
        assert not mock_ctx.log.info.called


class TestEdgeCases:
    """Tests for edge cases and variations."""

    @pytest.fixture
    def api_filter(self):
        """Create GitHubAPIFilter instance."""
        return GitHubAPIFilter()

    def _make_flow(self, method, path):
        """Create a mock flow object for testing."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = method
        flow.request.path = path
        flow.response = None
        return flow

    def test_merge_with_query_string(self, api_filter):
        """Test that merge is blocked even with query string parameters."""
        # Request with query parameters should still be blocked
        flow = self._make_flow("PUT", "/repos/owner/repo/pulls/123/merge?commit_title=Test")

        api_filter.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_graphql_mutation_case_insensitive(self, api_filter):
        """Test that GraphQL mutation detection is case-insensitive."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "POST"
        flow.request.path = "/graphql"
        # Use mixed case in mutation name
        flow.request.get_text = Mock(return_value=json.dumps({
            "query": "mutation { MergePullRequest(input: {pullRequestId: \"PR_123\"}) { pullRequest { id } } }"
        }))
        flow.response = None

        api_filter.request(flow)

        # Should be blocked despite case difference
        assert flow.response is not None
        assert flow.response.status_code == 403

    @patch.object(github_api_filter, "ctx")
    def test_graphql_malformed_json_allowed(self, mock_ctx, api_filter):
        """Test that malformed GraphQL requests (bad JSON) are allowed to pass.

        The filter tries to parse JSON but returns None if parsing fails,
        allowing the request to proceed (the API will reject it).
        """
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "POST"
        flow.request.path = "/graphql"
        flow.request.get_text = Mock(return_value="not valid json")
        flow.response = None

        api_filter.request(flow)

        # Should not be blocked by the filter
        # (malformed JSON won't match any mutation pattern)
        # The flow should either pass through or be rejected by another layer
        # Since _check_graphql_mutations returns None on JSON error,
        # request will continue through other checks

    @patch.object(github_api_filter, "ctx")
    def test_uploads_github_com_host(self, mock_ctx, api_filter):
        """Test that uploads.github.com is also filtered.

        uploads.github.com is in GITHUB_API_HOSTS for release asset uploads.
        """
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "uploads.github.com"
        flow.request.method = "GET"
        flow.request.path = "/repos/owner/repo/releases/assets/123"
        flow.response = None

        api_filter.request(flow)

        # Should be allowed (GET on release assets is permitted)
        assert flow.response is None
        assert mock_ctx.log.info.called


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
