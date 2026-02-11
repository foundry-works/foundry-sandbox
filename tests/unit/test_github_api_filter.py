"""Unit tests for GitHub API filter addon (github-api-filter.py).

Tests the GitHubAPIFilter class for blocking:
- REST merge, auto-merge, and review deletion operations
- GraphQL mutation blocking for self-merge prevention
"""

import importlib
import json
from unittest.mock import Mock, patch

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

    def test_graphql_malformed_json_blocked(self, api_filter):
        """Test that malformed GraphQL requests (bad JSON) are blocked (fail closed).

        The filter blocks unparseable JSON bodies to prevent parser-differential
        attacks where a crafted body might parse differently in Python vs. GitHub.
        """
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "POST"
        flow.request.path = "/graphql"
        flow.request.get_text = Mock(return_value="not valid json")
        flow.response = None

        api_filter.request(flow)

        # Should be blocked (fail closed on unparseable body)
        assert flow.response is not None
        assert flow.response.status_code == 403

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


class TestGraphQLCommentBypass:
    """Tests for GraphQL comment stripping before mutation detection."""

    @pytest.fixture
    def api_filter(self):
        """Create GitHubAPIFilter instance."""
        return GitHubAPIFilter()

    def test_comment_between_mutation_and_paren(self, api_filter):
        """Test that a GraphQL comment between mutation name and ( is blocked.

        A payload like `mergePullRequest # comment\n(` previously bypassed
        the `\\s*\\(` regex because the comment text intervened.
        """
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "POST"
        flow.request.path = "/graphql"
        flow.request.get_text = Mock(return_value=json.dumps({
            "query": "mutation { mergePullRequest # comment\n(input: {pullRequestId: \"PR_123\"}) { pullRequest { id } } }"
        }))
        flow.response = None

        api_filter.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_multiple_comments_in_query(self, api_filter):
        """Test that multiple comments don't prevent mutation detection."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "POST"
        flow.request.path = "/graphql"
        flow.request.get_text = Mock(return_value=json.dumps({
            "query": "# start comment\nmutation { # another comment\nenablePullRequestAutoMerge # bypass\n(input: {pullRequestId: \"PR_123\"}) { pullRequest { id } } }"
        }))
        flow.response = None

        api_filter.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    @patch.object(github_api_filter, "ctx")
    def test_comment_in_safe_query_still_allowed(self, mock_ctx, api_filter):
        """Test that comments in safe queries don't cause false positives."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "POST"
        flow.request.path = "/graphql"
        flow.request.get_text = Mock(return_value=json.dumps({
            "query": "# just a query\nquery { repository(owner: \"owner\", name: \"repo\") { name } }"
        }))
        flow.response = None

        api_filter.request(flow)

        assert flow.response is None


class TestPRReopenCaseInsensitive:
    """Tests for case-insensitive PR reopen detection."""

    @pytest.fixture
    def api_filter(self):
        """Create GitHubAPIFilter instance."""
        return GitHubAPIFilter()

    def _make_pr_patch_flow(self, state_value):
        """Create a mock flow for PATCH to a PR endpoint with given state."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "PATCH"
        flow.request.path = "/repos/owner/repo/pulls/123"
        flow.request.get_text = Mock(return_value=json.dumps({"state": state_value}))
        flow.response = None
        return flow

    def test_reopen_lowercase(self, api_filter):
        """Test that state: 'open' (lowercase) is detected as reopen."""
        flow = self._make_pr_patch_flow("open")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_reopen_uppercase(self, api_filter):
        """Test that state: 'OPEN' (uppercase) is detected as reopen."""
        flow = self._make_pr_patch_flow("OPEN")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_reopen_mixed_case(self, api_filter):
        """Test that state: 'Open' (mixed case) is detected as reopen."""
        flow = self._make_pr_patch_flow("Open")
        api_filter.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403


class TestHTTPMethodNormalization:
    """Tests for HTTP method normalization to uppercase."""

    @pytest.fixture
    def api_filter(self):
        """Create GitHubAPIFilter instance."""
        return GitHubAPIFilter()

    def test_lowercase_put_merge_blocked(self, api_filter):
        """Test that lowercase 'put' method for merge is still blocked."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "put"  # lowercase
        flow.request.path = "/repos/owner/repo/pulls/123/merge"
        flow.response = None

        api_filter.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_lowercase_delete_ref_blocked(self, api_filter):
        """Test that lowercase 'delete' method for ref deletion is still blocked."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "delete"  # lowercase
        flow.request.path = "/repos/owner/repo/git/refs/heads/main"
        flow.response = None

        api_filter.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    @patch.object(github_api_filter, "ctx")
    def test_lowercase_get_allowed(self, mock_ctx, api_filter):
        """Test that lowercase 'get' method for safe endpoint is allowed."""
        flow = Mock()
        flow.request = Mock()
        flow.request.host = "api.github.com"
        flow.request.method = "get"  # lowercase
        flow.request.path = "/repos/owner/repo/pulls/123"
        flow.response = None

        api_filter.request(flow)

        assert flow.response is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
