"""Integration tests for the GitHub API security filter (GitHubAPIChecker).

Tests the public interface of GitHubAPIChecker.check_request() with realistic
method/path/body combinations covering allowlisting, blocklisting, PR operations,
and GraphQL mutation filtering.
"""

import json

import pytest

from foundry_git_safety.github_filter import GitHubAPIChecker


# ---------------------------------------------------------------------------
# TestGitHubProxyIntegration
# ---------------------------------------------------------------------------


class TestGitHubProxyIntegration:
    """Tests for GitHubAPIChecker.check_request() allow/block decisions."""

    def test_allowed_get_repo_returns_true(self):
        """GET /repos/owner/repo is allowed."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("GET", "/repos/owner/repo")
        assert allowed is True
        assert reason is None

    def test_allowed_get_issues_returns_true(self):
        """GET /repos/owner/repo/issues is allowed."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "GET", "/repos/owner/repo/issues?state=open"
        )
        assert allowed is True
        assert reason is None

    def test_blocked_delete_repo_returns_false(self):
        """DELETE /repos/owner/repo is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("DELETE", "/repos/owner/repo")
        assert allowed is False
        assert reason is not None
        assert "delete" in reason.lower() or "destroy" in reason.lower()

    def test_blocked_delete_release_returns_false(self):
        """DELETE /repos/owner/repo/releases/123 is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "DELETE", "/repos/owner/repo/releases/123"
        )
        assert allowed is False
        assert "release" in reason.lower()

    def test_blocked_delete_ref_returns_false(self):
        """DELETE /repos/owner/repo/git/refs/heads/feature is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "DELETE", "/repos/owner/repo/git/refs/heads/feature"
        )
        assert allowed is False
        assert "branch" in reason.lower() or "tag" in reason.lower()

    def test_graphql_mutation_blocked(self):
        """A blocked GraphQL mutation (mergePullRequest) is rejected."""
        checker = GitHubAPIChecker()
        body = json.dumps({
            "query": "mutation { mergePullRequest(input: { pullRequestId: \"abc\" }) { clientMutationId } }"
        }).encode("utf-8")
        allowed, reason = checker.check_request("POST", "/graphql", body=body)
        assert allowed is False
        assert "mergePullRequest" in reason

    def test_graphql_query_allowed(self):
        """A read-only GraphQL query is allowed."""
        checker = GitHubAPIChecker()
        body = json.dumps({
            "query": "{ viewer { login } }"
        }).encode("utf-8")
        allowed, reason = checker.check_request("POST", "/graphql", body=body)
        assert allowed is True
        assert reason is None

    def test_pr_operations_blocked_by_default(self):
        """POST /repos/owner/repo/pulls (create PR) is blocked by default."""
        checker = GitHubAPIChecker(allow_pr_operations=False)
        body = json.dumps({"title": "test", "head": "feature", "base": "main"}).encode("utf-8")
        allowed, reason = checker.check_request(
            "POST", "/repos/owner/repo/pulls", body=body
        )
        assert allowed is False
        assert "PR operations" in reason

    def test_pr_operations_allowed_when_enabled(self):
        """POST /repos/owner/repo/pulls (create PR) is allowed with flag."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        body = json.dumps({"title": "test", "head": "feature", "base": "main"}).encode("utf-8")
        allowed, reason = checker.check_request(
            "POST", "/repos/owner/repo/pulls", body=body
        )
        assert allowed is True
        assert reason is None

    def test_actions_secrets_blocked(self):
        """GET /repos/owner/repo/actions/secrets is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "GET", "/repos/owner/repo/actions/secrets"
        )
        assert allowed is False
        assert "secret" in reason.lower()

    def test_get_user_allowed(self):
        """GET /user is allowed."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("GET", "/user")
        assert allowed is True
        assert reason is None

    def test_get_rate_limit_allowed(self):
        """GET /rate_limit is allowed."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("GET", "/rate_limit")
        assert allowed is True
        assert reason is None

    def test_pr_merge_blocked(self):
        """PUT /repos/owner/repo/pulls/1/merge is always blocked."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        allowed, reason = checker.check_request(
            "PUT", "/repos/owner/repo/pulls/1/merge"
        )
        assert allowed is False
        assert "merge" in reason.lower()

    def test_conditional_graphql_mutation_blocked_without_pr(self):
        """Conditional GraphQL mutations like createPullRequest are blocked
        when allow_pr_operations is False."""
        checker = GitHubAPIChecker(allow_pr_operations=False)
        body = json.dumps({
            "query": "mutation { createPullRequest(input: { repositoryId: \"abc\", headRefName: \"feat\", baseRefName: \"main\" }) { pullRequest { number } } }"
        }).encode("utf-8")
        allowed, reason = checker.check_request("POST", "/graphql", body=body)
        assert allowed is False
        assert "createPullRequest" in reason

    def test_conditional_graphql_mutation_allowed_with_pr(self):
        """Conditional GraphQL mutations are allowed when allow_pr_operations is True."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        body = json.dumps({
            "query": "mutation { createPullRequest(input: { repositoryId: \"abc\", headRefName: \"feat\", baseRefName: \"main\" }) { pullRequest { number } } }"
        }).encode("utf-8")
        allowed, reason = checker.check_request("POST", "/graphql", body=body)
        assert allowed is True
        assert reason is None


# ---------------------------------------------------------------------------
# TestProxyForwarding
# ---------------------------------------------------------------------------


class TestProxyForwarding:
    """Tests for non-standard paths and unknown hosts."""

    def test_unknown_path_is_blocked(self):
        """An unmatched method+path is blocked by default."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("DELETE", "/unknown/path")
        assert allowed is False
        assert reason is not None

    def test_patch_pr_reopen_blocked(self):
        """PATCH that sets state=open without other mutable fields is blocked."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        # Bare reopen payload — only state, no other mutable fields
        body = json.dumps({"state": "open"}).encode("utf-8")
        allowed, reason = checker.check_request(
            "PATCH", "/repos/owner/repo/pulls/42", body=body
        )
        assert allowed is False
        assert "reopen" in reason.lower()

    def test_patch_pr_reopen_with_state_reason_blocked(self):
        """PATCH with explicit state_reason=reopened is blocked."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        body = json.dumps({"state": "open", "state_reason": "reopened"}).encode("utf-8")
        allowed, reason = checker.check_request(
            "PATCH", "/repos/owner/repo/pulls/42", body=body
        )
        assert allowed is False
        assert "reopen" in reason.lower()

    def test_patch_pr_metadata_with_state_allowed(self):
        """PATCH with state=open AND other mutable fields is allowed."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        body = json.dumps({"state": "open", "title": "Update title"}).encode("utf-8")
        allowed, reason = checker.check_request(
            "PATCH", "/repos/owner/repo/pulls/42", body=body
        )
        assert allowed is True

    def test_branch_protection_put_blocked(self):
        """PUT to branch protection is always blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "PUT", "/repos/owner/repo/branches/main/protection"
        )
        assert allowed is False
        assert "branch protection" in reason.lower()

    def test_org_secrets_blocked(self):
        """GET /orgs/myorg/actions/secrets is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "GET", "/orgs/myorg/actions/secrets"
        )
        assert allowed is False
        assert "secret" in reason.lower()

    def test_post_gist_allowed(self):
        """POST /gists is allowed."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("POST", "/gists")
        assert allowed is True
        assert reason is None

    def test_get_search_allowed(self):
        """GET /search/repositories?q=test is allowed."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "GET", "/search/repositories?q=test"
        )
        assert allowed is True
        assert reason is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
