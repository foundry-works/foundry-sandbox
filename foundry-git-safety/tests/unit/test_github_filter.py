"""Tests for foundry_git_safety.github_filter — GitHub API security filter."""

import json

import pytest

from foundry_git_safety.github_filter import (
    ALLOWED_OPERATIONS,
    ALWAYS_BLOCKED_GRAPHQL_MUTATIONS,
    BLOCKED_PATTERNS,
    CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS,
    CONDITIONAL_PR_OPERATIONS,
    GitHubAPIChecker,
)


# ---------------------------------------------------------------------------
# TestGitHubAPIChecker
# ---------------------------------------------------------------------------


class TestGitHubAPIChecker:
    """Tests for GitHubAPIChecker.check_request() allow/block logic."""

    # -- Constructor ----------------------------------------------------------

    def test_default_allow_pr_operations_is_false(self):
        """Without explicit flag, PR operations default to blocked."""
        checker = GitHubAPIChecker()
        assert checker.allow_pr_operations is False

    def test_constructor_sets_allow_pr_operations(self):
        """Constructor argument is stored."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        assert checker.allow_pr_operations is True

    # -- Allowed operations ---------------------------------------------------

    def test_allowed_get_repos_endpoint(self):
        """GET /repos/owner/repo is allowed."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("GET", "/repos/owner/repo")
        assert allowed is True
        assert reason is None

    def test_allowed_get_repo_issues(self):
        """GET /repos/owner/repo/issues is allowed."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("GET", "/repos/owner/repo/issues")
        assert allowed is True
        assert reason is None

    def test_allowed_get_repo_pulls(self):
        """GET /repos/owner/repo/pulls is allowed."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("GET", "/repos/owner/repo/pulls")
        assert allowed is True
        assert reason is None

    def test_allowed_post_graphql(self):
        """POST /graphql with a safe query is allowed."""
        checker = GitHubAPIChecker()
        body = json.dumps({"query": "{ viewer { login } }"}).encode()
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert allowed is True
        assert reason is None

    def test_allowed_get_user(self):
        """GET /user is allowed."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("GET", "/user")
        assert allowed is True
        assert reason is None

    def test_allowed_get_rate_limit(self):
        """GET /rate_limit is allowed."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("GET", "/rate_limit")
        assert allowed is True
        assert reason is None

    # -- Blocked operations ---------------------------------------------------

    def test_blocked_delete_repo(self):
        """DELETE /repos/owner/repo is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("DELETE", "/repos/owner/repo")
        assert allowed is False
        assert "repo delete" in reason.lower()

    def test_blocked_put_merge_pr(self):
        """PUT /repos/owner/repo/pulls/123/merge is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "PUT", "/repos/owner/repo/pulls/123/merge"
        )
        assert allowed is False
        assert "merge" in reason.lower()

    def test_blocked_secrets_access(self):
        """GET /repos/owner/repo/actions/secrets is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "GET", "/repos/owner/repo/actions/secrets"
        )
        assert allowed is False
        assert "secret" in reason.lower()

    def test_blocked_secrets_modify(self):
        """PUT /repos/owner/repo/actions/secrets/MY_SECRET is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "PUT", "/repos/owner/repo/actions/secrets/MY_SECRET"
        )
        assert allowed is False
        assert "secret" in reason.lower()

    def test_blocked_branch_protection_modify(self):
        """PUT /repos/owner/repo/branches/main/protection is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "PUT", "/repos/owner/repo/branches/main/protection"
        )
        assert allowed is False
        assert "branch protection" in reason.lower()

    def test_blocked_branch_protection_delete(self):
        """DELETE /repos/owner/repo/branches/main/protection is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "DELETE", "/repos/owner/repo/branches/main/protection"
        )
        assert allowed is False
        assert "branch protection" in reason.lower()

    def test_blocked_delete_ref(self):
        """DELETE /repos/owner/repo/git/refs/heads/feature is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "DELETE", "/repos/owner/repo/git/refs/heads/feature"
        )
        assert allowed is False
        assert "deletes" in reason.lower() and "branch/tag" in reason.lower()

    def test_blocked_patch_ref(self):
        """PATCH /repos/owner/repo/git/refs/heads/main is blocked (force push)."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "PATCH", "/repos/owner/repo/git/refs/heads/main"
        )
        assert allowed is False
        assert "ref" in reason.lower()

    def test_blocked_create_ref(self):
        """POST /repos/owner/repo/git/refs is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "POST", "/repos/owner/repo/git/refs"
        )
        assert allowed is False
        assert "ref" in reason.lower()

    def test_blocked_merges_endpoint(self):
        """POST /repos/owner/repo/merges is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "POST", "/repos/owner/repo/merges"
        )
        assert allowed is False
        assert "merge" in reason.lower()

    def test_blocked_variables_access(self):
        """GET /repos/owner/repo/actions/variables is blocked."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "GET", "/repos/owner/repo/actions/variables"
        )
        assert allowed is False
        assert "variable" in reason.lower()

    def test_blocked_unknown_path(self):
        """An unrecognized method+path is blocked as raw API access."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("DELETE", "/some/unknown/path")
        assert allowed is False
        assert "not permitted" in reason.lower()

    # -- GraphQL mutation blocking --------------------------------------------

    def test_blocked_graphql_merge_pull_request(self):
        """GraphQL mergePullRequest mutation is blocked."""
        checker = GitHubAPIChecker()
        body = json.dumps({
            "query": "mutation { mergePullRequest(input: { pullRequestId: 1 }) { clientMutationId } }"
        }).encode()
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert allowed is False
        assert "mergePullRequest" in reason

    def test_blocked_graphql_enable_auto_merge(self):
        """GraphQL enablePullRequestAutoMerge mutation is blocked."""
        checker = GitHubAPIChecker()
        body = json.dumps({
            "query": "mutation { enablePullRequestAutoMerge(input: { pullRequestId: 1 }) { clientMutationId } }"
        }).encode()
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert allowed is False
        assert "enablePullRequestAutoMerge" in reason

    def test_unparseable_graphql_fails_closed(self):
        """Invalid JSON body in a GraphQL POST fails closed."""
        checker = GitHubAPIChecker()
        body = b"this is not json {{{"
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert allowed is False
        assert "unparseable" in reason.lower()

    # -- PR reopen detection --------------------------------------------------

    def test_blocked_pr_reopen_via_patch(self):
        """PATCH setting state=open on a PR is blocked."""
        checker = GitHubAPIChecker()
        body = json.dumps({"state": "open"}).encode()
        allowed, reason = checker.check_request(
            "PATCH", "/repos/owner/repo/pulls/42", body
        )
        assert allowed is False
        assert "reopen" in reason.lower()

    # -- Conditional PR operations --------------------------------------------

    def test_conditional_pr_operations_blocked_by_default(self):
        """POST /repos/owner/repo/pulls (create PR) is blocked when allow_pr_operations is False."""
        checker = GitHubAPIChecker(allow_pr_operations=False)
        body = json.dumps({"title": "test", "head": "feat", "base": "main"}).encode()
        allowed, reason = checker.check_request(
            "POST", "/repos/owner/repo/pulls", body
        )
        assert allowed is False
        assert "PR operations blocked" in reason

    def test_conditional_pr_operations_allowed_with_flag(self):
        """POST /repos/owner/repo/pulls (create PR) is allowed when allow_pr_operations is True."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        body = json.dumps({"title": "test", "head": "feat", "base": "main"}).encode()
        allowed, reason = checker.check_request(
            "POST", "/repos/owner/repo/pulls", body
        )
        assert allowed is True
        assert reason is None

    def test_conditional_pr_comment_blocked_by_default(self):
        """POST comment on PR is blocked when allow_pr_operations is False."""
        checker = GitHubAPIChecker(allow_pr_operations=False)
        body = json.dumps({"body": "comment"}).encode()
        allowed, reason = checker.check_request(
            "POST", "/repos/owner/repo/pulls/5/comments", body
        )
        assert allowed is False
        assert "PR operations blocked" in reason

    def test_conditional_pr_patch_blocked_by_default(self):
        """PATCH on a PR is blocked when allow_pr_operations is False and not a reopen."""
        checker = GitHubAPIChecker(allow_pr_operations=False)
        body = json.dumps({"title": "updated title"}).encode()
        allowed, reason = checker.check_request(
            "PATCH", "/repos/owner/repo/pulls/10", body
        )
        assert allowed is False
        assert "PR operations blocked" in reason

    # -- Query string stripping -----------------------------------------------

    def test_query_string_stripped_before_matching(self):
        """Query parameters in the path do not affect allow/block decisions."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request(
            "GET", "/repos/owner/repo/pulls?state=open"
        )
        assert allowed is True
        assert reason is None

    # -- Case insensitivity ---------------------------------------------------

    def test_method_case_insensitive(self):
        """HTTP method matching is case-insensitive."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("get", "/repos/owner/repo")
        assert allowed is True
        assert reason is None


# ---------------------------------------------------------------------------
# TestGraphQLMutations
# ---------------------------------------------------------------------------


class TestGraphQLMutations:
    """Tests for always-blocked and conditionally-blocked GraphQL mutations."""

    @pytest.mark.parametrize("mutation", ALWAYS_BLOCKED_GRAPHQL_MUTATIONS)
    def test_always_blocked_mutation(self, mutation):
        """Every mutation in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS is blocked regardless of flags."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        body = json.dumps({
            "query": f"mutation {{ {mutation}(input: {{ id: 1 }}) {{ clientMutationId }} }}"
        }).encode()
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert allowed is False
        assert mutation in reason

    @pytest.mark.parametrize("mutation", CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS)
    def test_conditional_mutation_blocked_by_default(self, mutation):
        """Conditionally blocked mutations are blocked when allow_pr_operations is False."""
        checker = GitHubAPIChecker(allow_pr_operations=False)
        body = json.dumps({
            "query": f"mutation {{ {mutation}(input: {{ id: 1 }}) {{ clientMutationId }} }}"
        }).encode()
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert allowed is False
        assert mutation in reason

    @pytest.mark.parametrize("mutation", CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS)
    def test_conditional_mutation_allowed_with_flag(self, mutation):
        """Conditionally blocked mutations are allowed when allow_pr_operations is True."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        body = json.dumps({
            "query": f"mutation {{ {mutation}(input: {{ id: 1 }}) {{ clientMutationId }} }}"
        }).encode()
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert allowed is True
        assert reason is None

    def test_graphql_comment_stripping(self):
        """Comments in GraphQL queries are stripped before mutation detection."""
        checker = GitHubAPIChecker()
        body = json.dumps({
            "query": "mutation { # mergePullRequest is blocked\n addPullRequestReviewComment(input: { body: \"ok\" }) { clientMutationId } }"
        }).encode()
        # With allow_pr_operations=False, addPullRequestReviewComment is blocked
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert allowed is False
        assert "addPullRequestReviewComment" in reason

    def test_graphql_escaped_quotes_bypass_blocked(self):
        """Escaped quotes inside triple quotes do not bypass comment stripping."""
        checker = GitHubAPIChecker()
        # The malicious query tries to escape a triple quote, then start a comment
        # to hide the blocked mutation mergePullRequest.
        query = 'mutation { allowedMutation(arg: """ \\""" # """) mergePullRequest(input: {}) { clientMutationId } }'
        body = json.dumps({"query": query}).encode()
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert allowed is False
        assert "mergePullRequest" in reason

    def test_graphql_null_body_not_blocked(self):
        """POST /graphql with no body does not trigger GraphQL mutation blocking."""
        checker = GitHubAPIChecker()
        allowed, reason = checker.check_request("POST", "/graphql", None)
        # Falls through to allowlist: POST /graphql is allowed
        assert allowed is True
        assert reason is None


# ---------------------------------------------------------------------------
# TestBlocklistCompleteness
# ---------------------------------------------------------------------------


class TestBlocklistCompleteness:
    """Tests ensuring every entry in BLOCKED_PATTERNS is exercised."""

    @pytest.mark.parametrize(
        "method, pattern, reason_substring",
        BLOCKED_PATTERNS,
        ids=[f"{m} {p}" for m, p, _ in BLOCKED_PATTERNS],
    )
    def test_blocked_pattern(self, method, pattern, reason_substring):
        """Each BLOCKED_PATTERNS entry blocks a matching request."""
        checker = GitHubAPIChecker()

        # Derive a representative path from the regex pattern.
        # Replace named groups with plausible values.
        test_path = _pattern_to_test_path(pattern)
        allowed, reason = checker.check_request(method, test_path)
        assert allowed is False, (
            f"BLOCKED_PATTERNS entry ({method} {pattern}) did not block {test_path}"
        )
        assert reason is not None

    def test_all_blocked_patterns_covered(self):
        """Sanity check: BLOCKED_PATTERNS is non-empty."""
        assert len(BLOCKED_PATTERNS) > 0, "BLOCKED_PATTERNS should not be empty"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pattern_to_test_path(pattern: str) -> str:
    """Convert a BLOCKED_PATTERNS regex into a representative test path.

    Replaces regex quantifiers and groups with concrete values so each
    pattern can be tested with a real-looking URL path.
    """
    import re as _re

    # Substitute [^/]+ one at a time with meaningful names
    # First two are always owner/repo, then branch, org, etc.
    replacements = ["owner", "repo", "main", "MY_SECRET", "123", "env-name"]
    ri = 0

    def _replacer(m):
        nonlocal ri
        val = replacements[ri] if ri < len(replacements) else "val"
        ri += 1
        return val

    path = _re.sub(r"\[\^/\]\+", _replacer, pattern)
    # Replace .* with empty string (trailing wildcard patterns)
    path = path.replace(".*", "")
    # Replace \d+ with a number
    path = path.replace(r"\d+", "1")
    # Clean up double slashes
    while "//" in path:
        path = path.replace("//", "/")
    return path


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
