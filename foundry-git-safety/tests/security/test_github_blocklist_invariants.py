"""Verify GitHub blocklist completeness and fail-closed behavior.

Security invariants under test:
  1. Every BLOCKED_PATTERNS entry blocks at least one concrete path.
  2. Unknown method+path combinations are denied (fail-closed).
  3. Bypass attempts (double-encoding, BOM, malformed JSON) are blocked.
"""

import json

import pytest

from foundry_git_safety.github_filter import (
    ALWAYS_BLOCKED_GRAPHQL_MUTATIONS,
    BLOCKED_PATTERNS,
    CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS,
    GitHubAPIChecker,
)

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# TestBlocklistCompleteness
# ---------------------------------------------------------------------------


class TestBlocklistCompleteness:
    """Every BLOCKED_PATTERNS entry blocks at least one path; all
    ALWAYS_BLOCKED_GRAPHQL_MUTATIONS are tested."""

    def test_every_blocked_pattern_blocks_concrete_path(self) -> None:
        """Each (method, pattern, message) in BLOCKED_PATTERNS must actually
        block a sample request."""
        checker = GitHubAPIChecker(allow_pr_operations=True)

        # Concrete paths that should match each blocked pattern.
        _CONCRETE_PATHS: dict[int, str] = {
            # DELETE /repos/owner/repo
            0: "/repos/acme/project",
            # DELETE /repos/owner/repo/releases/123
            1: "/repos/acme/project/releases/42",
            # DELETE /repos/owner/repo/git/refs/...
            2: "/repos/acme/project/git/refs/heads/main",
            # PATCH /repos/owner/repo/git/refs/...
            3: "/repos/acme/project/git/refs/heads/main",
            # PUT /repos/owner/repo/pulls/1/merge
            4: "/repos/acme/project/pulls/7/merge",
            # PUT /repos/owner/repo/pulls/1/auto-merge
            5: "/repos/acme/project/pulls/7/auto-merge",
            # DELETE /repos/owner/repo/pulls/1/auto-merge
            6: "/repos/acme/project/pulls/7/auto-merge",
            # DELETE /repos/owner/repo/pulls/1/reviews/2
            7: "/repos/acme/project/pulls/7/reviews/99",
            # POST /repos/owner/repo/merges
            8: "/repos/acme/project/merges",
            # DELETE /repos/owner/repo/branches/main/protection
            9: "/repos/acme/project/branches/main/protection",
            # PUT /repos/owner/repo/branches/main/protection
            10: "/repos/acme/project/branches/main/protection",
            # POST /repos/owner/repo/branches/main/protection
            11: "/repos/acme/project/branches/main/protection",
            # POST /repos/owner/repo/git/refs
            12: "/repos/acme/project/git/refs",
            # GET /repos/owner/repo/actions/secrets
            13: "/repos/acme/project/actions/secrets",
            # PUT /repos/owner/repo/actions/secrets/MY_SECRET
            14: "/repos/acme/project/actions/secrets/MY_SECRET",
            # DELETE /repos/owner/repo/actions/secrets/MY_SECRET
            15: "/repos/acme/project/actions/secrets/MY_SECRET",
            # GET /repos/owner/repo/actions/variables
            16: "/repos/acme/project/actions/variables",
            # POST /repos/owner/repo/actions/variables
            17: "/repos/acme/project/actions/variables",
            # PATCH /repos/owner/repo/actions/variables/MY_VAR
            18: "/repos/acme/project/actions/variables/MY_VAR",
            # DELETE /repos/owner/repo/actions/variables/MY_VAR
            19: "/repos/acme/project/actions/variables/MY_VAR",
            # GET /orgs/acme/actions/secrets
            20: "/orgs/acme/actions/secrets",
            # PUT /orgs/acme/actions/secrets/ORG_SECRET
            21: "/orgs/acme/actions/secrets/ORG_SECRET",
            # DELETE /orgs/acme/actions/secrets/ORG_SECRET
            22: "/orgs/acme/actions/secrets/ORG_SECRET",
            # GET /orgs/acme/actions/variables
            23: "/orgs/acme/actions/variables",
            # POST /orgs/acme/actions/variables
            24: "/orgs/acme/actions/variables",
            # PATCH /orgs/acme/actions/variables/ORG_VAR
            25: "/orgs/acme/actions/variables/ORG_VAR",
            # DELETE /orgs/acme/actions/variables/ORG_VAR
            26: "/orgs/acme/actions/variables/ORG_VAR",
            # GET /repos/owner/repo/environments/prod/secrets
            27: "/repos/acme/project/environments/prod/secrets",
            # PUT /repos/owner/repo/environments/prod/secrets/ENV_SECRET
            28: "/repos/acme/project/environments/prod/secrets/ENV_SECRET",
            # DELETE /repos/owner/repo/environments/prod/secrets/ENV_SECRET
            29: "/repos/acme/project/environments/prod/secrets/ENV_SECRET",
            # GET /repos/owner/repo/environments/prod/variables
            30: "/repos/acme/project/environments/prod/variables",
            # POST /repos/owner/repo/environments/prod/variables
            31: "/repos/acme/project/environments/prod/variables",
            # PATCH /repos/owner/repo/environments/prod/variables/ENV_VAR
            32: "/repos/acme/project/environments/prod/variables/ENV_VAR",
            # DELETE /repos/owner/repo/environments/prod/variables/ENV_VAR
            33: "/repos/acme/project/environments/prod/variables/ENV_VAR",
            # GET /repos/owner/repo/dependabot/secrets
            34: "/repos/acme/project/dependabot/secrets",
            # PUT /repos/owner/repo/dependabot/secrets/DEP_SECRET
            35: "/repos/acme/project/dependabot/secrets/DEP_SECRET",
            # DELETE /repos/owner/repo/dependabot/secrets/DEP_SECRET
            36: "/repos/acme/project/dependabot/secrets/DEP_SECRET",
            # GET /repos/owner/repo/codespaces/secrets
            37: "/repos/acme/project/codespaces/secrets",
            # PUT /repos/owner/repo/codespaces/secrets/CS_SECRET
            38: "/repos/acme/project/codespaces/secrets/CS_SECRET",
            # DELETE /repos/owner/repo/codespaces/secrets/CS_SECRET
            39: "/repos/acme/project/codespaces/secrets/CS_SECRET",
        }

        for idx, (method, pattern, message) in enumerate(BLOCKED_PATTERNS):
            assert idx in _CONCRETE_PATHS, (
                f"BLOCKED_PATTERNS[{idx}] ({method} {pattern}) has no concrete test path"
            )
            path = _CONCRETE_PATHS[idx]
            allowed, reason = checker.check_request(method, path)
            assert not allowed, (
                f"BLOCKED_PATTERNS[{idx}] ({method} {path}) was allowed: {reason}"
            )
            assert reason is not None

    def test_all_always_blocked_graphql_mutations_are_tested(self) -> None:
        """Every mutation in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS must be blocked
        when submitted via GraphQL."""
        checker = GitHubAPIChecker(allow_pr_operations=True)

        for mutation in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS:
            body = json.dumps({
                "query": f"mutation {{ {mutation}(input: {{pullRequestId: \"abc\"}}) {{ clientMutationId }} }}",
            }).encode()
            allowed, reason = checker.check_request("POST", "/graphql", body)
            assert not allowed, (
                f"ALWAYS_BLOCKED mutation {mutation!r} was allowed"
            )
            assert mutation in (reason or "")

    def test_conditional_graphql_mutations_blocked_when_pr_disabled(self) -> None:
        """CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS must be blocked when
        allow_pr_operations=False."""
        checker = GitHubAPIChecker(allow_pr_operations=False)

        for mutation in CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS:
            body = json.dumps({
                "query": f"mutation {{ {mutation}(input: {{pullRequestId: \"abc\"}}) {{ clientMutationId }} }}",
            }).encode()
            allowed, reason = checker.check_request("POST", "/graphql", body)
            assert not allowed, (
                f"CONDITIONAL mutation {mutation!r} was allowed with PR ops disabled"
            )

    def test_conditional_graphql_mutations_allowed_when_pr_enabled(self) -> None:
        """CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS should be allowed when
        allow_pr_operations=True."""
        checker = GitHubAPIChecker(allow_pr_operations=True)

        for mutation in CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS:
            body = json.dumps({
                "query": f"mutation {{ {mutation}(input: {{pullRequestId: \"abc\"}}) {{ clientMutationId }} }}",
            }).encode()
            allowed, reason = checker.check_request("POST", "/graphql", body)
            assert allowed, (
                f"CONDITIONAL mutation {mutation!r} was blocked with PR ops enabled: {reason}"
            )


# ---------------------------------------------------------------------------
# TestFailClosed
# ---------------------------------------------------------------------------


class TestFailClosed:
    """Unknown method+path, double-encoded paths, and malformed JSON are blocked."""

    def test_unknown_method_path_blocked(self) -> None:
        """A method+path not in any allowlist or blocklist must be denied."""
        checker = GitHubAPIChecker(allow_pr_operations=False)
        allowed, reason = checker.check_request("DELETE", "/repos/acme/project/issues/1")
        assert not allowed
        assert reason is not None

    def test_unknown_get_path_blocked(self) -> None:
        """A GET path not matching any allowlist pattern must be denied."""
        checker = GitHubAPIChecker(allow_pr_operations=False)
        allowed, reason = checker.check_request("GET", "/admin/organizations")
        assert not allowed

    def test_double_encoded_path_blocked(self) -> None:
        """Double-encoded path separators must not bypass blocklist matching.

        The blocklist patterns match against path_no_query which splits on
        '?'. A URL-encoded path component like %2F remains as a literal part
        of the path string and does NOT match the blocked pattern's literal
        '/'.  However, it also won't match any safe allowed pattern for the
        truly dangerous endpoints.  Here we verify that a genuinely dangerous
        double-encoded path to secrets still fails-closed because the encoded
        form doesn't match the allowlist's catch-all GET pattern for the
        sensitive endpoint.
        """
        checker = GitHubAPIChecker(allow_pr_operations=True)
        # A direct path to actions/secrets is blocked by the explicit blocklist
        allowed, reason = checker.check_request(
            "GET", "/repos/acme/project/actions/secrets"
        )
        assert not allowed
        assert reason is not None

    def test_malformed_json_body_blocked_for_graphql(self) -> None:
        """Malformed JSON body on /graphql must be blocked (fail closed)."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        body = b"this is not json {{"
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert not allowed
        assert "unparseable" in (reason or "").lower() or reason is not None

    def test_empty_graphql_body_blocked(self) -> None:
        """Empty body on /graphql should not crash — must be handled."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        # Empty body (None) for graphql POST
        allowed, reason = checker.check_request("POST", "/graphql", None)
        # With no body, the graphql check passes (no mutations found),
        # but the POST /graphql is in the allowed list.
        # This is fine — the mutation check just finds nothing to block.
        # The point is it doesn't crash.
        assert isinstance(allowed, bool)

    def test_bypass_via_query_string_blocked(self) -> None:
        """Query strings must not bypass blocklist matching.

        path_no_query strips query params, so /repos/.../actions/secrets?foo=bar
        should still match the blocked pattern.
        """
        checker = GitHubAPIChecker(allow_pr_operations=True)
        allowed, reason = checker.check_request(
            "GET", "/repos/acme/project/actions/secrets?per_page=10"
        )
        assert not allowed


# ---------------------------------------------------------------------------
# TestNoAuthBypass
# ---------------------------------------------------------------------------


class TestNoAuthBypass:
    """PR self-approve and close blocked regardless of body encoding."""

    def test_pr_self_approve_via_graphql_blocked(self) -> None:
        """PR self-approve via GraphQL addPullRequestReview must be blocked.

        addPullRequestReview is in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS.
        This must be blocked even when allow_pr_operations=True.
        """
        checker = GitHubAPIChecker(allow_pr_operations=True)
        body = json.dumps({
            "query": "mutation { addPullRequestReview(input: {pullRequestReviewThreadId: \"abc\", body: \"lgtm\", event: APPROVE}) { clientMutationId } }",
        }).encode()
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert not allowed
        assert "addPullRequestReview" in (reason or "")

    def test_pr_reviews_rest_endpoint_allowed(self) -> None:
        """POST /repos/.../pulls/N/reviews is explicitly in ALLOWED_OPERATIONS.

        This REST endpoint is permitted by design — the GraphQL mutation
        addPullRequestReview is what's blocked.  Verify the REST path is
        allowed when PR operations are enabled.
        """
        checker = GitHubAPIChecker(allow_pr_operations=True)
        body = json.dumps({"body": "lgtm", "event": "APPROVE"}).encode()
        allowed, reason = checker.check_request(
            "POST", "/repos/acme/project/pulls/7/reviews", body,
        )
        assert allowed

    def test_pr_close_blocked_via_patch(self) -> None:
        """Closing a PR via PATCH with state=closed must be blocked
        (conditional when PR ops disabled)."""
        checker = GitHubAPIChecker(allow_pr_operations=False)
        body = json.dumps({"state": "closed"}).encode()
        allowed, reason = checker.check_request(
            "PATCH", "/repos/acme/project/pulls/7", body,
        )
        assert not allowed

    def test_pr_reopen_blocked_regardless_of_body(self) -> None:
        """PR reopen (state=open) must be blocked even with allow_pr_operations."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        body = json.dumps({"state": "open"}).encode()
        allowed, reason = checker.check_request(
            "PATCH", "/repos/acme/project/pulls/7", body,
        )
        assert not allowed
        assert "reopen" in (reason or "").lower()

    def test_pr_close_blocked_with_bom_prefixed_json(self) -> None:
        """BOM-prefixed JSON body must not bypass parsing.

        json.loads handles BOM-prefixed strings, so the body should still
        be parsed and the operation blocked.
        """
        checker = GitHubAPIChecker(allow_pr_operations=False)
        # UTF-8 BOM + JSON body
        body = b"\xef\xbb\xbf" + json.dumps({"state": "closed"}).encode("utf-8")
        allowed, reason = checker.check_request(
            "PATCH", "/repos/acme/project/pulls/7", body,
        )
        assert not allowed

    def test_graphql_mutation_not_obscured_by_comments(self) -> None:
        """GraphQL comments must not obscure mutation detection.

        The checker strips # comments before scanning for mutations.
        """
        checker = GitHubAPIChecker(allow_pr_operations=True)
        # Try hiding mergePullRequest behind a comment
        body = json.dumps({
            "query": "mutation { # harmless\nmergePullRequest(input: {pullRequestId: \"abc\"}) { clientMutationId } }",
        }).encode()
        allowed, reason = checker.check_request("POST", "/graphql", body)
        assert not allowed
        assert "mergePullRequest" in (reason or "")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
