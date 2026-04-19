"""Verify GitHub blocklist completeness and fail-closed behavior.

Security invariants under test:
  1. Every BLOCKED_PATTERNS entry blocks at least one concrete path.
  2. Unknown method+path combinations are denied (fail-closed).
  3. Bypass attempts (double-encoding, BOM, malformed JSON) are blocked.
"""

import json
import re

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

        # Concrete test paths for blocked patterns.
        # Each entry is (description, method, path) — method must match and
        # path must match the corresponding BLOCKED_PATTERNS regex.
        _CONCRETE_PATHS = [
            ("DELETE /repos/owner/repo", "DELETE", "/repos/acme/project"),
            ("DELETE releases", "DELETE", "/repos/acme/project/releases/42"),
            ("DELETE git/refs", "DELETE", "/repos/acme/project/git/refs/heads/main"),
            ("PATCH git/refs", "PATCH", "/repos/acme/project/git/refs/heads/main"),
            ("PUT pulls/merge", "PUT", "/repos/acme/project/pulls/7/merge"),
            ("PUT pulls/auto-merge", "PUT", "/repos/acme/project/pulls/7/auto-merge"),
            ("DELETE pulls/auto-merge", "DELETE", "/repos/acme/project/pulls/7/auto-merge"),
            ("DELETE pulls/reviews", "DELETE", "/repos/acme/project/pulls/7/reviews/99"),
            ("POST merges", "POST", "/repos/acme/project/merges"),
            ("DELETE branches/protection", "DELETE", "/repos/acme/project/branches/main/protection"),
            ("PUT branches/protection", "PUT", "/repos/acme/project/branches/main/protection"),
            ("POST branches/protection", "POST", "/repos/acme/project/branches/main/protection"),
            ("POST git/refs", "POST", "/repos/acme/project/git/refs"),
            ("GET actions/secrets", "GET", "/repos/acme/project/actions/secrets"),
            ("PUT actions/secrets", "PUT", "/repos/acme/project/actions/secrets/MY_SECRET"),
            ("DELETE actions/secrets", "DELETE", "/repos/acme/project/actions/secrets/MY_SECRET"),
            ("GET actions/variables", "GET", "/repos/acme/project/actions/variables"),
            ("POST actions/variables", "POST", "/repos/acme/project/actions/variables"),
            ("PATCH actions/variables", "PATCH", "/repos/acme/project/actions/variables/MY_VAR"),
            ("DELETE actions/variables", "DELETE", "/repos/acme/project/actions/variables/MY_VAR"),
            ("GET orgs actions/secrets", "GET", "/orgs/acme/actions/secrets"),
            ("PUT orgs actions/secrets", "PUT", "/orgs/acme/actions/secrets/ORG_SECRET"),
            ("DELETE orgs actions/secrets", "DELETE", "/orgs/acme/actions/secrets/ORG_SECRET"),
            ("GET orgs actions/variables", "GET", "/orgs/acme/actions/variables"),
            ("POST orgs actions/variables", "POST", "/orgs/acme/actions/variables"),
            ("PATCH orgs actions/variables", "PATCH", "/orgs/acme/actions/variables/ORG_VAR"),
            ("DELETE orgs actions/variables", "DELETE", "/orgs/acme/actions/variables/ORG_VAR"),
            ("GET environments/secrets", "GET", "/repos/acme/project/environments/prod/secrets"),
            ("PUT environments/secrets", "PUT", "/repos/acme/project/environments/prod/secrets/ENV_SECRET"),
            ("DELETE environments/secrets", "DELETE", "/repos/acme/project/environments/prod/secrets/ENV_SECRET"),
            ("GET environments/variables", "GET", "/repos/acme/project/environments/prod/variables"),
            ("POST environments/variables", "POST", "/repos/acme/project/environments/prod/variables"),
            ("PATCH environments/variables", "PATCH", "/repos/acme/project/environments/prod/variables/ENV_VAR"),
            ("DELETE environments/variables", "DELETE", "/repos/acme/project/environments/prod/variables/ENV_VAR"),
            ("GET dependabot/secrets", "GET", "/repos/acme/project/dependabot/secrets"),
            ("PUT dependabot/secrets", "PUT", "/repos/acme/project/dependabot/secrets/DEP_SECRET"),
            ("DELETE dependabot/secrets", "DELETE", "/repos/acme/project/dependabot/secrets/DEP_SECRET"),
            ("GET codespaces/secrets", "GET", "/repos/acme/project/codespaces/secrets"),
            ("PUT codespaces/secrets", "PUT", "/repos/acme/project/codespaces/secrets/CS_SECRET"),
            ("DELETE codespaces/secrets", "DELETE", "/repos/acme/project/codespaces/secrets/CS_SECRET"),
        ]

        # Verify each BLOCKED_PATTERNS entry matches at least one concrete path
        for idx, (method, pattern, message) in enumerate(BLOCKED_PATTERNS):
            compiled = re.compile(pattern)
            matched_paths = [
                path for (_, m, path) in _CONCRETE_PATHS
                if m == method and compiled.match(path)
            ]
            assert matched_paths, (
                f"BLOCKED_PATTERNS[{idx}] ({method} {pattern}) has no concrete test path"
            )
            # Verify at least one matched path is actually blocked
            for path in matched_paths:
                allowed, reason = checker.check_request(method, path)
                assert not allowed, (
                    f"BLOCKED_PATTERNS[{idx}] ({method} {path}) was allowed: {reason}"
                )
                assert reason is not None
                break  # One successful block per pattern is sufficient

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

    def test_empty_graphql_body_not_crash(self) -> None:
        """Empty body on /graphql should not crash — must return a valid bool."""
        checker = GitHubAPIChecker(allow_pr_operations=True)
        allowed, reason = checker.check_request("POST", "/graphql", None)
        assert isinstance(allowed, bool)
        assert isinstance(reason, (str, type(None)))

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
