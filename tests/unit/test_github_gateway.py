"""Unit tests for GitHub API gateway and shared security policies.

Tests the security policy functions (now in security_policies.py) including:
- Path normalization
- Merge blocking (with GraphQL scoping fix)
- GitHub blocklist
- Body inspection

Also tests GitHub-specific credential loading from github_gateway.py.
"""

import json
import os
import sys
from unittest import mock
from unittest.mock import patch

# github_gateway.py imports aiohttp at module level.  Install a minimal
# mock so the module can be imported without aiohttp installed.
if "aiohttp" not in sys.modules:
    sys.modules["aiohttp"] = mock.MagicMock()
    sys.modules["aiohttp.web"] = mock.MagicMock()

# conftest.py adds unified-proxy to sys.path.

from github_gateway import _load_github_credential
from security_policies import (
    check_github_blocklist,
    check_github_body_policies,
    is_merge_request,
    normalize_path,
)


# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------


class TestLoadGitHubCredential:
    """Tests for _load_github_credential()."""

    def test_github_token_preferred(self):
        """GITHUB_TOKEN takes priority over GH_TOKEN."""
        with patch.dict(os.environ, {
            "GITHUB_TOKEN": "ghp_primary",
            "GH_TOKEN": "gho_fallback",
        }, clear=False):
            cred = _load_github_credential()
        assert cred is not None
        assert cred["header"] == "Authorization"
        assert cred["value"] == "Bearer ghp_primary"

    def test_gh_token_fallback(self):
        """GH_TOKEN is used when GITHUB_TOKEN is empty."""
        env = os.environ.copy()
        env.pop("GITHUB_TOKEN", None)
        env["GH_TOKEN"] = "gho_fallback"
        with patch.dict(os.environ, env, clear=True):
            cred = _load_github_credential()
        assert cred is not None
        assert cred["value"] == "Bearer gho_fallback"

    def test_no_token_returns_none(self):
        """Returns None when neither token is set."""
        env = os.environ.copy()
        env.pop("GITHUB_TOKEN", None)
        env.pop("GH_TOKEN", None)
        with patch.dict(os.environ, env, clear=True):
            cred = _load_github_credential()
        assert cred is None

    def test_empty_token_treated_as_missing(self):
        """Empty string tokens are treated as missing."""
        with patch.dict(os.environ, {
            "GITHUB_TOKEN": "",
            "GH_TOKEN": "",
        }, clear=False):
            cred = _load_github_credential()
        assert cred is None

    def test_whitespace_token_treated_as_missing(self):
        """Whitespace-only tokens are treated as missing."""
        with patch.dict(os.environ, {
            "GITHUB_TOKEN": "   ",
            "GH_TOKEN": "  \t  ",
        }, clear=False):
            cred = _load_github_credential()
        assert cred is None


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------


class TestNormalizePath:
    """Tests for normalize_path()."""

    def test_simple_path(self):
        assert normalize_path("/repos/owner/repo") == "/repos/owner/repo"

    def test_strips_query_string(self):
        assert normalize_path("/repos/owner/repo?per_page=100") == "/repos/owner/repo"

    def test_strips_fragment(self):
        assert normalize_path("/repos/owner/repo#section") == "/repos/owner/repo"

    def test_collapses_double_slashes(self):
        assert normalize_path("/repos//owner///repo") == "/repos/owner/repo"

    def test_resolves_dot_segments(self):
        assert normalize_path("/repos/owner/../other/repo") == "/repos/other/repo"

    def test_strips_trailing_slash(self):
        assert normalize_path("/repos/owner/repo/") == "/repos/owner/repo"

    def test_root_path_preserved(self):
        assert normalize_path("/") == "/"

    def test_rejects_double_encoding(self):
        """Double-encoded paths (% remaining after decode) are rejected."""
        # %252e decodes to %2e — the remaining % triggers rejection
        assert normalize_path("/repos/%252e%252e/evil") is None

    def test_single_encoded_dots_resolved(self):
        """Single-encoded .. (%2e%2e) decodes normally and gets resolved."""
        # %2e%2e decodes to .. which normpath resolves
        assert normalize_path("/repos/%2e%2e/evil") == "/evil"

    def test_single_encoded_slash_decoded(self):
        """Single-encoded / (%2F) decodes normally."""
        assert normalize_path("/repos/owner%2Frepo") == "/repos/owner/repo"

    def test_normpath_before_slash_collapse(self):
        """Path with .. and // is normalized correctly (normpath first)."""
        # /foo/ + .. = / + /bar = /bar (.. navigates up from foo)
        assert normalize_path("/foo//..//bar") == "/bar"

    def test_dotdot_with_double_slash(self):
        """Multiple .. segments with // are resolved correctly."""
        assert normalize_path("/a/b/../..//c") == "/c"

    def test_null_bytes_rejected(self):
        """Paths with null bytes (%00) are rejected as double-encoding."""
        # %00 decodes to a null byte, but the path still contains '%'
        # after decoding if double-encoded (%2500), or becomes a bare
        # null byte if single-encoded (%00). Either way, the path is
        # sanitized by posixpath.normpath or rejected.
        result = normalize_path("/repos/%2500/evil")
        assert result is None  # Double-encoding detected


# ---------------------------------------------------------------------------
# Merge blocking (Step E)
# ---------------------------------------------------------------------------


class TestIsMergeRequest:
    """Tests for is_merge_request()."""

    def test_rest_merge_endpoint(self):
        assert is_merge_request("/repos/owner/repo/pulls/42/merge", b"") is True

    def test_rest_auto_merge_endpoint(self):
        assert is_merge_request("/repos/owner/repo/pulls/1/auto-merge", b"") is True

    def test_graphql_merge_mutation(self):
        body = json.dumps({"query": "mutation { mergePullRequest(input: {}) }"}).encode()
        assert is_merge_request("/graphql", body) is True

    def test_graphql_auto_merge_mutation(self):
        body = json.dumps({"query": "mutation { enablePullRequestAutoMerge(input: {}) }"}).encode()
        assert is_merge_request("/graphql", body) is True

    def test_normal_pr_endpoint_not_blocked(self):
        assert is_merge_request("/repos/owner/repo/pulls/42", b"") is False

    def test_repo_merges_not_caught(self):
        """The repo merge API (/merges) is NOT caught by the early-exit merge check."""
        assert is_merge_request("/repos/owner/repo/merges", b"") is False

    def test_empty_body(self):
        assert is_merge_request("/repos/owner/repo/pulls", b"") is False

    def test_graphql_merge_keyword_in_variables_not_blocked(self):
        """GraphQL body with merge keyword only in variables (not query) is NOT blocked.

        This tests the Issue #5 fix: only the 'query' field is checked,
        not the entire body.
        """
        body = json.dumps({
            "query": "mutation { createPullRequest(input: $input) }",
            "variables": {
                "input": {
                    "title": "Fix mergePullRequest documentation"
                }
            }
        }).encode()
        assert is_merge_request("/graphql", body) is False

    def test_graphql_merge_keyword_in_query_field_blocked(self):
        """GraphQL body with merge keyword in query field IS blocked."""
        body = json.dumps({
            "query": "mutation { mergePullRequest(input: {pullRequestId: \"abc\"}) }",
            "variables": {}
        }).encode()
        assert is_merge_request("/graphql", body) is True

    def test_non_graphql_path_with_merge_keyword_in_body_not_blocked(self):
        """Non-GraphQL path with merge keyword in body is NOT blocked.

        Only /graphql paths have body inspection for merge keywords.
        """
        body = b'some text with mergePullRequest in it'
        assert is_merge_request("/some/other/path", body) is False

    def test_graphql_malformed_json_fallback(self):
        """Malformed JSON on /graphql falls back to substring scan (fail closed)."""
        body = b'not json but contains mergePullRequest'
        assert is_merge_request("/graphql", body) is True

    def test_graphql_no_query_field(self):
        """GraphQL body without 'query' field is not blocked."""
        body = json.dumps({"variables": {"note": "mergePullRequest ref"}}).encode()
        assert is_merge_request("/graphql", body) is False


# ---------------------------------------------------------------------------
# GitHub blocklist (Step 3)
# ---------------------------------------------------------------------------


class TestCheckGitHubBlocklist:
    """Tests for check_github_blocklist()."""

    def test_blocks_pr_merge(self):
        result = check_github_blocklist("PUT", "/repos/owner/repo/pulls/1/merge")
        assert result is not None
        assert "merge" in result.lower()

    def test_blocks_release_creation(self):
        result = check_github_blocklist("POST", "/repos/owner/repo/releases")
        assert result is not None
        assert "release" in result.lower()

    def test_blocks_git_ref_creation(self):
        result = check_github_blocklist("POST", "/repos/owner/repo/git/refs")
        assert result is not None
        assert "ref" in result.lower()

    def test_blocks_git_ref_mutation(self):
        result = check_github_blocklist("PATCH", "/repos/owner/repo/git/refs/heads/main")
        assert result is not None

    def test_blocks_git_ref_deletion(self):
        result = check_github_blocklist("DELETE", "/repos/owner/repo/git/refs/tags/v1")
        assert result is not None

    def test_blocks_auto_merge_put(self):
        result = check_github_blocklist("PUT", "/repos/owner/repo/pulls/1/auto-merge")
        assert result is not None

    def test_blocks_auto_merge_delete(self):
        result = check_github_blocklist("DELETE", "/repos/owner/repo/pulls/1/auto-merge")
        assert result is not None

    def test_blocks_review_deletion(self):
        result = check_github_blocklist("DELETE", "/repos/owner/repo/pulls/1/reviews/123")
        assert result is not None

    def test_blocks_repo_merges(self):
        result = check_github_blocklist("POST", "/repos/owner/repo/merges")
        assert result is not None
        assert "merge" in result.lower()

    def test_blocks_webhooks(self):
        result = check_github_blocklist("POST", "/repos/owner/repo/hooks")
        assert result is not None

    def test_blocks_deploy_keys(self):
        result = check_github_blocklist("POST", "/repos/owner/repo/deploy_keys")
        assert result is not None

    def test_blocks_actions_secrets(self):
        result = check_github_blocklist("GET", "/repos/owner/repo/actions/secrets")
        assert result is not None

    def test_blocks_branch_protection(self):
        result = check_github_blocklist("PUT", "/repos/owner/repo/branches/main/protection")
        assert result is not None

    def test_blocks_branch_rename(self):
        result = check_github_blocklist("POST", "/repos/owner/repo/branches/main/rename")
        assert result is not None

    def test_allows_pr_list(self):
        result = check_github_blocklist("GET", "/repos/owner/repo/pulls")
        assert result is None

    def test_allows_pr_get(self):
        result = check_github_blocklist("GET", "/repos/owner/repo/pulls/1")
        assert result is None

    def test_allows_issue_list(self):
        result = check_github_blocklist("GET", "/repos/owner/repo/issues")
        assert result is None

    def test_allows_graphql(self):
        result = check_github_blocklist("POST", "/graphql")
        assert result is None

    def test_allows_release_list(self):
        """GET releases is allowed (only POST creation is blocked)."""
        result = check_github_blocklist("GET", "/repos/owner/repo/releases")
        assert result is None

    def test_allows_pr_create(self):
        result = check_github_blocklist("POST", "/repos/owner/repo/pulls")
        assert result is None

    def test_allows_pr_comment(self):
        result = check_github_blocklist("POST", "/repos/owner/repo/issues/1/comments")
        assert result is None


# ---------------------------------------------------------------------------
# Body inspection (Step 3b)
# ---------------------------------------------------------------------------


class TestCheckGitHubBodyPolicies:
    """Tests for check_github_body_policies()."""

    def _json_body(self, data: dict) -> bytes:
        return json.dumps(data).encode()

    def test_blocks_pr_close(self):
        body = self._json_body({"state": "closed"})
        result = check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body,
            "application/json", "",
        )
        assert result is not None
        assert "pull request" in result.lower()

    def test_blocks_issue_close(self):
        body = self._json_body({"state": "closed"})
        result = check_github_body_policies(
            "PATCH", "/repos/owner/repo/issues/1", body,
            "application/json", "",
        )
        assert result is not None
        assert "issue" in result.lower()

    def test_allows_pr_reopen(self):
        body = self._json_body({"state": "open"})
        result = check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body,
            "application/json", "",
        )
        assert result is None

    def test_allows_pr_title_edit(self):
        body = self._json_body({"title": "New title"})
        result = check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body,
            "application/json", "",
        )
        assert result is None

    def test_blocks_pr_self_approval(self):
        body = self._json_body({"event": "APPROVE", "body": "LGTM"})
        result = check_github_body_policies(
            "POST", "/repos/owner/repo/pulls/1/reviews", body,
            "application/json", "",
        )
        assert result is not None
        assert "approv" in result.lower()

    def test_allows_pr_review_comment(self):
        body = self._json_body({"event": "COMMENT", "body": "Looks good"})
        result = check_github_body_policies(
            "POST", "/repos/owner/repo/pulls/1/reviews", body,
            "application/json", "",
        )
        assert result is None

    def test_allows_pr_review_request_changes(self):
        body = self._json_body({"event": "REQUEST_CHANGES", "body": "Fix this"})
        result = check_github_body_policies(
            "POST", "/repos/owner/repo/pulls/1/reviews", body,
            "application/json", "",
        )
        assert result is None

    def test_rejects_compressed_body(self):
        body = self._json_body({"state": "closed"})
        result = check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body,
            "application/json", "gzip",
        )
        assert result is not None
        assert "compress" in result.lower()

    def test_rejects_non_json_content_type(self):
        body = b"state=closed"
        result = check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body,
            "application/x-www-form-urlencoded", "",
        )
        assert result is not None
        assert "json" in result.lower()

    def test_rejects_malformed_json(self):
        body = b"not json at all"
        result = check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body,
            "application/json", "",
        )
        assert result is not None
        assert "malformed" in result.lower()

    def test_rejects_json_array(self):
        body = b"[1, 2, 3]"
        result = check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body,
            "application/json", "",
        )
        assert result is not None
        assert "object" in result.lower()

    def test_ignores_get_requests(self):
        result = check_github_body_policies(
            "GET", "/repos/owner/repo/pulls/1", None,
            "", "",
        )
        assert result is None

    def test_ignores_non_pr_patch(self):
        body = self._json_body({"state": "closed"})
        result = check_github_body_policies(
            "PATCH", "/repos/owner/repo/contents/README.md", body,
            "application/json", "",
        )
        assert result is None

    def test_case_insensitive_state(self):
        """state: 'CLOSED' (uppercase) should also be blocked."""
        body = self._json_body({"state": "CLOSED"})
        result = check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body,
            "application/json", "",
        )
        assert result is not None

    def test_case_insensitive_approve(self):
        """event: 'approve' (lowercase) should also be blocked."""
        body = self._json_body({"event": "approve"})
        result = check_github_body_policies(
            "POST", "/repos/owner/repo/pulls/1/reviews", body,
            "application/json", "",
        )
        assert result is not None

    def test_handles_utf8_bom(self):
        """Bodies with UTF-8 BOM should be handled correctly."""
        body = b"\xef\xbb\xbf" + self._json_body({"state": "closed"})
        result = check_github_body_policies(
            "PATCH", "/repos/owner/repo/pulls/1", body,
            "application/json", "",
        )
        assert result is not None


# ---------------------------------------------------------------------------
# Placeholder credential filter (gateway_base._PLACEHOLDER_MARKERS)
# ---------------------------------------------------------------------------


class TestPlaceholderFilter:
    """Tests that placeholder credential values are filtered by startswith."""

    def test_placeholder_prefix_is_stripped(self):
        """Header value starting with CRED_PROXY_ is a placeholder."""
        from gateway_base import _PLACEHOLDER_MARKERS

        value = "CRED_PROXY_abc123"
        assert any(value.startswith(m) for m in _PLACEHOLDER_MARKERS)

    def test_substring_match_is_not_stripped(self):
        """Header value containing CRED_PROXY_ mid-string is NOT a placeholder."""
        from gateway_base import _PLACEHOLDER_MARKERS

        value = "my-token-has-CRED_PROXY_in-it"
        assert not any(value.startswith(m) for m in _PLACEHOLDER_MARKERS)

    def test_full_placeholder_is_stripped(self):
        """CREDENTIAL_PROXY_PLACEHOLDER prefix is a placeholder."""
        from gateway_base import _PLACEHOLDER_MARKERS

        value = "CREDENTIAL_PROXY_PLACEHOLDER"
        assert any(value.startswith(m) for m in _PLACEHOLDER_MARKERS)

    def test_real_token_passes_through(self):
        """A real bearer token is not mistaken for a placeholder."""
        from gateway_base import _PLACEHOLDER_MARKERS

        value = "ghp_AbCdEf1234567890"
        assert not any(value.startswith(m) for m in _PLACEHOLDER_MARKERS)
