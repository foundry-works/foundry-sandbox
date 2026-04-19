"""Tests for foundry_git_safety.security_policies."""

import json

import pytest

from foundry_git_safety.security_policies import (
    BLOCKED_PATH_PATTERNS,
    check_github_blocklist,
    check_github_body_policies,
    is_merge_request,
    normalize_path,
)


class TestNormalizePath:
    def test_basic_path(self):
        assert normalize_path("/repos/owner/repo/pulls/1") == "/repos/owner/repo/pulls/1"

    def test_query_string_stripped(self):
        assert normalize_path("/repos/owner/repo?p=1") == "/repos/owner/repo"

    def test_double_encoding_rejected(self):
        assert normalize_path("/repos/%252F/repo") is None

    def test_repeated_slashes_collapsed(self):
        assert normalize_path("/repos//owner///repo") == "/repos/owner/repo"

    def test_dot_segments_resolved(self):
        assert normalize_path("/repos/owner/../org/repo") == "/repos/org/repo"

    def test_trailing_slash_stripped(self):
        assert normalize_path("/repos/owner/repo/") == "/repos/owner/repo"

    def test_bare_slash_preserved(self):
        assert normalize_path("/") == "/"

    def test_url_encoded_path(self):
        assert normalize_path("/repos/owner%2Forg/repo") == "/repos/owner/org/repo"


class TestIsMergeRequest:
    def test_rest_merge_path(self):
        assert is_merge_request("/repos/o/r/pulls/1/merge", b"")

    def test_rest_auto_merge_path(self):
        assert is_merge_request("/repos/o/r/pulls/1/auto-merge", b"")

    def test_graphql_merge_mutation(self):
        body = json.dumps({"query": "mutation { mergePullRequest(...) }"}).encode()
        assert is_merge_request("/graphql", body)

    def test_graphql_non_merge_query(self):
        body = json.dumps({"query": "{ viewer { login } }"}).encode()
        assert not is_merge_request("/graphql", body)

    def test_non_merge_rest_path(self):
        assert not is_merge_request("/repos/o/r/pulls/1", b"")

    def test_double_encoding_fails_closed(self):
        assert is_merge_request("/repos/%252E/pulls/1/merge", b"")


class TestCheckGithubBlocklist:
    def test_put_merge_pr_blocked(self):
        assert check_github_blocklist("PUT", "/repos/o/r/pulls/1/merge") is not None

    def test_post_create_release_blocked(self):
        assert check_github_blocklist("POST", "/repos/o/r/releases") is not None

    def test_post_git_refs_creation_blocked(self):
        assert check_github_blocklist("POST", "/repos/o/r/git/refs") is not None

    def test_patch_git_refs_blocked(self):
        assert check_github_blocklist("PATCH", "/repos/o/r/git/refs/heads/main") is not None

    def test_delete_git_refs_blocked(self):
        assert check_github_blocklist("DELETE", "/repos/o/r/git/refs/heads/main") is not None

    def test_blocked_hooks_path(self):
        assert check_github_blocklist("GET", "/repos/o/r/hooks") is not None

    def test_blocked_secrets_path(self):
        assert check_github_blocklist("GET", "/repos/o/r/actions/secrets") is not None

    def test_blocked_deploy_keys(self):
        assert check_github_blocklist("GET", "/repos/o/r/keys") is not None

    def test_allowed_path_returns_none(self):
        assert check_github_blocklist("GET", "/repos/o/r/pulls") is None

    def test_delete_review_blocked(self):
        assert check_github_blocklist("DELETE", "/repos/o/r/pulls/1/reviews/42") is not None

    def test_post_merges_blocked(self):
        assert check_github_blocklist("POST", "/repos/o/r/merges") is not None


class TestCheckGithubBodyPolicies:
    def test_patch_pr_close_blocked(self):
        body = json.dumps({"state": "closed"}).encode()
        result = check_github_body_policies(
            "PATCH", "/repos/o/r/pulls/1", body, "application/json", ""
        )
        assert result is not None
        assert "clos" in result.lower()

    def test_patch_issue_close_blocked(self):
        body = json.dumps({"state": "closed"}).encode()
        result = check_github_body_policies(
            "PATCH", "/repos/o/r/issues/1", body, "application/json", ""
        )
        assert result is not None

    def test_post_pr_review_approve_blocked(self):
        body = json.dumps({"event": "APPROVE"}).encode()
        result = check_github_body_policies(
            "POST", "/repos/o/r/pulls/1/reviews", body, "application/json", ""
        )
        assert result is not None

    def test_compressed_body_rejected(self):
        result = check_github_body_policies(
            "POST", "/repos/o/r/pulls/1/reviews", b"{}", "application/json", "gzip"
        )
        assert result is not None

    def test_non_json_content_type_rejected(self):
        result = check_github_body_policies(
            "POST", "/repos/o/r/pulls/1/reviews", b"{}", "text/plain", ""
        )
        assert result is not None

    def test_streaming_body_rejected(self):
        result = check_github_body_policies(
            "POST", "/repos/o/r/pulls/1/reviews", None, "application/json", ""
        )
        assert result is not None

    def test_malformed_json_rejected(self):
        result = check_github_body_policies(
            "POST", "/repos/o/r/pulls/1/reviews", b"not json", "application/json", ""
        )
        assert result is not None

    def test_non_close_patch_allowed(self):
        body = json.dumps({"title": "Updated"}).encode()
        result = check_github_body_policies(
            "PATCH", "/repos/o/r/pulls/1", body, "application/json", ""
        )
        assert result is None

    def test_get_method_always_allowed(self):
        result = check_github_body_policies(
            "GET", "/repos/o/r/pulls/1", None, "", ""
        )
        assert result is None

    def test_bom_stripped_from_body(self):
        body = b"\xef\xbb\xbf" + json.dumps({"state": "closed"}).encode()
        result = check_github_body_policies(
            "PATCH", "/repos/o/r/pulls/1", body, "application/json", ""
        )
        assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
