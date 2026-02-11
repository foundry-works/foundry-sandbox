"""Unit tests for the policy engine addon.

Tests normalize_path(), PolicyDecision, and PolicyEngine's GitHub blocklist
and body inspection methods.
"""

import pytest

from addons.policy_engine import normalize_path, PolicyDecision, PolicyEngine


class TestNormalizePath:
    def test_simple_path(self):
        assert normalize_path("/repos/foo/bar") == "/repos/foo/bar"

    def test_strips_query_string(self):
        assert normalize_path("/repos/foo?page=1") == "/repos/foo"

    def test_strips_fragment(self):
        assert normalize_path("/repos/foo#section") == "/repos/foo"

    def test_url_decodes_once(self):
        assert normalize_path("/repos/foo%20bar") == "/repos/foo bar"

    def test_rejects_double_encoding(self):
        result = normalize_path("/repos/foo%2520bar")
        assert result is None

    def test_collapses_double_slashes(self):
        assert normalize_path("/repos//foo///bar") == "/repos/foo/bar"

    def test_resolves_dot_dot(self):
        assert normalize_path("/repos/foo/../bar") == "/repos/bar"

    def test_strips_trailing_slash(self):
        assert normalize_path("/repos/foo/") == "/repos/foo"

    def test_root_path(self):
        assert normalize_path("/") == "/"


class TestGitHubBlocklist:
    def test_blocks_pr_merge(self):
        engine = PolicyEngine()
        result = engine._check_github_blocklist("PUT", "/repos/owner/repo/pulls/123/merge")
        assert result is not None

    def test_blocks_release_creation(self):
        engine = PolicyEngine()
        result = engine._check_github_blocklist("POST", "/repos/owner/repo/releases")
        assert result is not None

    def test_blocks_auto_merge(self):
        engine = PolicyEngine()
        result = engine._check_github_blocklist("PUT", "/repos/o/r/pulls/1/auto-merge")
        assert result is not None

    def test_blocks_review_deletion(self):
        engine = PolicyEngine()
        result = engine._check_github_blocklist("DELETE", "/repos/o/r/pulls/1/reviews/42")
        assert result is not None

    def test_blocks_git_ref_creation(self):
        engine = PolicyEngine()
        result = engine._check_github_blocklist("POST", "/repos/o/r/git/refs")
        assert result is not None

    def test_allows_get_on_blocked_paths(self):
        engine = PolicyEngine()
        assert engine._check_github_blocklist("GET", "/repos/o/r/pulls/1/merge") is None

    def test_allows_normal_api_paths(self):
        engine = PolicyEngine()
        assert engine._check_github_blocklist("GET", "/repos/o/r/issues") is None


class TestBodyInspection:
    def test_blocks_pr_close_via_state(self):
        engine = PolicyEngine()
        body = b'{"state": "closed"}'
        result = engine._check_github_body_policies(
            "PATCH", "/repos/o/r/pulls/1", body, "application/json", "")
        assert result is not None

    def test_blocks_issue_close_via_state(self):
        engine = PolicyEngine()
        body = b'{"state": "closed"}'
        result = engine._check_github_body_policies(
            "PATCH", "/repos/o/r/issues/1", body, "application/json", "")
        assert result is not None

    def test_blocks_pr_approval(self):
        engine = PolicyEngine()
        body = b'{"event": "APPROVE"}'
        result = engine._check_github_body_policies(
            "POST", "/repos/o/r/pulls/1/reviews", body, "application/json", "")
        assert result is not None

    def test_allows_pr_comment(self):
        engine = PolicyEngine()
        body = b'{"event": "COMMENT"}'
        result = engine._check_github_body_policies(
            "POST", "/repos/o/r/pulls/1/reviews", body, "application/json", "")
        assert result is None

    def test_allows_state_open(self):
        engine = PolicyEngine()
        body = b'{"state": "open"}'
        result = engine._check_github_body_policies(
            "PATCH", "/repos/o/r/pulls/1", body, "application/json", "")
        assert result is None


class TestPolicyDecision:
    def test_to_dict_contains_required_fields(self):
        d = PolicyDecision(allowed=True, reason="allowed", policy_type="domain")
        result = d.to_dict()
        assert result["allowed"] is True
        assert result["reason"] == "allowed"
        assert result["policy_type"] == "domain"
