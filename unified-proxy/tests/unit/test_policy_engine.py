"""Unit tests for the policy engine addon.

Tests normalize_path(), PolicyDecision, and PolicyEngine's GitHub blocklist
and body inspection methods.
"""


from addons.policy_engine import is_ip_literal, normalize_path, PolicyDecision, PolicyEngine


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


class TestIsIpLiteral:
    """Tests for IP literal detection including IPv6."""

    def test_bare_ipv6_loopback(self):
        """Bare ::1 should be detected as IP literal."""
        assert is_ip_literal("::1") is True

    def test_bare_ipv6_full(self):
        """Full IPv6 address should be detected as IP literal."""
        assert is_ip_literal("2001:db8::1") is True

    def test_ipv4_mapped_ipv6(self):
        """IPv4-mapped IPv6 (::ffff:127.0.0.1) should be detected."""
        assert is_ip_literal("::ffff:127.0.0.1") is True

    def test_bracketed_ipv6_still_detected(self):
        """Bracketed IPv6 [::1] should be detected by regex pattern."""
        assert is_ip_literal("[::1]") is True

    def test_regular_hostname_not_ip(self):
        """Regular hostnames should not be detected as IP literals."""
        assert is_ip_literal("github.com") is False

    def test_ipv4_still_detected(self):
        """IPv4 dotted decimal should still be detected."""
        assert is_ip_literal("127.0.0.1") is True


class TestPolicyDecision:
    def test_to_dict_contains_required_fields(self):
        d = PolicyDecision(allowed=True, reason="allowed", policy_type="domain")
        result = d.to_dict()
        assert result["allowed"] is True
        assert result["reason"] == "allowed"
        assert result["policy_type"] == "domain"
