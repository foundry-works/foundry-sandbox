"""Unit tests for deep policy rule engine, circuit breaker, and policy loading."""

import json
import threading

import pytest

from foundry_git_safety.deep_policy_engine import (
    CircuitBreaker,
    CompiledRule,
    PolicySet,
    _check_condition,
    _match_body,
    _strip_graphql_comments,
    _traverse_jsonpath,
)
from foundry_git_safety.schemas.foundry_yaml import (
    DeepPolicyConfig,
    DeepPolicyRule,
    DeepPolicyServiceConfig,
)


# ── jsonpath traversal ────────────────────────────────────────


class TestTraverseJsonpath:
    def test_top_level_key(self):
        assert _traverse_jsonpath({"state": "open"}, "state") == "open"

    def test_nested_key(self):
        data = {"a": {"b": {"c": 42}}}
        assert _traverse_jsonpath(data, "a.b.c") == 42

    def test_missing_key_returns_none(self):
        assert _traverse_jsonpath({"x": 1}, "y") is None

    def test_missing_intermediate_returns_none(self):
        assert _traverse_jsonpath({"a": 1}, "a.b") is None

    def test_empty_path_returns_none(self):
        assert _traverse_jsonpath({"x": 1}, "") is None

    def test_non_dict_intermediate_returns_none(self):
        assert _traverse_jsonpath({"a": "string"}, "a.b") is None


# ── body matching ─────────────────────────────────────────────


class TestMatchBody:
    def _make_rule(self, **kwargs):
        defaults = {
            "path_pattern": "/test",
            "action": "deny",
            "body_jsonpath": "state",
            "body_value": "open",
        }
        defaults.update(kwargs)
        return CompiledRule(DeepPolicyRule(**defaults))

    def test_exact_value_match(self):
        rule = self._make_rule(body_value="open")
        assert _match_body("open", rule) is True

    def test_exact_value_mismatch(self):
        rule = self._make_rule(body_value="closed")
        assert _match_body("open", rule) is False

    def test_pattern_match(self):
        rule = self._make_rule(body_value="", body_pattern=r"merge\w+")
        assert _match_body("mergePullRequest", rule) is True

    def test_pattern_no_match(self):
        rule = self._make_rule(body_value="", body_pattern=r"merge\w+")
        assert _match_body("createIssue", rule) is False

    def test_no_jsonpath_always_matches(self):
        rule = self._make_rule(body_jsonpath="", body_value="", body_pattern="")
        assert _match_body("anything", rule) is True

    def test_none_actual_returns_false(self):
        rule = self._make_rule(body_value="open")
        assert _match_body(None, rule) is False


# ── condition checking ────────────────────────────────────────


class TestCheckCondition:
    def test_empty_condition_passes(self):
        assert _check_condition("", {}) is True

    def test_equals_true(self):
        assert _check_condition("allow_pr == true", {"allow_pr": "true"}) is True

    def test_allow_pr_operations_alias(self):
        assert _check_condition(
            "allow_pr_operations == true",
            {"allow_pr_operations": "true"},
        ) is True

    def test_equals_false(self):
        assert _check_condition("allow_pr == false", {"allow_pr": "true"}) is False

    def test_not_equals(self):
        assert _check_condition("allow_pr != true", {"allow_pr": "false"}) is True

    def test_missing_key_treated_as_empty(self):
        # Missing key resolves to "" which doesn't match "false"
        assert _check_condition("allow_pr == false", {}) is False
        # But empty string matches empty string
        assert _check_condition("allow_pr == ", {}) is True

    def test_unknown_operator_passes(self):
        assert _check_condition("allow_pr >= 5", {}) is True


# ── GraphQL comment stripping ─────────────────────────────────


class TestStripGraphqlComments:
    def test_strip_line_comment(self):
        query = "{ viewer { login } # this is a comment\n}"
        result = _strip_graphql_comments(query)
        assert "#" not in result
        assert "login" in result

    def test_preserve_string_literal(self):
        query = '{ search(query: "repo:foo#bar") { nodes } }'
        result = _strip_graphql_comments(query)
        assert "repo:foo#bar" in result

    def test_preserve_triple_quoted_string(self):
        query = '{ search(query: """a#b""") { nodes } }'
        result = _strip_graphql_comments(query)
        assert "a#b" in result


# ── PolicySet evaluation ──────────────────────────────────────


def _make_service(rules, default_action="deny", **kwargs):
    defaults = {
        "slug": "test-svc",
        "host": "api.example.com",
    }
    defaults.update(kwargs)
    return DeepPolicyServiceConfig(
        rules=[DeepPolicyRule(**r) for r in rules],
        default_action=default_action,
        **defaults,
    )


class TestPolicySetEvaluate:
    def test_deny_rule_matches(self):
        svc = _make_service([
            {"method": "DELETE", "path_pattern": r"^/repos/.+$", "action": "deny",
             "reason": "deletion blocked", "priority": 100},
        ])
        ps = PolicySet("test-svc", svc)
        allowed, reason = ps.evaluate("DELETE", "/repos/owner/repo")
        assert allowed is False
        assert "deletion blocked" in reason

    def test_allow_rule_matches(self):
        svc = _make_service([
            {"method": "GET", "path_pattern": r"^/repos/.+$", "action": "allow",
             "priority": 10},
        ])
        ps = PolicySet("test-svc", svc)
        allowed, reason = ps.evaluate("GET", "/repos/owner/repo")
        assert allowed is True
        assert reason is None

    def test_deny_wins_over_allow_on_same_priority(self):
        svc = _make_service([
            {"method": "GET", "path_pattern": r"^/test$", "action": "allow",
             "priority": 10},
            {"method": "GET", "path_pattern": r"^/test$", "action": "deny",
             "reason": "blocked", "priority": 10},
        ])
        ps = PolicySet("test-svc", svc)
        allowed, reason = ps.evaluate("GET", "/test")
        assert allowed is False

    def test_higher_priority_evaluated_first(self):
        svc = _make_service([
            {"method": "*", "path_pattern": r"^/.*$", "action": "allow",
             "priority": 1},
            {"method": "DELETE", "path_pattern": r"^/.*$", "action": "deny",
             "reason": "no deletes", "priority": 100},
        ])
        ps = PolicySet("test-svc", svc)
        allowed, reason = ps.evaluate("DELETE", "/anything")
        assert allowed is False
        assert "no deletes" in reason

    def test_no_match_uses_default_deny(self):
        svc = _make_service([], default_action="deny")
        ps = PolicySet("test-svc", svc)
        allowed, reason = ps.evaluate("GET", "/unknown")
        assert allowed is False

    def test_no_match_uses_default_allow(self):
        svc = _make_service([], default_action="allow")
        ps = PolicySet("test-svc", svc)
        allowed, reason = ps.evaluate("GET", "/unknown")
        assert allowed is True

    def test_query_string_stripped(self):
        svc = _make_service([
            {"method": "GET", "path_pattern": r"^/repos/[^/]+$", "action": "allow",
             "priority": 10},
        ])
        ps = PolicySet("test-svc", svc)
        allowed, _ = ps.evaluate("GET", "/repos/owner?per_page=10")
        assert allowed is True

    def test_wildcard_method_matches_all(self):
        svc = _make_service([
            {"method": "*", "path_pattern": r"^/health$", "action": "allow",
             "priority": 10},
        ])
        ps = PolicySet("test-svc", svc)
        for method in ("GET", "POST", "PUT", "DELETE"):
            allowed, _ = ps.evaluate(method, "/health")
            assert allowed is True

    def test_body_jsonpath_match(self):
        svc = _make_service([
            {"method": "PATCH", "path_pattern": r"^/pulls/\d+$", "action": "deny",
             "reason": "reopen blocked", "priority": 100,
             "body_jsonpath": "state", "body_value": "open"},
        ])
        ps = PolicySet("test-svc", svc)
        body = json.dumps({"state": "open"}).encode()
        allowed, reason = ps.evaluate("PATCH", "/pulls/123", body=body)
        assert allowed is False
        assert "reopen" in reason

    def test_body_jsonpath_no_match(self):
        svc = _make_service([
            {"method": "PATCH", "path_pattern": r"^/pulls/\d+$", "action": "deny",
             "reason": "reopen blocked", "priority": 100,
             "body_jsonpath": "state", "body_value": "open"},
        ])
        ps = PolicySet("test-svc", svc)
        body = json.dumps({"state": "closed", "title": "fix"}).encode()
        allowed, reason = ps.evaluate("PATCH", "/pulls/123", body=body)
        # Deny rule didn't match body, fall through to default
        assert allowed is False

    def test_body_pattern_match(self):
        svc = _make_service([
            {"method": "POST", "path_pattern": r"^/graphql$", "action": "deny",
             "reason": "mutation blocked", "priority": 90,
             "body_jsonpath": "query", "body_pattern": r"\bmergePullRequest\s*\("},
        ])
        ps = PolicySet("test-svc", svc)
        body = json.dumps({"query": "mutation { mergePullRequest(input: {}) }"}).encode()
        allowed, reason = ps.evaluate("POST", "/graphql", body=body)
        assert allowed is False

    def test_pr_review_approve_blocked(self):
        svc = _make_service([
            {"method": "POST", "path_pattern": r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews$",
             "action": "deny", "priority": 95,
             "body_jsonpath": "event", "body_value": "APPROVE",
             "reason": "Self-approving pull requests is blocked by policy"},
            {"method": "POST", "path_pattern": r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews$",
             "action": "allow", "priority": 10},
        ])
        ps = PolicySet("test-svc", svc)
        # APPROVE event blocked
        body = json.dumps({"event": "APPROVE", "body": "LGTM"}).encode()
        allowed, reason = ps.evaluate("POST", "/repos/o/r/pulls/1/reviews", body=body)
        assert allowed is False
        assert "Self-approving" in reason
        # COMMENT event allowed (deny rule doesn't match)
        body2 = json.dumps({"event": "COMMENT", "body": "nit"}).encode()
        allowed2, _ = ps.evaluate("POST", "/repos/o/r/pulls/1/reviews", body=body2)
        assert allowed2 is True

    def test_condition_skips_rule(self):
        svc = _make_service([
            {"method": "POST", "path_pattern": r"^/pulls$", "action": "deny",
             "reason": "PR blocked", "priority": 50,
             "condition": "allow_pr == false"},
            {"method": "POST", "path_pattern": r"^/pulls$", "action": "allow",
             "priority": 10},
        ])
        ps = PolicySet("test-svc", svc)
        # Condition met: deny applies
        allowed, _ = ps.evaluate("POST", "/pulls", context={"allow_pr": "false"})
        assert allowed is False
        # Condition not met: deny skipped, allow applies
        allowed, _ = ps.evaluate("POST", "/pulls", context={"allow_pr": "true"})
        assert allowed is True

    def test_graphql_comment_stripping_in_query(self):
        svc = _make_service([
            {"method": "POST", "path_pattern": r"^/graphql$", "action": "deny",
             "reason": "mutation blocked", "priority": 90,
             "body_jsonpath": "query", "body_pattern": r"\bmergePullRequest\s*\("},
        ])
        ps = PolicySet("test-svc", svc)
        query = "mutation { # dangerous\n mergePullRequest(input: {}) }"
        body = json.dumps({"query": query}).encode()
        allowed, reason = ps.evaluate("POST", "/graphql", body=body)
        assert allowed is False

    def test_unparseable_body_fails_closed_on_deny(self):
        svc = _make_service([
            {"method": "POST", "path_pattern": r"^/graphql$", "action": "deny",
             "reason": "mutation blocked", "priority": 90,
             "body_jsonpath": "query", "body_pattern": r"merge"},
        ])
        ps = PolicySet("test-svc", svc)
        allowed, reason = ps.evaluate("POST", "/graphql", body=b"not json{{{")
        assert allowed is False


# ── CircuitBreaker ────────────────────────────────────────────


class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker()
        assert cb.get_state("svc") == "closed"
        assert cb.is_open("svc") is False

    def test_opens_after_threshold_failures(self):
        cb = CircuitBreaker(threshold=3, recovery_seconds=60)
        cb.record_failure("svc")
        cb.record_failure("svc")
        assert cb.get_state("svc") == "closed"
        cb.record_failure("svc")
        assert cb.get_state("svc") == "open"
        assert cb.is_open("svc") is True

    def test_success_resets_to_closed(self):
        cb = CircuitBreaker(threshold=2, recovery_seconds=60)
        cb.record_failure("svc")
        cb.record_failure("svc")
        assert cb.get_state("svc") == "open"
        cb.record_success("svc")
        assert cb.get_state("svc") == "closed"

    def test_recovery_to_half_open(self):
        cb = CircuitBreaker(threshold=1, recovery_seconds=0)
        cb.record_failure("svc")
        assert cb.get_state("svc") == "open"
        # recovery_seconds=0 means immediate half-open
        assert cb.is_open("svc") is False
        assert cb.get_state("svc") == "half-open"

    def test_half_open_failure_reopens(self):
        cb = CircuitBreaker(threshold=1, recovery_seconds=0)
        cb.record_failure("svc")
        cb.is_open("svc")  # triggers transition to half-open
        cb.record_failure("svc")
        assert cb.get_state("svc") == "open"

    def test_per_slug_isolation(self):
        cb = CircuitBreaker(threshold=1, recovery_seconds=60)
        cb.record_failure("svc-a")
        assert cb.get_state("svc-a") == "open"
        assert cb.get_state("svc-b") == "closed"

    def test_thread_safety(self):
        cb = CircuitBreaker(threshold=100, recovery_seconds=60)
        errors = []

        def worker():
            try:
                for _ in range(100):
                    cb.record_failure("svc")
                    cb.is_open("svc")
                    cb.record_success("svc")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors


# ── Policy loading ────────────────────────────────────────────


class TestPolicyLoading:
    def test_load_bundled_github_default(self):
        from foundry_git_safety.deep_policy_engine import load_policy_sets

        cfg = DeepPolicyConfig(
            enabled=True,
            policy_file="bundled://github-default",
        )
        policy_sets, services = load_policy_sets(cfg)
        assert "github" in policy_sets
        assert policy_sets["github"].rule_count > 0
        assert policy_sets["github"].host == "api.github.com"
        assert policy_sets["github"].default_action == "deny"

    def test_load_inline_services(self):
        from foundry_git_safety.deep_policy_engine import load_policy_sets

        cfg = DeepPolicyConfig(
            enabled=True,
            services=[
                DeepPolicyServiceConfig(
                    slug="myapi",
                    host="api.example.com",
                    rules=[
                        DeepPolicyRule(
                            method="GET",
                            path_pattern=r"^/v1/.*$",
                            action="allow",
                            priority=10,
                        ),
                    ],
                    default_action="deny",
                ),
            ],
        )
        policy_sets, services = load_policy_sets(cfg)
        assert "myapi" in policy_sets
        ps = policy_sets["myapi"]
        allowed, _ = ps.evaluate("GET", "/v1/resources")
        assert allowed is True
        allowed, _ = ps.evaluate("DELETE", "/v1/resources")
        assert allowed is False

    def test_missing_bundled_policy_raises(self):
        from foundry_git_safety.deep_policy_engine import _load_bundled_policy

        with pytest.raises(FileNotFoundError):
            _load_bundled_policy("nonexistent")

    def test_invalid_policy_file_returns_empty(self):
        from foundry_git_safety.deep_policy_engine import load_policy_sets

        cfg = DeepPolicyConfig(
            enabled=True,
            policy_file="/nonexistent/path.yaml",
        )
        policy_sets, services = load_policy_sets(cfg)
        assert len(policy_sets) == 0
