"""Parity tests: verify bundled GitHub YAML policy matches GitHubAPIChecker.

Every BLOCKED_PATTERNS and ALLOWED_OPERATIONS entry is tested through both
the original hardcoded GitHubAPIChecker and the new PolicySet loaded from
deep-policy-github.yaml, asserting identical allow/deny results.
"""

import json

import pytest

pytestmark = pytest.mark.security

from foundry_git_safety.deep_policy_engine import load_policy_sets
from foundry_git_safety.github_filter import (
    ALLOWED_OPERATIONS,
    BLOCKED_PATTERNS,
    CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS,
    CONDITIONAL_PR_OPERATIONS,
    ALWAYS_BLOCKED_GRAPHQL_MUTATIONS,
    GitHubAPIChecker,
)
from foundry_git_safety.schemas.foundry_yaml import DeepPolicyConfig


def _pattern_to_test_path(pattern: str) -> str:
    """Convert a regex path pattern to a concrete test URL path."""
    replacements = {
        "[^/]+": "owner",
        "\\d+": "123",
        ".*": "anything",
    }
    result = pattern
    for regex, replacement in replacements.items():
        result = result.replace(regex, replacement)
    # Strip regex anchors
    result = result.lstrip("^").rstrip("$")
    return result


@pytest.fixture(scope="module")
def checker():
    return GitHubAPIChecker(allow_pr_operations=False)


@pytest.fixture(scope="module")
def checker_with_pr():
    return GitHubAPIChecker(allow_pr_operations=True)


@pytest.fixture(scope="module")
def policy_set():
    cfg = DeepPolicyConfig(enabled=True, policy_file="bundled://github-default")
    policy_sets, _ = load_policy_sets(cfg)
    return policy_sets["github"]


@pytest.fixture(scope="module")
def policy_set_no_pr(policy_set):
    return policy_set


@pytest.fixture(scope="module")
def policy_set_with_pr(policy_set):
    """Same policy set but with allow_pr_operations context."""
    return policy_set


# ── Blocklist parity ──────────────────────────────────────────


class TestBlocklistParity:
    @pytest.mark.parametrize(
        "method,pattern,reason",
        [(m, p, r) for m, p, r in BLOCKED_PATTERNS],
        ids=[f"{m}-{i}" for i, (m, p, r) in enumerate(BLOCKED_PATTERNS)],
    )
    def test_blocked_entry(self, method, pattern, reason, checker, policy_set):
        test_path = _pattern_to_test_path(pattern)
        # GitHubAPIChecker blocks it
        allowed_checker, _ = checker.check_request(method, test_path)
        assert allowed_checker is False, (
            f"GitHubAPIChecker allowed {method} {test_path} (expected block)"
        )
        # PolicySet also blocks it
        allowed_ps, _ = policy_set.evaluate(method, test_path)
        assert allowed_ps is False, (
            f"PolicySet allowed {method} {test_path} (expected block)"
        )


# ── Allowlist parity ──────────────────────────────────────────


class TestAllowlistParity:
    @pytest.mark.parametrize(
        "method,pattern",
        [(m, p) for m, p in ALLOWED_OPERATIONS],
        ids=[f"{m}-{i}" for i, (m, p) in enumerate(ALLOWED_OPERATIONS)],
    )
    def test_allowed_entry(self, method, pattern, checker, policy_set):
        test_path = _pattern_to_test_path(pattern)
        # GitHubAPIChecker allows it
        allowed_checker, _ = checker.check_request(method, test_path)
        assert allowed_checker is True, (
            f"GitHubAPIChecker denied {method} {test_path} (expected allow)"
        )
        # PolicySet also allows it
        allowed_ps, _ = policy_set.evaluate(method, test_path)
        assert allowed_ps is True, (
            f"PolicySet denied {method} {test_path} (expected allow)"
        )


# ── GraphQL mutation parity ───────────────────────────────────


class TestGraphQLParity:
    @pytest.mark.parametrize(
        "mutation",
        ALWAYS_BLOCKED_GRAPHQL_MUTATIONS,
    )
    def test_always_blocked_mutation(self, mutation, checker, policy_set):
        query = f"mutation {{{mutation}(input: {{}}) {{ id }}}}"
        body = json.dumps({"query": query}).encode()

        allowed_checker, _ = checker.check_request("POST", "/graphql", body)
        assert allowed_checker is False

        allowed_ps, _ = policy_set.evaluate("POST", "/graphql", body)
        assert allowed_ps is False

    @pytest.mark.parametrize(
        "mutation",
        CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS,
    )
    def test_conditional_mutation_blocked_no_pr(self, mutation, checker, policy_set):
        query = f"mutation {{{mutation}(input: {{}}) {{ id }}}}"
        body = json.dumps({"query": query}).encode()

        allowed_checker, _ = checker.check_request("POST", "/graphql", body)
        assert allowed_checker is False

        allowed_ps, _ = policy_set.evaluate(
            "POST", "/graphql", body,
            context={"allow_pr_operations": "false"},
        )
        assert allowed_ps is False

    @pytest.mark.parametrize(
        "mutation",
        CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS,
    )
    def test_conditional_mutation_allowed_with_pr(
        self, mutation, checker_with_pr, policy_set_with_pr,
    ):
        query = f"mutation {{{mutation}(input: {{}}) {{ id }}}}"
        body = json.dumps({"query": query}).encode()

        allowed_checker, _ = checker_with_pr.check_request("POST", "/graphql", body)
        assert allowed_checker is True

        allowed_ps, _ = policy_set_with_pr.evaluate(
            "POST", "/graphql", body,
            context={"allow_pr_operations": "true"},
        )
        assert allowed_ps is True


# ── Conditional PR REST operations parity ──────────────────────


class TestConditionalPRParity:
    @pytest.mark.parametrize(
        "method,pattern",
        [(m, p) for m, p in CONDITIONAL_PR_OPERATIONS],
    )
    def test_pr_ops_blocked_without_flag(self, method, pattern, checker, policy_set):
        test_path = _pattern_to_test_path(pattern)
        allowed_checker, _ = checker.check_request(method, test_path)
        assert allowed_checker is False

        allowed_ps, _ = policy_set.evaluate(
            method, test_path,
            context={"allow_pr_operations": "false"},
        )
        assert allowed_ps is False

    @pytest.mark.parametrize(
        "method,pattern",
        [(m, p) for m, p in CONDITIONAL_PR_OPERATIONS],
    )
    def test_pr_ops_allowed_with_flag(
        self, method, pattern, checker_with_pr, policy_set_with_pr,
    ):
        test_path = _pattern_to_test_path(pattern)
        allowed_checker, _ = checker_with_pr.check_request(method, test_path)
        assert allowed_checker is True

        allowed_ps, _ = policy_set_with_pr.evaluate(
            method, test_path,
            context={"allow_pr_operations": "true"},
        )
        assert allowed_ps is True


# ── Default deny parity ──────────────────────────────────────


class TestDefaultDenyParity:
    def test_unknown_path_denied_both(self, checker, policy_set):
        allowed_checker, _ = checker.check_request("POST", "/unknown/endpoint")
        assert allowed_checker is False

        allowed_ps, _ = policy_set.evaluate("POST", "/unknown/endpoint")
        assert allowed_ps is False
