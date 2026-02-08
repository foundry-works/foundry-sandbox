"""Integration tests for branch isolation between sandboxes.

End-to-end tests verifying that two sandboxes on the same repo
cannot see each other's branches — both via command validation
(blocked refs) and output filtering (hidden refs).

Tests cover:
- Cross-sandbox ref blocking for log/show/diff/cherry-pick/fetch/worktree add
- Output filtering for branch -a, show-ref, for-each-ref, log --decorate
- Legacy startup without sandbox_branch metadata fails closed
- Fetch/pull deny when refspec targets another sandbox
"""

import os
import sys
from unittest import mock

import pytest

# conftest.py handles mitmproxy mocking and path setup

from branch_isolation import (
    filter_ref_listing_output,
    validate_branch_isolation,
)


# Two sandboxes sharing a repo
SANDBOX_A = "sandbox/alice"
SANDBOX_B = "sandbox/bob"
META_A = {"sandbox_branch": SANDBOX_A}
META_B = {"sandbox_branch": SANDBOX_B}


class TestCrossSandboxBlocking:
    """Verify that sandbox A cannot reference sandbox B's branch and vice versa."""

    @pytest.mark.parametrize("command", [
        "log", "show", "diff", "blame", "cherry-pick", "rev-list",
    ])
    def test_ref_reading_blocked_cross_sandbox(self, command):
        # A cannot read B's branch
        err = validate_branch_isolation([command, SANDBOX_B], META_A)
        assert err is not None, f"{command} should block {SANDBOX_B} for sandbox A"
        assert SANDBOX_B in err.reason

        # B cannot read A's branch
        err = validate_branch_isolation([command, SANDBOX_A], META_B)
        assert err is not None, f"{command} should block {SANDBOX_A} for sandbox B"
        assert SANDBOX_A in err.reason

    @pytest.mark.parametrize("command", [
        "log", "show", "diff", "blame", "cherry-pick", "rev-list",
    ])
    def test_ref_reading_allowed_own_branch(self, command):
        assert validate_branch_isolation([command, SANDBOX_A], META_A) is None
        assert validate_branch_isolation([command, SANDBOX_B], META_B) is None

    @pytest.mark.parametrize("command", [
        "log", "show", "diff", "blame",
    ])
    def test_ref_reading_allowed_well_known(self, command):
        assert validate_branch_isolation([command, "main"], META_A) is None
        assert validate_branch_isolation([command, "master"], META_B) is None

    def test_worktree_add_blocked_cross_sandbox(self):
        err = validate_branch_isolation(
            ["worktree", "add", "/tmp/wt", SANDBOX_B], META_A
        )
        assert err is not None
        assert SANDBOX_B in err.reason

    def test_fetch_blocked_cross_sandbox(self):
        err = validate_branch_isolation(
            ["fetch", "origin", SANDBOX_B], META_A
        )
        assert err is not None

    def test_fetch_allowed_own_branch(self):
        assert validate_branch_isolation(
            ["fetch", "origin", SANDBOX_A], META_A
        ) is None

    def test_checkout_blocked_cross_sandbox(self):
        err = validate_branch_isolation(["checkout", SANDBOX_B], META_A)
        assert err is not None

    def test_checkout_allowed_own_branch(self):
        assert validate_branch_isolation(["checkout", SANDBOX_A], META_A) is None


class TestCrossSandboxOutputFiltering:
    """Verify output filtering hides cross-sandbox branches."""

    def test_branch_a_listing_hides_b(self):
        output = (
            f"* {SANDBOX_A}\n"
            f"  {SANDBOX_B}\n"
            "  main\n"
            "  develop\n"
        )
        result = filter_ref_listing_output(output, ["branch", "-a"], SANDBOX_A)
        assert SANDBOX_A in result
        assert "main" in result
        assert "develop" in result
        assert SANDBOX_B not in result

    def test_branch_b_listing_hides_a(self):
        output = (
            f"  {SANDBOX_A}\n"
            f"* {SANDBOX_B}\n"
            "  main\n"
        )
        result = filter_ref_listing_output(output, ["branch", "-a"], SANDBOX_B)
        assert SANDBOX_B in result
        assert "main" in result
        assert SANDBOX_A not in result

    def test_show_ref_hides_cross_sandbox(self):
        output = (
            f"abc1234 refs/heads/{SANDBOX_A}\n"
            f"def5678 refs/heads/{SANDBOX_B}\n"
            "111aaaa refs/heads/main\n"
            "222bbbb refs/tags/v1.0\n"
        )
        result_a = filter_ref_listing_output(output, ["show-ref", "--heads"], SANDBOX_A)
        assert f"refs/heads/{SANDBOX_A}" in result_a
        assert f"refs/heads/{SANDBOX_B}" not in result_a
        assert "refs/heads/main" in result_a

        result_b = filter_ref_listing_output(output, ["show-ref", "--heads"], SANDBOX_B)
        assert f"refs/heads/{SANDBOX_B}" in result_b
        assert f"refs/heads/{SANDBOX_A}" not in result_b

    def test_for_each_ref_hides_cross_sandbox(self):
        output = (
            f"abc1234 refs/heads/{SANDBOX_A}\n"
            f"def5678 refs/heads/{SANDBOX_B}\n"
            "111aaaa refs/tags/v1.0\n"
        )
        result = filter_ref_listing_output(output, ["for-each-ref"], SANDBOX_A)
        assert f"refs/heads/{SANDBOX_A}" in result
        assert "refs/tags/v1.0" in result
        assert f"refs/heads/{SANDBOX_B}" not in result

    def test_log_decorate_hides_cross_sandbox(self):
        output = (
            f"abc1234 (HEAD -> {SANDBOX_A}, origin/{SANDBOX_B}) commit msg\n"
            "def5678 normal commit\n"
        )
        result = filter_ref_listing_output(output, ["log", "--oneline", "--decorate"], SANDBOX_A)
        assert f"HEAD -> {SANDBOX_A}" in result
        assert SANDBOX_B not in result
        assert "normal commit" in result


class TestLegacyFailClosed:
    """Legacy startup without sandbox_branch fails closed (blocks all refs)."""

    def test_no_sandbox_branch_fails_closed(self):
        # Without sandbox_branch in metadata, isolation blocks commands
        meta_legacy = {"other_key": "value"}
        err = validate_branch_isolation(["log", SANDBOX_B], meta_legacy)
        assert err is not None
        assert "missing sandbox_branch" in err.reason

    def test_none_metadata_allows_all(self):
        assert validate_branch_isolation(["log", SANDBOX_B], None) is None

    def test_empty_metadata_fails_closed(self):
        err = validate_branch_isolation(["log", SANDBOX_B], {})
        assert err is not None
        assert "missing sandbox_branch" in err.reason


class TestFetchPullDeny:
    """Fetch/pull deny when refspec targets another sandbox."""

    def test_fetch_refspec_source_denied(self):
        err = validate_branch_isolation(
            ["fetch", "origin", f"+{SANDBOX_B}:refs/heads/{SANDBOX_B}"], META_A
        )
        assert err is not None

    def test_fetch_refspec_destination_denied(self):
        err = validate_branch_isolation(
            ["fetch", "origin", f"+main:refs/heads/{SANDBOX_B}"], META_A
        )
        assert err is not None

    def test_pull_cross_sandbox_denied(self):
        err = validate_branch_isolation(
            ["pull", "origin", SANDBOX_B], META_A
        )
        assert err is not None

    def test_pull_own_branch_allowed(self):
        assert validate_branch_isolation(
            ["pull", "origin", SANDBOX_A], META_A
        ) is None

    def test_fetch_no_refspec_allowed(self):
        # Just `fetch origin` without refspec is allowed
        assert validate_branch_isolation(
            ["fetch", "origin"], META_A
        ) is None


class TestPushCrossSandboxBlocking:
    """Push isolation: sandbox A cannot push to sandbox B's branch."""

    def test_push_cross_sandbox_blocked(self):
        err = validate_branch_isolation(
            ["push", "origin", SANDBOX_B], META_A
        )
        assert err is not None
        assert SANDBOX_B in err.reason

    def test_push_own_branch_allowed(self):
        assert validate_branch_isolation(
            ["push", "origin", SANDBOX_A], META_A
        ) is None

    def test_push_refspec_cross_sandbox_blocked(self):
        err = validate_branch_isolation(
            ["push", "origin", f"{SANDBOX_A}:{SANDBOX_B}"], META_A
        )
        assert err is not None

    def test_push_delete_cross_sandbox_blocked(self):
        err = validate_branch_isolation(
            ["push", "origin", f":{SANDBOX_B}"], META_A
        )
        assert err is not None

    def test_push_all_blocked(self):
        err = validate_branch_isolation(
            ["push", "--all", "origin"], META_A
        )
        assert err is not None

    def test_push_mirror_blocked(self):
        err = validate_branch_isolation(
            ["push", "--mirror", "origin"], META_A
        )
        assert err is not None

    def test_push_bidirectional_blocking(self):
        """Both directions are blocked."""
        err_a = validate_branch_isolation(
            ["push", "origin", SANDBOX_B], META_A
        )
        err_b = validate_branch_isolation(
            ["push", "origin", SANDBOX_A], META_B
        )
        assert err_a is not None
        assert err_b is not None
