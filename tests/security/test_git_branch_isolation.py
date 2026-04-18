"""Security regression tests for git branch isolation.

Verifies that known leak channels (reflog, notes, for-each-ref --format,
log --source, log --decorate, branch -a, show-ref) do not expose another
sandbox's private branch names.

Converted from the shell-script version (test_git_branch_isolation.sh) to
pytest for consistent CI collection and better failure diagnostics.
"""

import os
import sys

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from branch_isolation import validate_branch_isolation
from branch_output_filter import filter_ref_listing_output

pytestmark = [pytest.mark.security]

SANDBOX_A = "sandbox/alice"
SANDBOX_B = "sandbox/bob"
META_A = {"sandbox_branch": SANDBOX_A}


# ---------------------------------------------------------------------------
# Reflog isolation
# ---------------------------------------------------------------------------


class TestReflogIsolation:
    """Reflog commands must not expose cross-sandbox refs."""

    def test_blocks_cross_sandbox_ref(self):
        err = validate_branch_isolation(["reflog", "show", SANDBOX_B], META_A)
        assert err is not None, "reflog should block cross-sandbox ref"

    def test_allows_own_branch(self):
        err = validate_branch_isolation(["reflog", "show", SANDBOX_A], META_A)
        assert err is None, "reflog should allow own branch"

    def test_blocks_cross_sandbox_via_refs_heads(self):
        err = validate_branch_isolation(
            ["reflog", "show", f"refs/heads/{SANDBOX_B}"], META_A
        )
        assert err is not None, "reflog should block cross-sandbox via refs/heads"


# ---------------------------------------------------------------------------
# Notes isolation
# ---------------------------------------------------------------------------


class TestNotesIsolation:
    """Notes --ref must not allow cross-sandbox branch access."""

    def test_blocks_ref_to_cross_sandbox_branch(self):
        err = validate_branch_isolation(
            ["notes", f"--ref={SANDBOX_B}", "list"], META_A
        )
        assert err is not None, "notes --ref should block cross-sandbox branch"

    def test_allows_ref_to_own_branch(self):
        err = validate_branch_isolation(
            ["notes", f"--ref={SANDBOX_A}", "list"], META_A
        )
        assert err is None, "notes --ref should allow own branch"


# ---------------------------------------------------------------------------
# for-each-ref output filtering
# ---------------------------------------------------------------------------


class TestForEachRefFiltering:
    """for-each-ref output must hide cross-sandbox branches."""

    def test_hides_cross_sandbox_branch(self):
        output = (
            f"abc1234 refs/heads/{SANDBOX_A}\n"
            f"def5678 refs/heads/{SANDBOX_B}\n"
            f"111aaaa refs/tags/v1.0\n"
        )
        result = filter_ref_listing_output(output, ["for-each-ref"], SANDBOX_A)
        assert f"refs/heads/{SANDBOX_B}" not in result
        assert f"refs/heads/{SANDBOX_A}" in result
        assert "refs/tags/v1.0" in result

    def test_full_refs_heads_path_hides_cross_sandbox(self):
        output = (
            f"refs/heads/{SANDBOX_A}\n"
            f"refs/heads/{SANDBOX_B}\n"
            f"refs/heads/main\n"
        )
        result = filter_ref_listing_output(
            output, ["for-each-ref", "--format=%(refname)"], SANDBOX_A
        )
        assert f"refs/heads/{SANDBOX_B}" not in result
        assert f"refs/heads/{SANDBOX_A}" in result


# ---------------------------------------------------------------------------
# log --source filtering
# ---------------------------------------------------------------------------


class TestLogSourceFiltering:
    """log --source output must redact cross-sandbox branch names."""

    def test_redacts_cross_sandbox_branch_name(self):
        output = f"abc1234\trefs/heads/{SANDBOX_B}\tcommit msg\n"
        result = filter_ref_listing_output(output, ["log", "--source"], SANDBOX_A)
        assert SANDBOX_B not in result
        assert "[redacted]" in result

    def test_preserves_own_branch(self):
        output = f"abc1234\trefs/heads/{SANDBOX_A}\tcommit msg\n"
        result = filter_ref_listing_output(output, ["log", "--source"], SANDBOX_A)
        assert SANDBOX_A in result


# ---------------------------------------------------------------------------
# log --decorate filtering
# ---------------------------------------------------------------------------


class TestLogDecorateFiltering:
    """log --decorate output must hide cross-sandbox decorations."""

    def test_hides_cross_sandbox_decoration(self):
        output = f"abc1234 (HEAD -> {SANDBOX_A}, origin/{SANDBOX_B}) msg\n"
        result = filter_ref_listing_output(
            output, ["log", "--oneline", "--decorate"], SANDBOX_A
        )
        assert SANDBOX_B not in result
        assert f"HEAD -> {SANDBOX_A}" in result


# ---------------------------------------------------------------------------
# branch -a output filtering
# ---------------------------------------------------------------------------


class TestBranchListFiltering:
    """branch -a output must hide cross-sandbox branches."""

    def test_hides_cross_sandbox_branch(self):
        output = f"* {SANDBOX_A}\n  {SANDBOX_B}\n  main\n"
        result = filter_ref_listing_output(output, ["branch", "-a"], SANDBOX_A)
        assert SANDBOX_B not in result
        assert SANDBOX_A in result
        assert "main" in result


# ---------------------------------------------------------------------------
# show-ref output filtering
# ---------------------------------------------------------------------------


class TestShowRefFiltering:
    """show-ref output must hide cross-sandbox refs."""

    def test_hides_cross_sandbox_ref(self):
        output = (
            f"abc1234 refs/heads/{SANDBOX_A}\n"
            f"def5678 refs/heads/{SANDBOX_B}\n"
        )
        result = filter_ref_listing_output(output, ["show-ref"], SANDBOX_A)
        assert f"refs/heads/{SANDBOX_B}" not in result
        assert f"refs/heads/{SANDBOX_A}" in result
