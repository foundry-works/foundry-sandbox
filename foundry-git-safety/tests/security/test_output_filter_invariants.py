"""Verify that no output filter leaks cross-sandbox branch names.

Security invariants under test:
  1. Branch listings never reveal other sandbox branches.
  2. Ref enumeration commands never reveal other sandbox branches.
  3. Log decorations never reveal other sandbox branches.
  4. Stderr filtering removes cross-sandbox refs.
"""

import pytest

from foundry_git_safety.branch_output_filter import (
    _filter_branch_output,
    _filter_custom_format_decorations,
    _filter_decoration_refs,
    _filter_log_decorations,
    _filter_log_source_refs,
    _filter_ref_enum_output,
    filter_ref_listing_output,
    filter_stderr_branch_refs,
)

pytestmark = pytest.mark.security

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

SANDBOX_BRANCH = "sandbox/alice"
BASE_BRANCH = "main"

# Branches that belong to other sandboxes and must NEVER appear in output.
OTHER_BRANCHES = [
    "sandbox/bob",
    "sandbox/charlie",
    "sandbox/dave-evil",
    "sandbox/0day-exploit",
]


def _assert_no_leak(output: str, label: str = "output") -> None:
    """Assert that no OTHER_BRANCHES appear in filtered output."""
    for name in OTHER_BRANCHES:
        assert name not in output, (
            f"{label} leaked cross-sandbox branch {name!r}:\n{output!r}"
        )


# ---------------------------------------------------------------------------
# TestNoCrossSandboxLeakInBranch
# ---------------------------------------------------------------------------


class TestNoCrossSandboxLeakInBranch:
    """git branch variants must not leak other sandbox branch names."""

    def test_branch_a_no_leak(self) -> None:
        """git branch -a must strip remote branches from other sandboxes."""
        raw = "\n".join([
            "* sandbox/alice",
            "  main",
            "  remotes/origin/main",
            "  remotes/origin/sandbox/alice",
            "  remotes/origin/sandbox/bob",
            "  remotes/origin/sandbox/charlie",
        ]) + "\n"
        result = _filter_branch_output(raw, SANDBOX_BRANCH, BASE_BRANCH)
        _assert_no_leak(result)
        assert "sandbox/alice" in result
        assert "main" in result

    def test_branch_verbose_no_leak(self) -> None:
        """git branch -v must not leak other sandbox branches in verbose output."""
        raw = "\n".join([
            "* sandbox/alice  abc1234 Some commit",
            "  main            def5678 Another commit",
            "  sandbox/bob     ghi9012 Evil commit",
        ]) + "\n"
        result = _filter_branch_output(raw, SANDBOX_BRANCH, BASE_BRANCH)
        _assert_no_leak(result)
        assert "sandbox/alice" in result
        assert "main" in result

    def test_branch_show_current_allows_own_branch(self) -> None:
        """git branch --show-current returns the sandbox's own branch."""
        raw = "sandbox/alice\n"
        # filter_ref_listing_output handles --show-current specially
        result = filter_ref_listing_output(
            raw, ["branch", "--show-current"], SANDBOX_BRANCH, BASE_BRANCH,
        )
        assert result == raw

    def test_branch_show_current_blocks_other_branch(self) -> None:
        """git branch --show-current would leak if it returned another
        sandbox's branch — must be cleared."""
        raw = "sandbox/bob\n"
        result = filter_ref_listing_output(
            raw, ["branch", "--show-current"], SANDBOX_BRANCH, BASE_BRANCH,
        )
        assert result == ""


# ---------------------------------------------------------------------------
# TestNoCrossSandboxLeakInRefEnum
# ---------------------------------------------------------------------------


class TestNoCrossSandboxLeakInRefEnum:
    """for-each-ref and show-ref must not leak other sandbox branch names."""

    def test_for_each_ref_no_leak(self) -> None:
        """for-each-ref output must strip refs/heads/<other> lines."""
        raw = "\n".join([
            "refs/heads/main\tabc1234",
            "refs/heads/sandbox/alice\tdef5678",
            "refs/heads/sandbox/bob\tghi9012",
            "refs/heads/sandbox/charlie\tjkl3456",
            "refs/tags/v1.0\tmnop789",
        ]) + "\n"
        result = _filter_ref_enum_output(raw, SANDBOX_BRANCH, BASE_BRANCH)
        _assert_no_leak(result)
        assert "refs/heads/main" in result
        assert "refs/heads/sandbox/alice" in result
        assert "refs/tags/v1.0" in result

    def test_show_ref_no_leak(self) -> None:
        """show-ref output must strip other sandbox branches."""
        raw = "\n".join([
            "abc1234 refs/heads/main",
            "def5678 refs/heads/sandbox/alice",
            "ghi9012 refs/heads/sandbox/bob",
            "jkl3456 refs/heads/release/1.0",
            "mnop789 refs/tags/v1.0",
        ]) + "\n"
        result = _filter_ref_enum_output(raw, SANDBOX_BRANCH, BASE_BRANCH)
        _assert_no_leak(result)
        assert "refs/heads/main" in result
        assert "refs/heads/sandbox/alice" in result
        assert "refs/heads/release/1.0" in result

    def test_for_each_ref_custom_format_no_leak(self) -> None:
        """Custom --format with short refnames must still filter."""
        # Use SHA-like tokens (>=12 hex chars) so the parser enters the
        # SHA-prefixed branch and evaluates the second token as a ref.
        raw = "\n".join([
            "abc1234def567\tmain",
            "def5678abc123\tsandbox/alice",
            "ghi9012jkl345\tsandbox/bob",
            "jkl3456ghi901\tsandbox/charlie",
        ]) + "\n"
        result = _filter_ref_enum_output(raw, SANDBOX_BRANCH, BASE_BRANCH)
        _assert_no_leak(result)
        assert "sandbox/alice" in result

    def test_for_each_ref_remote_refs_no_leak(self) -> None:
        """Remote refs from for-each-ref must also be filtered."""
        raw = "\n".join([
            "abc1234 refs/remotes/origin/main",
            "def5678 refs/remotes/origin/sandbox/alice",
            "ghi9012 refs/remotes/origin/sandbox/bob",
        ]) + "\n"
        result = _filter_ref_enum_output(raw, SANDBOX_BRANCH, BASE_BRANCH)
        _assert_no_leak(result)


# ---------------------------------------------------------------------------
# TestNoCrossSandboxLeakInLog
# ---------------------------------------------------------------------------


class TestNoCrossSandboxLeakInLog:
    """git log --decorate and --source must not leak other sandbox branches."""

    def test_log_decorate_no_leak(self) -> None:
        """Standard --decorate must strip other sandbox refs from parens."""
        # Use valid hex SHAs (>=1 hex char) so _DECORATION_LINE_RE matches.
        raw = "\n".join([
            "abc1234 (HEAD -> sandbox/alice, origin/sandbox/alice) First commit",
            "def5678 (origin/main, origin/sandbox/bob) Second commit",
            "cab9012 (tag: v1.0, origin/sandbox/charlie) Third commit",
        ]) + "\n"
        result = _filter_log_decorations(raw, SANDBOX_BRANCH, BASE_BRANCH)
        _assert_no_leak(result)
        assert "sandbox/alice" in result
        assert "origin/main" in result or "main" in result
        assert "tag: v1.0" in result

    def test_log_custom_format_d_no_leak(self) -> None:
        """Custom --format=%d (parenthesized) must filter decorations."""
        raw = "\n".join([
            " (HEAD -> sandbox/alice, origin/sandbox/bob)",
            " (origin/main, tag: v1.0)",
            " (origin/sandbox/charlie, origin/sandbox/dave-evil)",
        ]) + "\n"
        result = _filter_custom_format_decorations(
            raw, SANDBOX_BRANCH, BASE_BRANCH,
        )
        _assert_no_leak(result)

    def test_log_custom_format_bare_D_no_leak(self) -> None:
        """Custom --format=%D (bare) must filter decorations."""
        raw = "\n".join([
            "HEAD -> sandbox/alice, origin/sandbox/bob",
            "origin/main, tag: v1.0",
            "origin/sandbox/charlie, origin/sandbox/dave-evil",
        ]) + "\n"
        result = _filter_custom_format_decorations(
            raw, SANDBOX_BRANCH, BASE_BRANCH, has_bare_D=True,
        )
        _assert_no_leak(result)

    def test_log_source_no_leak(self) -> None:
        """git log --source must redact disallowed refs/heads/ entries."""
        raw = "\n".join([
            "abc1234\trefs/heads/sandbox/alice\tcommit message one",
            "def5678\trefs/heads/sandbox/bob\tcommit message two",
            "ghi9012\trefs/heads/sandbox/charlie\tcommit message three",
        ]) + "\n"
        result = _filter_log_source_refs(raw, SANDBOX_BRANCH, BASE_BRANCH)
        _assert_no_leak(result)
        assert "sandbox/alice" in result

    def test_decoration_refs_filter_allows_own_branch(self) -> None:
        """_filter_decoration_refs keeps the sandbox's own branch."""
        result = _filter_decoration_refs(
            "HEAD -> sandbox/alice, origin/sandbox/alice",
            SANDBOX_BRANCH,
            BASE_BRANCH,
        )
        assert result is not None
        assert "sandbox/alice" in result

    def test_decoration_refs_filter_removes_all_others(self) -> None:
        """If all decoration refs are disallowed, returns None."""
        result = _filter_decoration_refs(
            "sandbox/bob, sandbox/charlie",
            SANDBOX_BRANCH,
            BASE_BRANCH,
        )
        assert result is None


# ---------------------------------------------------------------------------
# TestNoCrossSandboxLeakInStderr
# ---------------------------------------------------------------------------


class TestNoCrossSandboxLeakInStderr:
    """Stderr filtering must remove cross-sandbox refs."""

    def test_stderr_refs_heads_no_leak(self) -> None:
        """refs/heads/<other> in stderr must be redacted."""
        raw = (
            "error: pathspec 'refs/heads/sandbox/bob' did not match any file"
        )
        result = filter_stderr_branch_refs(raw, SANDBOX_BRANCH, BASE_BRANCH)
        _assert_no_leak(result)
        assert "<redacted>" in result

    def test_stderr_refs_remotes_no_leak(self) -> None:
        """refs/remotes/origin/<other> in stderr must be redacted."""
        raw = (
            "error: src refspec refs/remotes/origin/sandbox/bob does not match any"
        )
        result = filter_stderr_branch_refs(raw, SANDBOX_BRANCH, BASE_BRANCH)
        _assert_no_leak(result)
        assert "<redacted>" in result

    def test_stderr_slashed_quoted_branch_no_leak(self) -> None:
        """Single-quoted slashed branch names in stderr must be redacted."""
        raw = "error: branch 'sandbox/bob' not found."
        result = filter_stderr_branch_refs(raw, SANDBOX_BRANCH, BASE_BRANCH)
        _assert_no_leak(result)
        assert "<redacted>" in result

    def test_stderr_simple_quoted_branch_no_leak(self) -> None:
        """Simple quoted branch names in git error context must be redacted."""
        raw = "error: pathspec 'bobbranch' did not match any file(s) known to git."
        result = filter_stderr_branch_refs(raw, SANDBOX_BRANCH, BASE_BRANCH)
        # 'bobbranch' is not an allowed branch — should be redacted
        assert "bobbranch" not in result

    def test_stderr_preserves_own_branch(self) -> None:
        """Stderr containing the sandbox's own branch should NOT be redacted."""
        raw = "hint: branch 'sandbox/alice' set up to track."
        result = filter_stderr_branch_refs(raw, SANDBOX_BRANCH, BASE_BRANCH)
        assert "sandbox/alice" in result
        assert "<redacted>" not in result

    def test_stderr_preserves_well_known_branches(self) -> None:
        """Well-known branches (main, master) should not be redacted."""
        raw = "hint: branch 'main' set up to track."
        result = filter_stderr_branch_refs(raw, SANDBOX_BRANCH, BASE_BRANCH)
        assert "main" in result
        assert "<redacted>" not in result

    def test_stderr_empty_input_passes_through(self) -> None:
        """Empty stderr returns empty string."""
        assert filter_stderr_branch_refs("", SANDBOX_BRANCH, BASE_BRANCH) == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
