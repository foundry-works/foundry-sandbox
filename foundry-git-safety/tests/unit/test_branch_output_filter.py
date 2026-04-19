"""Tests for foundry_git_safety.branch_output_filter — branch/ref/log output filtering."""

import pytest

from foundry_git_safety.branch_output_filter import (
    filter_ref_listing_output,
    filter_stderr_branch_refs,
)


# ---------------------------------------------------------------------------
# TestFilterBranchOutput
# ---------------------------------------------------------------------------


class TestFilterBranchOutput:
    """Tests for branch listing output filtering via filter_ref_listing_output."""

    def test_hides_cross_sandbox_branch(self):
        """Lines for branches not belonging to this sandbox are removed."""
        output = "* sandbox/alice\n  sandbox/bob\n"
        result = filter_ref_listing_output(output, ["branch"], "sandbox/alice", None)
        assert "sandbox/bob" not in result
        assert "sandbox/alice" in result

    def test_preserves_own_branch(self):
        """The sandbox's own branch line is preserved."""
        output = "* sandbox/alice\n  main\n"
        result = filter_ref_listing_output(output, ["branch"], "sandbox/alice", None)
        assert "sandbox/alice" in result

    def test_preserves_well_known_branches(self):
        """Well-known branches (main, master, develop) are always preserved."""
        output = "  main\n  develop\n  production\n"
        result = filter_ref_listing_output(output, ["branch"], "sandbox/alice", None)
        assert "main" in result
        assert "develop" in result
        assert "production" in result

    def test_preserves_well_known_prefixes_same_prefix(self):
        """release/* branches visible from a release/* sandbox."""
        output = "  release/1.0\n  hotfix/urgent-fix\n"
        result = filter_ref_listing_output(output, ["branch"], "release/my-fix", None)
        assert "release/1.0" in result
        assert "hotfix/urgent-fix" not in result

    def test_well_known_prefixes_cross_prefix_blocked(self):
        """release/* branches NOT visible from a non-release sandbox."""
        output = "  release/1.0\n  hotfix/urgent-fix\n"
        result = filter_ref_listing_output(output, ["branch"], "sandbox/alice", None)
        assert "release/1.0" not in result
        assert "hotfix/urgent-fix" not in result

    def test_empty_output_passthrough(self):
        """Empty string input returns empty string."""
        result = filter_ref_listing_output("", ["branch"], "sandbox/alice", None)
        assert result == ""

    def test_preserves_base_branch(self):
        """The base branch is preserved when provided."""
        output = "  sandbox/alice\n  feature/x\n"
        result = filter_ref_listing_output(
            output, ["branch"], "sandbox/alice", "feature/x"
        )
        assert "feature/x" in result

    def test_show_current_returns_own_branch(self):
        """branch --show-current returns the branch name when it is the sandbox's own."""
        output = "sandbox/alice\n"
        result = filter_ref_listing_output(
            output, ["branch", "--show-current"], "sandbox/alice", None
        )
        assert result == "sandbox/alice\n"

    def test_show_current_hides_other_branch(self):
        """branch --show-current returns empty when the branch is not allowed."""
        output = "sandbox/bob\n"
        result = filter_ref_listing_output(
            output, ["branch", "--show-current"], "sandbox/alice", None
        )
        assert result == ""

    def test_verbose_branch_output_preserved(self):
        """Verbose branch listing (with SHA and message) is preserved for allowed branches."""
        output = "* sandbox/alice abc1234 [origin/sandbox/alice] latest commit\n"
        result = filter_ref_listing_output(output, ["branch"], "sandbox/alice", None)
        assert "sandbox/alice" in result

    def test_remote_branch_listing_keeps_allowed(self):
        """Remote tracking branch lines for allowed branches are preserved."""
        output = "  remotes/origin/sandbox/alice\n  remotes/origin/sandbox/bob\n"
        result = filter_ref_listing_output(output, ["branch"], "sandbox/alice", None)
        assert "remotes/origin/sandbox/alice" in result
        assert "remotes/origin/sandbox/bob" not in result

    def test_head_symref_preserved(self):
        """HEAD -> origin/main symref line is preserved."""
        output = "  remotes/origin/HEAD -> origin/main\n"
        result = filter_ref_listing_output(output, ["branch"], "sandbox/alice", None)
        assert "HEAD -> origin/main" in result


# ---------------------------------------------------------------------------
# TestFilterRefEnumOutput
# ---------------------------------------------------------------------------


class TestFilterRefEnumOutput:
    """Tests for ref enumeration output filtering via filter_ref_listing_output."""

    def test_hides_cross_sandbox_ref(self):
        """Refs belonging to other sandboxes are removed from for-each-ref output."""
        output = "abc123 refs/heads/sandbox/alice\ndef456 refs/heads/sandbox/bob\n"
        result = filter_ref_listing_output(
            output, ["for-each-ref"], "sandbox/alice", None
        )
        assert "refs/heads/sandbox/alice" in result
        assert "refs/heads/sandbox/bob" not in result

    def test_preserves_tags(self):
        """Tag refs are always preserved."""
        output = "abc123 refs/tags/v1.0\n"
        result = filter_ref_listing_output(
            output, ["for-each-ref"], "sandbox/alice", None
        )
        assert "refs/tags/v1.0" in result

    def test_preserves_own_ref(self):
        """The sandbox's own ref is preserved."""
        output = "abc123 refs/heads/sandbox/alice\n"
        result = filter_ref_listing_output(
            output, ["for-each-ref"], "sandbox/alice", None
        )
        assert "refs/heads/sandbox/alice" in result

    def test_preserves_main_ref(self):
        """Well-known branch refs are preserved."""
        output = "abc123 refs/heads/main\n"
        result = filter_ref_listing_output(
            output, ["for-each-ref"], "sandbox/alice", None
        )
        assert "refs/heads/main" in result

    def test_ls_remote_dispatch(self):
        """ls-remote command dispatches to the ref enum filter."""
        output = "abc123 refs/heads/sandbox/alice\ndef456 refs/heads/sandbox/bob\n"
        result = filter_ref_listing_output(
            output, ["ls-remote"], "sandbox/alice", None
        )
        assert "sandbox/alice" in result
        assert "sandbox/bob" not in result

    def test_show_ref_dispatch(self):
        """show-ref command dispatches to the ref enum filter."""
        output = "abc123 refs/heads/sandbox/alice\ndef456 refs/heads/sandbox/bob\n"
        result = filter_ref_listing_output(
            output, ["show-ref"], "sandbox/alice", None
        )
        assert "sandbox/alice" in result
        assert "sandbox/bob" not in result

    def test_empty_output_passthrough(self):
        """Empty output returns empty."""
        result = filter_ref_listing_output(
            "", ["for-each-ref"], "sandbox/alice", None
        )
        assert result == ""


# ---------------------------------------------------------------------------
# TestFilterLogDecorations
# ---------------------------------------------------------------------------


class TestFilterLogDecorations:
    """Tests for log decoration filtering via filter_ref_listing_output."""

    def test_hides_cross_sandbox_decoration(self):
        """Disallowed branch decorations are removed from log output."""
        output = "abc1234 (HEAD -> sandbox/alice, sandbox/bob) commit msg\n"
        result = filter_ref_listing_output(
            output, ["log"], "sandbox/alice", None
        )
        assert "sandbox/bob" not in result
        assert "sandbox/alice" in result

    def test_preserves_own_decoration(self):
        """The sandbox's own branch decoration is preserved."""
        output = "abc1234 (HEAD -> sandbox/alice) commit msg\n"
        result = filter_ref_listing_output(
            output, ["log"], "sandbox/alice", None
        )
        assert "sandbox/alice" in result

    def test_preserves_head(self):
        """HEAD decoration is always preserved."""
        output = "abc1234 (HEAD -> sandbox/alice) commit msg\n"
        result = filter_ref_listing_output(
            output, ["log"], "sandbox/alice", None
        )
        assert "HEAD" in result

    def test_preserves_tag_decoration(self):
        """Tag decorations are always preserved."""
        output = "abc1234 (HEAD -> main, tag: v1.0) commit msg\n"
        result = filter_ref_listing_output(
            output, ["log"], "sandbox/alice", None
        )
        assert "tag: v1.0" in result

    def test_removes_empty_parens(self):
        """When all decorations are filtered, empty parentheses are removed."""
        output = "abc1234 (sandbox/bob) commit msg\n"
        result = filter_ref_listing_output(
            output, ["log"], "sandbox/alice", None
        )
        assert "()" not in result
        assert "sandbox/bob" not in result

    def test_non_decoration_line_preserved(self):
        """Lines without decorations (e.g. commit messages) are preserved."""
        output = "    This is a commit message\n"
        result = filter_ref_listing_output(
            output, ["log"], "sandbox/alice", None
        )
        assert "This is a commit message" in result

    def test_preserves_base_branch_in_decoration(self):
        """Base branch (without slashes) is preserved in decorations."""
        output = "abc1234 (HEAD -> sandbox/alice, develop) msg\n"
        result = filter_ref_listing_output(
            output, ["log"], "sandbox/alice", "develop"
        )
        assert "develop" in result


# ---------------------------------------------------------------------------
# TestFilterStderrBranchRefs
# ---------------------------------------------------------------------------


class TestFilterStderrBranchRefs:
    """Tests for filter_stderr_branch_refs() stderr redaction."""

    def test_redacts_refs_heads_other(self):
        """refs/heads/<other> paths in stderr are redacted."""
        stderr = "error: refs/heads/sandbox/bob is not a valid ref"
        result = filter_stderr_branch_refs(stderr, "sandbox/alice", None)
        assert "sandbox/bob" not in result
        assert "<redacted>" in result

    def test_preserves_own_branch_in_stderr(self):
        """refs/heads/<own> paths in stderr are preserved."""
        stderr = "error: refs/heads/sandbox/alice is not a valid ref"
        result = filter_stderr_branch_refs(stderr, "sandbox/alice", None)
        assert "sandbox/alice" in result

    def test_redacts_slashed_bare_name_in_quotes(self):
        """Slashed branch names in single quotes are redacted."""
        stderr = "error: pathspec 'sandbox/bob' did not match"
        result = filter_stderr_branch_refs(stderr, "sandbox/alice", None)
        assert "sandbox/bob" not in result
        assert "<redacted>" in result

    def test_preserves_slashed_own_branch_in_quotes(self):
        """Own slashed branch name in single quotes is preserved."""
        stderr = "error: pathspec 'sandbox/alice' did not match"
        result = filter_stderr_branch_refs(stderr, "sandbox/alice", None)
        assert "sandbox/alice" in result

    def test_redacts_simple_branch_in_error_context(self):
        """Simple branch name in git error context is redacted."""
        stderr = "error: branch 'bob' not found"
        result = filter_stderr_branch_refs(stderr, "sandbox/alice", None)
        assert "'bob'" not in result
        assert "<redacted>" in result

    def test_preserves_simple_own_branch_in_error_context(self):
        """Own simple branch name in error context is preserved."""
        stderr = "error: branch 'sandbox/alice' not found"
        result = filter_stderr_branch_refs(stderr, "sandbox/alice", None)
        # sandbox/alice is slashed so it matches the slashed pattern
        assert "sandbox/alice" in result

    def test_empty_stderr_passthrough(self):
        """Empty stderr returns empty string."""
        result = filter_stderr_branch_refs("", "sandbox/alice", None)
        assert result == ""

    def test_none_sandbox_branch_passthrough(self):
        """Empty sandbox_branch returns input unchanged."""
        stderr = "error: refs/heads/sandbox/bob"
        result = filter_stderr_branch_refs(stderr, "", None)
        assert result == stderr

    def test_redacts_remote_ref(self):
        """refs/remotes/origin/<other> is redacted."""
        stderr = "error: refs/remotes/origin/sandbox/bob not found"
        result = filter_stderr_branch_refs(stderr, "sandbox/alice", None)
        assert "sandbox/bob" not in result
        assert "<redacted>" in result


# ---------------------------------------------------------------------------
# TestFilterRefListingOutput
# ---------------------------------------------------------------------------


class TestFilterRefListingOutput:
    """Tests for filter_ref_listing_output() dispatch logic."""

    def test_dispatches_to_branch_filter(self):
        """branch command dispatches to branch listing filter."""
        output = "* sandbox/alice\n  sandbox/bob\n"
        result = filter_ref_listing_output(output, ["branch"], "sandbox/alice", None)
        assert "sandbox/alice" in result
        assert "sandbox/bob" not in result

    def test_dispatches_to_ref_enum_for_for_each_ref(self):
        """for-each-ref command dispatches to ref enum filter."""
        output = "abc123 refs/heads/sandbox/alice\n"
        result = filter_ref_listing_output(
            output, ["for-each-ref"], "sandbox/alice", None
        )
        assert "refs/heads/sandbox/alice" in result

    def test_dispatches_to_log_for_log_with_decorate(self):
        """log command dispatches to log decoration filter."""
        output = "abc1234 (HEAD -> sandbox/alice, sandbox/bob) msg\n"
        result = filter_ref_listing_output(output, ["log"], "sandbox/alice", None)
        assert "sandbox/alice" in result
        assert "sandbox/bob" not in result

    def test_unknown_command_passthrough(self):
        """Unknown subcommand returns output unchanged."""
        output = "some output\n"
        result = filter_ref_listing_output(
            output, ["stash"], "sandbox/alice", None
        )
        assert result == output

    def test_none_subcommand_passthrough(self):
        """No subcommand found returns output unchanged."""
        output = "some output\n"
        result = filter_ref_listing_output(
            output, ["--version"], "sandbox/alice", None
        )
        assert result == output

    def test_empty_output_unchanged(self):
        """Empty output is returned as-is without dispatch."""
        result = filter_ref_listing_output("", ["branch"], "sandbox/alice", None)
        assert result == ""

    def test_empty_sandbox_branch_unchanged(self):
        """Empty sandbox_branch returns output unchanged."""
        output = "* sandbox/bob\n"
        result = filter_ref_listing_output(output, ["branch"], "", None)
        assert result == output

    def test_log_with_custom_format_d(self):
        """log with --format containing %d uses custom format decoration filter."""
        output = " (HEAD -> sandbox/alice, sandbox/bob)\n"
        result = filter_ref_listing_output(
            output, ["log", "--format=%d"], "sandbox/alice", None
        )
        assert "sandbox/alice" in result
        assert "sandbox/bob" not in result

    def test_log_with_source_flag(self):
        """log --source filters disallowed source refs."""
        output = "abc1234 refs/heads/sandbox/alice\tmsg\n"
        result = filter_ref_listing_output(
            output, ["log", "--source"], "sandbox/alice", None
        )
        assert "sandbox/alice" in result

    def test_log_source_redacts_disallowed(self):
        """log --source redacts disallowed branch refs."""
        output = "abc1234 refs/heads/sandbox/bob\tmsg\n"
        result = filter_ref_listing_output(
            output, ["log", "--source"], "sandbox/alice", None
        )
        assert "sandbox/bob" not in result
        assert "[redacted]" in result

    def test_global_flags_skipped_before_subcommand(self):
        """Global flags like -c are skipped before extracting the subcommand."""
        output = "* sandbox/alice\n  sandbox/bob\n"
        result = filter_ref_listing_output(
            output, ["-c", "core.bare=false", "branch"], "sandbox/alice", None
        )
        assert "sandbox/alice" in result
        assert "sandbox/bob" not in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
