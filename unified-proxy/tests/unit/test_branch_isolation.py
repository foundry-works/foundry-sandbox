"""
Unit tests for branch isolation helpers in git_operations.

Tests cover:
- _get_subcommand_args: subcommand extraction with global flags
- _strip_rev_suffixes: revision suffix stripping from ref strings
- _is_allowed_branch_name: bare branch name validation
- _is_allowed_ref: full ref validation with ranges, suffixes, SHA hashes
- validate_branch_isolation: command-level branch isolation enforcement
- _filter_ref_listing_output: output filtering for branch/ref listings and log decorations
"""

import sys
from unittest import mock

import pytest

# git_operations imports mitmproxy indirectly via git_policies; ensure mocks
# are in place before import.
for mod in ("mitmproxy", "mitmproxy.http", "mitmproxy.ctx", "mitmproxy.flow"):
    if mod not in sys.modules:
        sys.modules[mod] = mock.MagicMock()

from git_operations import (
    _extract_sha_args,
    _filter_ref_listing_output,
    _filter_stderr_branch_refs,
    _get_subcommand_args,
    _is_allowed_branch_name,
    _is_allowed_ref,
    _is_allowed_short_ref_token,
    _strip_rev_suffixes,
    validate_branch_isolation,
    validate_sha_reachability,
)


# ---------------------------------------------------------------------------
# _get_subcommand_args
# ---------------------------------------------------------------------------


class TestGetSubcommandArgs:
    """Test extraction of git subcommand and its arguments."""

    def test_simple_command(self):
        subcmd, args, configs = _get_subcommand_args(["push", "origin", "main"])
        assert subcmd == "push"
        assert args == ["origin", "main"]
        assert configs == []

    def test_global_c_flag(self):
        subcmd, args, configs = _get_subcommand_args(
            ["-c", "user.name=Test", "commit", "-m", "msg"]
        )
        assert subcmd == "commit"
        assert args == ["-m", "msg"]
        assert configs == ["user.name=Test"]

    def test_compact_c_flag(self):
        subcmd, args, configs = _get_subcommand_args(
            ["-cuser.name=Test", "commit", "-m", "msg"]
        )
        assert subcmd == "commit"
        assert args == ["-m", "msg"]
        assert configs == ["user.name=Test"]

    def test_double_dash_terminator(self):
        subcmd, args, configs = _get_subcommand_args(
            ["--", "push", "origin", "main"]
        )
        assert subcmd == "push"
        assert args == ["origin", "main"]
        assert configs == []

    def test_empty_args(self):
        subcmd, args, configs = _get_subcommand_args([])
        assert subcmd is None
        assert args == []
        assert configs == []

    def test_only_flags(self):
        subcmd, args, configs = _get_subcommand_args(
            ["-c", "foo=bar", "--"]
        )
        assert subcmd is None
        assert args == []
        assert configs == ["foo=bar"]

    def test_capital_c_path_flag(self):
        subcmd, args, configs = _get_subcommand_args(
            ["-C", "/some/path", "status"]
        )
        assert subcmd == "status"
        assert args == []
        assert configs == []

    def test_git_dir_flag(self):
        subcmd, args, configs = _get_subcommand_args(
            ["--git-dir", "/repo/.git", "log", "--oneline"]
        )
        assert subcmd == "log"
        assert args == ["--oneline"]
        assert configs == []

    def test_work_tree_flag(self):
        subcmd, args, configs = _get_subcommand_args(
            ["--work-tree", "/repo", "diff"]
        )
        assert subcmd == "diff"
        assert args == []
        assert configs == []

    def test_flag_equals_value_form(self):
        subcmd, args, configs = _get_subcommand_args(
            ["--git-dir=/repo/.git", "log"]
        )
        assert subcmd == "log"
        assert args == []
        assert configs == []

    def test_multiple_global_flags(self):
        subcmd, args, configs = _get_subcommand_args(
            [
                "-c", "a=1",
                "-C", "/path",
                "--git-dir=/repo/.git",
                "-c", "b=2",
                "fetch",
                "--all",
            ]
        )
        assert subcmd == "fetch"
        assert args == ["--all"]
        assert configs == ["a=1", "b=2"]


# ---------------------------------------------------------------------------
# _strip_rev_suffixes
# ---------------------------------------------------------------------------


class TestStripRevSuffixes:
    """Test stripping of revision suffixes from ref strings."""

    def test_tilde_n(self):
        assert _strip_rev_suffixes("HEAD~3") == "HEAD"

    def test_caret_n(self):
        assert _strip_rev_suffixes("main^2") == "main"

    def test_bare_tilde_and_caret(self):
        assert _strip_rev_suffixes("main^^") == "main"
        assert _strip_rev_suffixes("HEAD~") == "HEAD"

    def test_chained_suffixes(self):
        assert _strip_rev_suffixes("HEAD~2^3") == "HEAD"
        assert _strip_rev_suffixes("feature~1^2~3") == "feature"

    def test_no_suffix(self):
        assert _strip_rev_suffixes("main") == "main"
        assert _strip_rev_suffixes("HEAD") == "HEAD"
        assert _strip_rev_suffixes("refs/heads/feature") == "refs/heads/feature"

    def test_sha_unchanged(self):
        sha = "abc123def456"
        assert _strip_rev_suffixes(sha) == sha
        # SHA with suffix should strip
        assert _strip_rev_suffixes("abc123def456~2^3") == "abc123def456"


# ---------------------------------------------------------------------------
# _is_allowed_branch_name
# ---------------------------------------------------------------------------

# All _is_allowed_branch_name tests use "sandbox/abc" as the sandbox branch.
SANDBOX = "sandbox/abc"


class TestIsAllowedBranchName:
    """Test bare branch name validation against sandbox isolation."""

    def test_own_branch_allowed(self):
        assert _is_allowed_branch_name(SANDBOX, SANDBOX) is True

    def test_well_known_branches_allowed(self):
        for name in ("main", "master", "develop", "production"):
            assert _is_allowed_branch_name(name, SANDBOX) is True

    def test_well_known_prefix_release(self):
        assert _is_allowed_branch_name("release/1.0", SANDBOX) is True

    def test_well_known_prefix_hotfix(self):
        assert _is_allowed_branch_name("hotfix/urgent", SANDBOX) is True

    def test_other_sandbox_blocked(self):
        assert _is_allowed_branch_name("sandbox/other", SANDBOX) is False

    def test_arbitrary_branch_blocked(self):
        assert _is_allowed_branch_name("feature/xyz", SANDBOX) is False


# ---------------------------------------------------------------------------
# _is_allowed_ref
# ---------------------------------------------------------------------------


class TestIsAllowedRef:
    """Test full ref validation under branch isolation."""

    # --- HEAD and relative refs ---

    def test_head_allowed(self):
        assert _is_allowed_ref("HEAD", SANDBOX) is True

    def test_head_relative_allowed(self):
        assert _is_allowed_ref("HEAD~3", SANDBOX) is True
        assert _is_allowed_ref("HEAD^2", SANDBOX) is True

    # --- @{} refs ---
    # Standalone @{upstream}/@{u} are consumed entirely by _strip_rev_suffixes
    # (the @{...} regex matches the whole string), so they are not allowed as
    # bare refs.  Branch-qualified forms like HEAD@{1} are tested via stash.

    def test_standalone_at_ref_blocked(self):
        # @{upstream} stripped to "" which is not a valid branch name
        assert _is_allowed_ref("@{upstream}", SANDBOX) is False
        assert _is_allowed_ref("@{u}", SANDBOX) is False

    # --- Own branch ---

    def test_own_branch_bare(self):
        assert _is_allowed_ref(SANDBOX, SANDBOX) is True

    def test_own_branch_refs_heads(self):
        assert _is_allowed_ref(f"refs/heads/{SANDBOX}", SANDBOX) is True

    # --- Well-known branches ---

    def test_well_known_branches(self):
        for name in ("main", "master", "develop", "production"):
            assert _is_allowed_ref(name, SANDBOX) is True

    # --- Other sandbox blocked ---

    def test_other_sandbox_bare_blocked(self):
        assert _is_allowed_ref("sandbox/other", SANDBOX) is False

    def test_other_sandbox_refs_heads_blocked(self):
        assert _is_allowed_ref("refs/heads/sandbox/other", SANDBOX) is False

    # --- Remote refs ---

    def test_remote_other_sandbox_blocked_origin(self):
        assert _is_allowed_ref("origin/sandbox/other", SANDBOX) is False

    def test_remote_other_sandbox_blocked_refs_remotes(self):
        assert _is_allowed_ref("refs/remotes/origin/sandbox/other", SANDBOX) is False

    def test_remote_well_known_allowed(self):
        assert _is_allowed_ref("origin/main", SANDBOX) is True
        assert _is_allowed_ref("refs/remotes/origin/master", SANDBOX) is True

    # --- Tags ---

    def test_tags_allowed(self):
        assert _is_allowed_ref("refs/tags/v1.0", SANDBOX) is True
        assert _is_allowed_ref("tags/v2.0", SANDBOX) is True

    # --- SHA hashes ---

    def test_sha_long_hex_allowed(self):
        assert _is_allowed_ref("abcdef123456", SANDBOX) is True  # 12 chars
        assert _is_allowed_ref("abcdef1234567890abcdef1234567890abcdef12", SANDBOX) is True

    def test_sha_short_hex_blocked(self):
        assert _is_allowed_ref("abcdef12345", SANDBOX) is False  # 11 chars

    # --- Range operators ---

    def test_range_double_dot(self):
        assert _is_allowed_ref(f"main..{SANDBOX}", SANDBOX) is True
        assert _is_allowed_ref("main..sandbox/other", SANDBOX) is False

    def test_range_triple_dot(self):
        assert _is_allowed_ref(f"main...{SANDBOX}", SANDBOX) is True
        assert _is_allowed_ref("main...sandbox/other", SANDBOX) is False

    def test_range_with_caret_prefix(self):
        # ^main is shorthand for exclusion but will hit range logic only if
        # combined with ..; standalone ^main goes through normal ref checks
        assert _is_allowed_ref("main..HEAD^2", SANDBOX) is True

    # --- FETCH_HEAD ---

    def test_fetch_head_blocked(self):
        assert _is_allowed_ref("FETCH_HEAD", SANDBOX) is False

    # --- Branch with slashes ---

    def test_branch_with_slashes(self):
        assert _is_allowed_ref("release/1.0", SANDBOX) is True
        assert _is_allowed_ref("hotfix/critical/fix", SANDBOX) is True

    # --- Rev suffixes on allowed/blocked refs ---

    def test_rev_suffix_on_allowed_ref(self):
        assert _is_allowed_ref("main~3", SANDBOX) is True
        assert _is_allowed_ref(f"{SANDBOX}^2", SANDBOX) is True

    def test_rev_suffix_on_blocked_ref(self):
        assert _is_allowed_ref("sandbox/other~3", SANDBOX) is False
        assert _is_allowed_ref("FETCH_HEAD^2", SANDBOX) is False

    # --- Range with rev suffixes ---

    def test_range_with_rev_suffixes(self):
        assert _is_allowed_ref("main~2..HEAD^3", SANDBOX) is True
        assert _is_allowed_ref("sandbox/other~1..main", SANDBOX) is False


# ---------------------------------------------------------------------------
# validate_branch_isolation
# ---------------------------------------------------------------------------

META = {"sandbox_branch": SANDBOX}
OTHER = "sandbox/other"


class TestValidateBranchIsolation:
    """Test the top-level branch isolation validator."""

    # --- No metadata → allow all; no sandbox_branch → fail closed ---

    def test_no_metadata_allows_all(self):
        assert validate_branch_isolation(["log", OTHER], None) is None

    def test_no_sandbox_branch_fails_closed(self):
        err = validate_branch_isolation(["log", OTHER], {})
        assert err is not None
        assert "missing sandbox_branch" in err.reason

    # --- ref-reading commands ---

    def test_blocks_other_branch_in_log(self):
        err = validate_branch_isolation(["log", OTHER], META)
        assert err is not None
        assert OTHER in err.reason

    def test_allows_own_branch_in_log(self):
        assert validate_branch_isolation(["log", SANDBOX], META) is None

    def test_pathspecs_after_double_dash_not_checked(self):
        # After --, args are pathspecs, not refs
        assert validate_branch_isolation(["log", "--", OTHER], META) is None

    def test_paths_without_double_dash_treated_as_refs(self):
        err = validate_branch_isolation(["log", OTHER], META)
        assert err is not None

    # --- branch deletion ---

    def test_branch_deletion_blocked(self):
        err = validate_branch_isolation(["branch", "-d", OTHER], META)
        assert err is not None
        assert "delete" in err.reason

    def test_branch_deletion_own_allowed(self):
        assert validate_branch_isolation(["branch", "-d", SANDBOX], META) is None

    # --- checkout / switch ---

    def test_checkout_other_branch_blocked(self):
        err = validate_branch_isolation(["checkout", OTHER], META)
        assert err is not None
        assert OTHER in err.reason

    def test_checkout_b_start_point_blocked(self):
        err = validate_branch_isolation(
            ["checkout", "-b", "new-branch", OTHER], META
        )
        assert err is not None
        assert OTHER in err.reason

    def test_switch_c_start_point_blocked(self):
        err = validate_branch_isolation(
            ["switch", "-c", "new-branch", OTHER], META
        )
        assert err is not None
        assert OTHER in err.reason

    def test_checkout_own_branch_allowed(self):
        assert validate_branch_isolation(["checkout", SANDBOX], META) is None

    def test_checkout_orphan_start_point_blocked(self):
        err = validate_branch_isolation(
            ["checkout", "--orphan", "new-orphan", OTHER], META
        )
        assert err is not None

    # --- --all/--branches/--remotes/--glob blocked ---

    def test_all_flag_blocked(self):
        err = validate_branch_isolation(["log", "--all"], META)
        assert err is not None
        assert "--all" in err.reason

    def test_branches_flag_blocked(self):
        err = validate_branch_isolation(["log", "--branches"], META)
        assert err is not None

    def test_remotes_flag_blocked(self):
        err = validate_branch_isolation(["log", "--remotes"], META)
        assert err is not None

    def test_glob_flag_blocked(self):
        err = validate_branch_isolation(["log", "--glob=refs/*"], META)
        assert err is not None

    def test_log_max_count_value_not_treated_as_ref(self):
        # -n consumes the next argument; numeric value should not be parsed as ref
        err = validate_branch_isolation(["log", "-n", "5"], META)
        assert err is None

    def test_log_format_value_not_treated_as_ref(self):
        # --format consumes the next argument
        err = validate_branch_isolation(["log", "--format", "%h %s"], META)
        assert err is None

    # --- ref enum commands (handled by output filtering, not blocked here) ---

    def test_for_each_ref_not_input_blocked(self):
        assert validate_branch_isolation(["for-each-ref"], META) is None

    def test_ls_remote_not_input_blocked(self):
        assert validate_branch_isolation(["ls-remote"], META) is None

    def test_show_ref_not_input_blocked(self):
        assert validate_branch_isolation(["show-ref"], META) is None

    # --- fetch ---

    def test_fetch_other_branch_blocked(self):
        err = validate_branch_isolation(["fetch", "origin", OTHER], META)
        assert err is not None

    def test_fetch_own_branch_allowed(self):
        assert validate_branch_isolation(
            ["fetch", "origin", SANDBOX], META
        ) is None

    def test_fetch_well_known_branch_allowed(self):
        assert validate_branch_isolation(
            ["fetch", "origin", "main"], META
        ) is None

    def test_fetch_no_refspec_allowed(self):
        assert validate_branch_isolation(["fetch", "origin"], META) is None

    def test_fetch_depth_flag_parsing(self):
        # --depth consumes the next arg; it should not be treated as a refspec
        assert validate_branch_isolation(
            ["fetch", "--depth", "1", "origin"], META
        ) is None

    def test_fetch_explicit_refspec(self):
        err = validate_branch_isolation(
            ["fetch", "origin", f"+{OTHER}:refs/heads/{OTHER}"], META
        )
        assert err is not None

    # --- pull ---

    def test_pull_other_branch_blocked(self):
        err = validate_branch_isolation(["pull", "origin", OTHER], META)
        assert err is not None

    # --- rev-parse (IS in _REF_READING_CMDS) ---

    def test_rev_parse_other_branch_blocked(self):
        err = validate_branch_isolation(["rev-parse", OTHER], META)
        assert err is not None

    def test_rev_parse_own_branch_allowed(self):
        assert validate_branch_isolation(["rev-parse", SANDBOX], META) is None

    # --- worktree add ---

    def test_worktree_add_other_branch_blocked(self):
        err = validate_branch_isolation(
            ["worktree", "add", "/tmp/wt", OTHER], META
        )
        assert err is not None

    def test_worktree_add_own_branch_allowed(self):
        assert validate_branch_isolation(
            ["worktree", "add", "/tmp/wt", SANDBOX], META
        ) is None

    # --- reset ---

    def test_reset_hard_other_branch_blocked(self):
        err = validate_branch_isolation(
            ["reset", "--hard", OTHER], META
        )
        assert err is not None

    # --- bisect ---

    def test_bisect_start_other_branch_blocked(self):
        err = validate_branch_isolation(
            ["bisect", "start", OTHER], META
        )
        assert err is not None

    def test_bisect_good_bad_not_checked(self):
        # bisect good/bad are not "start", so not checked here
        assert validate_branch_isolation(
            ["bisect", "good", OTHER], META
        ) is None

    # --- name-rev / shortlog ---

    def test_name_rev_other_branch_blocked(self):
        err = validate_branch_isolation(["name-rev", OTHER], META)
        assert err is not None

    def test_shortlog_other_branch_blocked(self):
        err = validate_branch_isolation(["shortlog", OTHER], META)
        assert err is not None

    # --- archive / format-patch ---

    def test_archive_other_branch_blocked(self):
        err = validate_branch_isolation(["archive", OTHER], META)
        assert err is not None

    def test_archive_own_branch_allowed(self):
        assert validate_branch_isolation(["archive", SANDBOX], META) is None

    def test_format_patch_other_branch_blocked(self):
        err = validate_branch_isolation(["format-patch", OTHER], META)
        assert err is not None

    def test_format_patch_own_branch_allowed(self):
        assert validate_branch_isolation(
            ["format-patch", SANDBOX], META
        ) is None

    # --- Error message suggests -- separator ---

    def test_error_message_suggests_separator(self):
        err = validate_branch_isolation(["log", OTHER], META)
        assert err is not None
        assert "--" in err.reason


# ---------------------------------------------------------------------------
# _filter_ref_listing_output
# ---------------------------------------------------------------------------


class TestFilterRefListingOutput:
    """Test output filtering for branch listings, ref enumerations, and log decorations."""

    # --- Branch listing ---

    def test_branch_listing_hides_other_sandbox(self):
        output = (
            f"* {SANDBOX}\n"
            f"  sandbox/other\n"
            "  main\n"
        )
        result = _filter_ref_listing_output(output, ["branch"], SANDBOX)
        assert f"* {SANDBOX}" in result
        assert "main" in result
        assert "sandbox/other" not in result

    def test_branch_verbose_hides_other(self):
        output = (
            f"* {SANDBOX}   abc1234 some commit\n"
            f"  sandbox/other abc1234 another commit\n"
            "  main          abc1234 third commit\n"
        )
        result = _filter_ref_listing_output(output, ["branch", "-v"], SANDBOX)
        assert SANDBOX in result
        assert "main" in result
        assert "sandbox/other" not in result

    # --- Ref enumeration (for-each-ref) ---

    def test_for_each_ref_hides_other_keeps_tags(self):
        output = (
            f"abc1234 refs/heads/{SANDBOX}\n"
            "abc1234 refs/heads/sandbox/other\n"
            "abc1234 refs/tags/v1.0\n"
            "abc1234 refs/heads/main\n"
        )
        result = _filter_ref_listing_output(output, ["for-each-ref"], SANDBOX)
        assert f"refs/heads/{SANDBOX}" in result
        assert "refs/tags/v1.0" in result
        assert "refs/heads/main" in result
        assert "refs/heads/sandbox/other" not in result

    def test_for_each_ref_short_format_hides_other_slashed_branch(self):
        output = (
            f"{SANDBOX}\n"
            "sandbox/other\n"
            "main\n"
        )
        result = _filter_ref_listing_output(
            output, ["for-each-ref", "--format=%(refname:short)"], SANDBOX
        )
        assert SANDBOX in result
        assert "main" in result
        assert "sandbox/other" not in result

    def test_for_each_ref_objectname_short_ref_filters_second_token(self):
        output = (
            f"abcdef123456 {SANDBOX}\n"
            "abcdef123456 sandbox/other\n"
        )
        result = _filter_ref_listing_output(
            output, ["for-each-ref", "--format=%(objectname) %(refname:short)"], SANDBOX
        )
        assert f"abcdef123456 {SANDBOX}" in result
        assert "sandbox/other" not in result

    # --- show-ref ---

    def test_show_ref_hides_other(self):
        output = (
            f"abc1234 refs/heads/{SANDBOX}\n"
            "abc1234 refs/heads/sandbox/other\n"
        )
        result = _filter_ref_listing_output(output, ["show-ref"], SANDBOX)
        assert f"refs/heads/{SANDBOX}" in result
        assert "refs/heads/sandbox/other" not in result

    # --- Log decoration filtering ---

    def test_log_decoration_hides_other(self):
        output = (
            f"abc1234 (HEAD -> {SANDBOX}, origin/sandbox/other, tag: v1.0) commit msg\n"
        )
        result = _filter_ref_listing_output(output, ["log", "--oneline"], SANDBOX)
        assert "HEAD" in result
        assert "tag: v1.0" in result
        assert "sandbox/other" not in result

    def test_log_decoration_preserves_head_and_tags(self):
        output = (
            "abc1234 (HEAD, tag: v2.0) commit msg\n"
        )
        result = _filter_ref_listing_output(output, ["log", "--oneline"], SANDBOX)
        assert "HEAD" in result
        assert "tag: v2.0" in result

    def test_log_decoration_strips_empty_parens(self):
        # When all decorations are removed, parens should be gone
        output = "abc1234 (origin/sandbox/other) commit msg\n"
        result = _filter_ref_listing_output(output, ["log", "--oneline"], SANDBOX)
        assert "()" not in result
        assert "sandbox/other" not in result

    def test_log_decoration_ignores_commit_message_parens(self):
        # Commit message parens should not be parsed as decorations
        output = "abc1234 some commit (with parens)\n"
        result = _filter_ref_listing_output(output, ["log", "--oneline"], SANDBOX)
        assert "(with parens)" in result

    def test_log_decoration_preserves_detached_head(self):
        output = "abc1234 (HEAD) detached commit\n"
        result = _filter_ref_listing_output(output, ["log", "--oneline"], SANDBOX)
        assert "(HEAD)" in result

    # --- Log --format=%d (parenthesized) ---

    def test_log_format_d_hides_other(self):
        output = f" (HEAD -> {SANDBOX}, origin/sandbox/other)\n"
        result = _filter_ref_listing_output(
            output, ["log", "--format=%d"], SANDBOX
        )
        assert f"HEAD -> {SANDBOX}" in result
        assert "sandbox/other" not in result

    # --- Log --format=%D (bare) ---

    def test_log_format_D_hides_other(self):
        output = f"HEAD -> {SANDBOX}, origin/sandbox/other\n"
        result = _filter_ref_listing_output(
            output, ["log", "--format=%D"], SANDBOX
        )
        assert f"HEAD -> {SANDBOX}" in result
        assert "sandbox/other" not in result

    def test_log_format_split_D_hides_other(self):
        output = f"HEAD -> {SANDBOX}, origin/sandbox/other\n"
        result = _filter_ref_listing_output(
            output, ["log", "--format", "%D"], SANDBOX
        )
        assert f"HEAD -> {SANDBOX}" in result
        assert "sandbox/other" not in result

    def test_log_pretty_split_d_hides_other(self):
        output = f" (HEAD -> {SANDBOX}, origin/sandbox/other)\n"
        result = _filter_ref_listing_output(
            output, ["log", "--pretty", "%d"], SANDBOX
        )
        assert f"HEAD -> {SANDBOX}" in result
        assert "sandbox/other" not in result

    # --- %d-only format skips bare heuristic ---

    def test_log_format_d_does_not_trigger_bare_heuristic(self):
        """With %d (not %D), commit messages with commas should not be mangled."""
        # A commit message that looks like a bare decoration list but isn't
        output = "HEAD, something/else\n"
        result = _filter_ref_listing_output(
            output, ["log", "--format=%d"], SANDBOX
        )
        # %d produces parenthesized output; bare lines should pass through
        assert result == output

    def test_log_format_D_triggers_bare_heuristic(self):
        """With %D, bare decoration lines should be filtered."""
        output = f"HEAD -> {SANDBOX}, origin/sandbox/other\n"
        result = _filter_ref_listing_output(
            output, ["log", "--format=%D"], SANDBOX
        )
        assert f"HEAD -> {SANDBOX}" in result
        assert "sandbox/other" not in result

    # --- Log --format without %d/%D uses SHA-anchored regex ---

    def test_log_format_without_d_uses_sha_anchored(self):
        # Without %d/%D, falls through to standard log decoration filter
        output = f"abc1234 (HEAD -> {SANDBOX}, origin/sandbox/other) msg\n"
        result = _filter_ref_listing_output(
            output, ["log", "--format=%H %s"], SANDBOX
        )
        assert "HEAD" in result
        assert "sandbox/other" not in result


# ---------------------------------------------------------------------------
# Additional ref-reading commands coverage
# ---------------------------------------------------------------------------


class TestRefReadingCommandsCoverage:
    """Verify all commands in _REF_READING_CMDS block other sandbox refs."""

    @pytest.mark.parametrize("cmd", [
        "show", "diff", "blame", "cherry-pick", "merge", "rebase",
        "rev-list", "diff-tree", "describe", "cat-file", "ls-tree",
    ])
    def test_ref_reading_cmd_blocks_other_branch(self, cmd):
        err = validate_branch_isolation([cmd, OTHER], META)
        assert err is not None
        assert OTHER in err.reason

    @pytest.mark.parametrize("cmd", [
        "show", "diff", "blame", "cherry-pick", "merge", "rebase",
        "rev-list", "diff-tree", "describe", "cat-file", "ls-tree",
    ])
    def test_ref_reading_cmd_allows_own_branch(self, cmd):
        assert validate_branch_isolation([cmd, SANDBOX], META) is None


# ---------------------------------------------------------------------------
# Notes isolation
# ---------------------------------------------------------------------------


class TestNotesIsolation:
    """Test notes --ref validation including split form."""

    def test_notes_ref_equals_other_blocked(self):
        err = validate_branch_isolation(
            ["notes", "--ref=sandbox/other", "list"], META
        )
        assert err is not None
        assert "sandbox/other" in err.reason

    def test_notes_ref_split_other_blocked(self):
        """The split form --ref <value> must also be validated."""
        err = validate_branch_isolation(
            ["notes", "--ref", "sandbox/other", "list"], META
        )
        assert err is not None
        assert "sandbox/other" in err.reason

    def test_notes_ref_equals_own_allowed(self):
        assert validate_branch_isolation(
            ["notes", f"--ref={SANDBOX}", "list"], META
        ) is None

    def test_notes_ref_split_own_allowed(self):
        assert validate_branch_isolation(
            ["notes", "--ref", SANDBOX, "list"], META
        ) is None

    def test_notes_positional_other_blocked(self):
        err = validate_branch_isolation(
            ["notes", "show", OTHER], META
        )
        assert err is not None

    def test_notes_positional_own_allowed(self):
        assert validate_branch_isolation(
            ["notes", "show", SANDBOX], META
        ) is None


# ---------------------------------------------------------------------------
# Reflog isolation
# ---------------------------------------------------------------------------


class TestReflogIsolation:
    """Test reflog ref validation."""

    def test_reflog_show_other_blocked(self):
        err = validate_branch_isolation(
            ["reflog", "show", OTHER], META
        )
        assert err is not None

    def test_reflog_show_own_allowed(self):
        assert validate_branch_isolation(
            ["reflog", "show", SANDBOX], META
        ) is None

    def test_reflog_bare_other_blocked(self):
        """reflog <ref> without sub-subcommand."""
        err = validate_branch_isolation(
            ["reflog", OTHER], META
        )
        assert err is not None

    def test_reflog_no_args_allowed(self):
        assert validate_branch_isolation(["reflog"], META) is None


# ---------------------------------------------------------------------------
# Tag isolation
# ---------------------------------------------------------------------------


class TestTagIsolation:
    """Test tag commit-ish validation."""

    def test_tag_create_with_other_branch_blocked(self):
        err = validate_branch_isolation(
            ["tag", "v1.0", OTHER], META
        )
        assert err is not None
        assert OTHER in err.reason

    def test_tag_create_with_own_branch_allowed(self):
        assert validate_branch_isolation(
            ["tag", "v1.0", SANDBOX], META
        ) is None

    def test_tag_with_message_and_other_blocked(self):
        err = validate_branch_isolation(
            ["tag", "-a", "v1.0", "-m", "release", OTHER], META
        )
        assert err is not None

    def test_tag_name_only_allowed(self):
        """Just a tag name, no commit-ish."""
        assert validate_branch_isolation(
            ["tag", "v1.0"], META
        ) is None

    def test_tag_list_allowed(self):
        assert validate_branch_isolation(["tag", "-l"], META) is None


# ---------------------------------------------------------------------------
# Stash ref handling
# ---------------------------------------------------------------------------


class TestStashRefAllowed:
    """Verify stash refs are allowed."""

    def test_stash_bare(self):
        assert _is_allowed_ref("stash", SANDBOX) is True

    def test_stash_at_index(self):
        assert _is_allowed_ref("stash@{0}", SANDBOX) is True

    def test_stash_at_higher_index(self):
        assert _is_allowed_ref("stash@{5}", SANDBOX) is True


# ---------------------------------------------------------------------------
# Remote branch output filtering
# ---------------------------------------------------------------------------


class TestRemoteBranchOutputFiltering:
    """Test git branch -a output filtering for remote branches."""

    def test_branch_a_hides_remote_other_sandbox(self):
        output = (
            f"* {SANDBOX}\n"
            "  main\n"
            "  remotes/origin/main\n"
            f"  remotes/origin/{SANDBOX}\n"
            "  remotes/origin/sandbox/other\n"
        )
        result = _filter_ref_listing_output(output, ["branch", "-a"], SANDBOX)
        assert f"* {SANDBOX}" in result
        assert "main" in result
        assert "sandbox/other" not in result


# ---------------------------------------------------------------------------
# _extract_sha_args — value flag skipping
# ---------------------------------------------------------------------------


class TestExtractShaArgs:
    """Test SHA-like arg extraction with value flag skipping."""

    def test_basic_sha(self):
        shas = _extract_sha_args(["abc123def456"])
        assert shas == ["abc123def456"]

    def test_skips_format_value(self):
        """--format value should not be mistaken for a SHA."""
        shas = _extract_sha_args(["--format", "abc123def456"])
        assert shas == []

    def test_skips_format_equals_value(self):
        shas = _extract_sha_args(["--format=abc123def456"])
        assert shas == []

    def test_skips_pretty_value(self):
        shas = _extract_sha_args(["--pretty", "abc123def456"])
        assert shas == []

    def test_sha_after_format(self):
        shas = _extract_sha_args(["--format", "oneline", "abc123def456"])
        assert shas == ["abc123def456"]

    def test_stops_at_double_dash(self):
        shas = _extract_sha_args(["--", "abc123def456"])
        assert shas == []

    def test_range_operator(self):
        shas = _extract_sha_args(["abc123def456..def456abc123"])
        assert len(shas) == 2

    def test_skips_short_hex(self):
        shas = _extract_sha_args(["abc123"])
        assert shas == []

    def test_skips_dash_flags(self):
        shas = _extract_sha_args(["--oneline", "-n", "5", "abc123def456"])
        assert shas == ["abc123def456"]


# ---------------------------------------------------------------------------
# _filter_stderr_branch_refs
# ---------------------------------------------------------------------------


class TestFilterStderrBranchRefs:
    """Test stderr redaction of disallowed branch names."""

    def test_redacts_disallowed_heads_ref(self):
        stderr = "error: pathspec 'refs/heads/sandbox/other' did not match"
        result = _filter_stderr_branch_refs(stderr, SANDBOX)
        assert "sandbox/other" not in result
        assert "<redacted>" in result

    def test_keeps_allowed_heads_ref(self):
        stderr = f"hint: refs/heads/{SANDBOX} is up to date"
        result = _filter_stderr_branch_refs(stderr, SANDBOX)
        assert SANDBOX in result
        assert "<redacted>" not in result

    def test_redacts_disallowed_remote_ref(self):
        stderr = "error: refs/remotes/origin/sandbox/other not found"
        result = _filter_stderr_branch_refs(stderr, SANDBOX)
        assert "sandbox/other" not in result
        assert "<redacted>" in result

    def test_keeps_well_known_branch(self):
        stderr = "hint: refs/heads/main is up to date"
        result = _filter_stderr_branch_refs(stderr, SANDBOX)
        assert "main" in result
        assert "<redacted>" not in result

    def test_empty_stderr(self):
        assert _filter_stderr_branch_refs("", SANDBOX) == ""

    def test_none_sandbox_branch(self):
        stderr = "error: refs/heads/sandbox/other"
        assert _filter_stderr_branch_refs(stderr, None) == stderr

    # --- Bare branch names in single-quoted contexts ---

    def test_redacts_bare_branch_in_single_quotes(self):
        stderr = "error: pathspec 'sandbox/other' did not match"
        result = _filter_stderr_branch_refs(stderr, SANDBOX)
        assert "sandbox/other" not in result
        assert "'<redacted>'" in result

    def test_keeps_allowed_bare_branch_in_single_quotes(self):
        stderr = f"hint: '{SANDBOX}' is up to date"
        result = _filter_stderr_branch_refs(stderr, SANDBOX)
        assert SANDBOX in result
        assert "<redacted>" not in result

    def test_keeps_well_known_bare_branch_in_single_quotes(self):
        stderr = "error: pathspec 'release/1.0' did not match"
        result = _filter_stderr_branch_refs(stderr, SANDBOX)
        assert "release/1.0" in result
        assert "<redacted>" not in result

    def test_bare_branch_no_slash_not_matched(self):
        """Single-word tokens in quotes should not be matched (no false-positives)."""
        stderr = "error: pathspec 'main' did not match"
        result = _filter_stderr_branch_refs(stderr, SANDBOX)
        assert "main" in result
        assert "<redacted>" not in result


# ---------------------------------------------------------------------------
# fetch --all blocking
# ---------------------------------------------------------------------------


class TestFetchAllBlocking:
    """Test that fetch --all is blocked under branch isolation."""

    def test_fetch_all_blocked(self):
        err = validate_branch_isolation(["fetch", "--all"], META)
        assert err is not None
        assert "--all" in err.reason

    def test_fetch_origin_main_allowed(self):
        err = validate_branch_isolation(["fetch", "origin", "main"], META)
        assert err is None

    def test_pull_all_blocked(self):
        err = validate_branch_isolation(["pull", "--all"], META)
        assert err is not None
        assert "--all" in err.reason


# ---------------------------------------------------------------------------
# _is_allowed_ref — non-origin remote handling
# ---------------------------------------------------------------------------


class TestIsAllowedRefNonOriginRemotes:
    """Test ref validation with non-origin remote names."""

    def test_upstream_main_allowed(self):
        assert _is_allowed_ref("upstream/main", SANDBOX) is True

    def test_upstream_disallowed_sandbox(self):
        assert _is_allowed_ref("upstream/sandbox/other", SANDBOX) is False

    def test_upstream_own_sandbox_allowed(self):
        assert _is_allowed_ref(f"upstream/{SANDBOX}", SANDBOX) is True

    def test_refs_remotes_upstream_main(self):
        assert _is_allowed_ref("refs/remotes/upstream/main", SANDBOX) is True

    def test_refs_remotes_upstream_disallowed(self):
        assert _is_allowed_ref("refs/remotes/upstream/sandbox/other", SANDBOX) is False

    def test_refs_remotes_origin_main(self):
        assert _is_allowed_ref("refs/remotes/origin/main", SANDBOX) is True

    def test_refs_remotes_origin_disallowed(self):
        assert _is_allowed_ref("refs/remotes/origin/sandbox/other", SANDBOX) is False


# ---------------------------------------------------------------------------
# _is_allowed_short_ref_token — incomplete remote paths
# ---------------------------------------------------------------------------


class TestIsAllowedShortRefTokenRemotes:
    """Test short ref token validation for remote refs."""

    def test_complete_remote_ref_allowed(self):
        assert _is_allowed_short_ref_token("refs/remotes/origin/main", SANDBOX) is True

    def test_complete_remote_ref_disallowed(self):
        assert _is_allowed_short_ref_token(
            "refs/remotes/origin/sandbox/other", SANDBOX
        ) is False

    def test_incomplete_remote_ref_denied(self):
        """refs/remotes/origin (no branch component) should be denied."""
        assert _is_allowed_short_ref_token("refs/remotes/origin", SANDBOX) is False

    def test_incomplete_remote_ref_two_parts(self):
        """refs/remotes (only 2 parts) should be denied."""
        assert _is_allowed_short_ref_token("refs/remotes", SANDBOX) is False

    def test_non_origin_remote_ref(self):
        assert _is_allowed_short_ref_token(
            "refs/remotes/upstream/main", SANDBOX
        ) is True


# ---------------------------------------------------------------------------
# Output filter — unrecognized lines dropped
# ---------------------------------------------------------------------------


class TestOutputFilterDropsUnrecognized:
    """Test that output filters drop unrecognized lines (fail-closed)."""

    def test_branch_output_drops_unrecognized_line(self):
        output = (
            f"* {SANDBOX}\n"
            "  main\n"
            "WEIRD UNRECOGNIZED FORMAT\n"
        )
        result = _filter_ref_listing_output(output, ["branch"], SANDBOX)
        assert SANDBOX in result
        assert "main" in result
        assert "WEIRD UNRECOGNIZED FORMAT" not in result

    def test_branch_output_keeps_empty_lines(self):
        output = (
            f"* {SANDBOX}\n"
            "\n"
            "  main\n"
        )
        result = _filter_ref_listing_output(output, ["branch"], SANDBOX)
        assert SANDBOX in result
        assert "main" in result

    def test_ref_enum_drops_unrecognized_nonempty(self):
        output = (
            "abc123456789 refs/heads/main\n"
            "WEIRD LINE NO REF\n"
        )
        result = _filter_ref_listing_output(output, ["for-each-ref"], SANDBOX)
        assert "main" in result
        # The weird line has no recognizable ref format — it should be dropped
        # unless its first token passes the short ref check
        # "WEIRD" doesn't pass _is_allowed_short_ref_token so it gets dropped
        assert "WEIRD LINE NO REF" not in result

    def test_ref_enum_keeps_empty_lines(self):
        output = (
            "abc123456789 refs/heads/main\n"
            "\n"
            "def456789012 refs/tags/v1.0\n"
        )
        result = _filter_ref_listing_output(output, ["for-each-ref"], SANDBOX)
        assert "main" in result
        assert "v1.0" in result


# ---------------------------------------------------------------------------
# validate_sha_reachability — fail-closed on bare repo resolution
# ---------------------------------------------------------------------------


class TestShaReachabilityFailClosed:
    """Test that SHA reachability denies when bare repo cannot be resolved."""

    def test_returns_error_when_no_bare_repo(self, tmp_path):
        """When _resolve_bare_repo_path returns None, should return error."""
        # Create a directory without .git
        repo = tmp_path / "not-a-repo"
        repo.mkdir()
        # A SHA-like arg in a ref-reading command
        args = ["log", "abc123def45678"]
        metadata = {"sandbox_branch": SANDBOX}
        result = validate_sha_reachability(args, str(repo), metadata)
        assert result is not None
        assert "cannot resolve bare repo" in result.reason

    def test_skips_when_no_metadata(self):
        result = validate_sha_reachability(["log", "abc123def45678"], "/fake", None)
        assert result is None

    def test_skips_when_no_sandbox_branch(self):
        result = validate_sha_reachability(
            ["log", "abc123def45678"], "/fake", {}
        )
        assert result is None

    def test_skips_non_ref_reading_command(self):
        result = validate_sha_reachability(
            ["push", "abc123def45678"], "/fake",
            {"sandbox_branch": SANDBOX},
        )
        assert result is None


# ---------------------------------------------------------------------------
# Ref exclusion prefix (^ref) and --not flag
# ---------------------------------------------------------------------------


class TestRefExclusionPrefix:
    """Test ^ref exclusion prefix handling in ref-reading isolation.

    The ^ref prefix (used by rev-list/log to exclude refs) is NOT
    stripped by _strip_rev_suffixes (which only handles trailing ^N).
    As a result, ^ref is treated as a bare branch name and blocked
    unless it matches the sandbox branch.  This is the intended
    conservative behaviour.
    """

    def test_caret_ref_blocked(self):
        """^main is blocked — caret prefix is not recognized as negation."""
        err = validate_branch_isolation(["log", "^main"], META)
        assert err is not None

    def test_caret_disallowed_ref(self):
        err = validate_branch_isolation(["log", "^sandbox/other"], META)
        assert err is not None


# ---------------------------------------------------------------------------
# sandbox/other@{upstream} pattern
# ---------------------------------------------------------------------------


class TestRefSuffixPatterns:
    """Test ref@{upstream} and similar suffix patterns."""

    def test_own_branch_upstream(self):
        assert _is_allowed_ref(f"{SANDBOX}@{{upstream}}", SANDBOX) is True

    def test_disallowed_branch_upstream(self):
        assert _is_allowed_ref("sandbox/other@{upstream}", SANDBOX) is False

    def test_own_branch_at_number(self):
        assert _is_allowed_ref(f"{SANDBOX}@{{0}}", SANDBOX) is True


# ---------------------------------------------------------------------------
# --branches=, --remotes= value forms in ref-reading
# ---------------------------------------------------------------------------


class TestRefReadingValueFormFlags:
    """Test --branches=, --remotes= patterns in ref-reading isolation."""

    def test_branches_equals_blocked(self):
        err = validate_branch_isolation(["log", "--branches=sandbox/*"], META)
        assert err is not None

    def test_remotes_equals_blocked(self):
        err = validate_branch_isolation(["log", "--remotes=origin/*"], META)
        assert err is not None

    def test_glob_equals_blocked(self):
        err = validate_branch_isolation(["log", "--glob=refs/heads/*"], META)
        assert err is not None


# ---------------------------------------------------------------------------
# Reflog expire/delete sub-subcommands
# ---------------------------------------------------------------------------


class TestReflogSubSubcommands:
    """Test reflog expire/delete isolation."""

    def test_reflog_expire_own_branch(self):
        err = validate_branch_isolation(["reflog", "expire", SANDBOX], META)
        assert err is None

    def test_reflog_expire_disallowed(self):
        err = validate_branch_isolation(
            ["reflog", "expire", "sandbox/other"], META
        )
        assert err is not None

    def test_reflog_delete_own_branch(self):
        err = validate_branch_isolation(
            ["reflog", "delete", f"{SANDBOX}@{{0}}"], META
        )
        assert err is None

    def test_reflog_delete_disallowed(self):
        err = validate_branch_isolation(
            ["reflog", "delete", "sandbox/other@{0}"], META
        )
        assert err is not None

    def test_reflog_show_allowed(self):
        err = validate_branch_isolation(["reflog", "show", SANDBOX], META)
        assert err is None


# ---------------------------------------------------------------------------
# bisect with disallowed ref
# ---------------------------------------------------------------------------


class TestBisectIsolation:
    """Test bisect sub-subcommand isolation."""

    def test_bisect_start_own_branch(self):
        err = validate_branch_isolation(["bisect", "start", SANDBOX], META)
        assert err is None

    def test_bisect_start_disallowed(self):
        err = validate_branch_isolation(
            ["bisect", "start", "sandbox/other"], META
        )
        assert err is not None

    def test_bisect_good_not_checked(self):
        """Known gap: bisect good/bad refs are not validated."""
        err = validate_branch_isolation(
            ["bisect", "good", "sandbox/other"], META
        )
        # Currently not checked — this pins the existing behaviour
        assert err is None

    def test_bisect_bad_not_checked(self):
        """Known gap: bisect good/bad refs are not validated."""
        err = validate_branch_isolation(
            ["bisect", "bad", "sandbox/other"], META
        )
        assert err is None


# ---------------------------------------------------------------------------
# ls-remote output filtering
# ---------------------------------------------------------------------------


class TestLsRemoteOutputFiltering:
    """Test ls-remote output format filtering."""

    def test_ls_remote_filters_disallowed(self):
        output = (
            "abc123456789\trefs/heads/main\n"
            "def456789012\trefs/heads/sandbox/other\n"
            f"fed987654321\trefs/heads/{SANDBOX}\n"
            "111222333444\trefs/tags/v1.0\n"
        )
        result = _filter_ref_listing_output(output, ["ls-remote"], SANDBOX)
        assert "main" in result
        assert SANDBOX in result
        assert "v1.0" in result
        assert "sandbox/other" not in result

    def test_show_ref_filters_disallowed(self):
        output = (
            "abc123456789 refs/heads/main\n"
            "def456789012 refs/heads/sandbox/other\n"
        )
        result = _filter_ref_listing_output(output, ["show-ref"], SANDBOX)
        assert "main" in result
        assert "sandbox/other" not in result
