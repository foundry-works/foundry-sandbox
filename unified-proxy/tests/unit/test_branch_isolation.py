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
    _filter_ref_listing_output,
    _get_subcommand_args,
    _is_allowed_branch_name,
    _is_allowed_ref,
    _strip_rev_suffixes,
    validate_branch_isolation,
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

    # --- No metadata / no sandbox_branch → allow all ---

    def test_no_metadata_allows_all(self):
        assert validate_branch_isolation(["log", OTHER], None) is None

    def test_no_sandbox_branch_allows_all(self):
        assert validate_branch_isolation(["log", OTHER], {}) is None

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

    # --- rev-parse ---
    # rev-parse is not in _REF_READING_CMDS, so it passes through

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

    # --- Log --format without %d/%D uses SHA-anchored regex ---

    def test_log_format_without_d_uses_sha_anchored(self):
        # Without %d/%D, falls through to standard log decoration filter
        output = f"abc1234 (HEAD -> {SANDBOX}, origin/sandbox/other) msg\n"
        result = _filter_ref_listing_output(
            output, ["log", "--format=%H %s"], SANDBOX
        )
        assert "HEAD" in result
        assert "sandbox/other" not in result
