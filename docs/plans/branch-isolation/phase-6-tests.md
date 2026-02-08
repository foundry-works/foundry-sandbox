# Phase 6: Automated Tests

## 6A. Test setup

**File:** `unified-proxy/tests/unit/test_branch_isolation.py`

The proxy already has pytest infrastructure (`unified-proxy/pytest.ini`, `unified-proxy/tests/`). Add these tests under `tests/unit/` and run with:

```bash
cd unified-proxy && python -m pytest tests/unit/test_branch_isolation.py -v
```

## 6B. Test `_get_subcommand_args` and `_is_allowed_ref`

```python
import pytest
from git_operations import (
    _get_subcommand_args, _is_allowed_ref, _is_allowed_branch_name,
    _strip_rev_suffixes, validate_branch_isolation,
    _filter_ref_listing_output,
)


class TestGetSubcommandArgs:
    """Unit tests for the subcommand extraction helper."""

    def test_simple_command(self):
        sub, args = _get_subcommand_args(["log", "--oneline"])
        assert sub == "log"
        assert args == ["--oneline"]

    def test_global_c_flag(self):
        sub, args = _get_subcommand_args(["-c", "core.pager=less", "log"])
        assert sub == "log"
        assert args == []

    def test_compact_c_flag(self):
        sub, args = _get_subcommand_args(["-ccore.pager=less", "diff", "HEAD"])
        assert sub == "diff"
        assert args == ["HEAD"]

    def test_double_dash_terminator(self):
        """'--' terminates global options; next arg is the subcommand."""
        sub, args = _get_subcommand_args(["--", "log", "--all"])
        assert sub == "log"
        assert args == ["--all"]

    def test_empty_args(self):
        sub, args = _get_subcommand_args([])
        assert sub is None
        assert args == []

    def test_only_flags(self):
        sub, args = _get_subcommand_args(["-c", "key=val"])
        assert sub is None
        assert args == []

    def test_global_C_flag(self):
        """-C <path> is a two-token global flag -- path is not the subcommand."""
        sub, args = _get_subcommand_args(["-C", "/some/path", "log", "--oneline"])
        assert sub == "log"
        assert args == ["--oneline"]

    def test_global_git_dir_flag(self):
        sub, args = _get_subcommand_args(["--git-dir", "/path/to/.git", "status"])
        assert sub == "status"
        assert args == []

    def test_global_work_tree_flag(self):
        sub, args = _get_subcommand_args(["--work-tree", "/path", "diff", "HEAD"])
        assert sub == "diff"
        assert args == ["HEAD"]

    def test_global_flag_equals_form(self):
        """--git-dir=/path (single token) should also be handled."""
        sub, args = _get_subcommand_args(["--git-dir=/path/to/.git", "log"])
        assert sub == "log"
        assert args == []

    def test_multiple_global_flags(self):
        sub, args = _get_subcommand_args(
            ["-C", "/path", "-c", "core.pager=less", "show", "HEAD"]
        )
        assert sub == "show"
        assert args == ["HEAD"]


class TestStripRevSuffixes:
    """Unit tests for revision suffix stripping."""

    def test_tilde_n(self):
        assert _strip_rev_suffixes("main~3") == "main"

    def test_caret_n(self):
        assert _strip_rev_suffixes("branch^2") == "branch"

    def test_bare_tilde(self):
        assert _strip_rev_suffixes("HEAD~") == "HEAD"

    def test_bare_caret(self):
        assert _strip_rev_suffixes("HEAD^") == "HEAD"

    def test_chained_suffixes(self):
        assert _strip_rev_suffixes("main~1^2~3") == "main"
        assert _strip_rev_suffixes("branch^2~1") == "branch"

    def test_no_suffix(self):
        assert _strip_rev_suffixes("main") == "main"
        assert _strip_rev_suffixes("feature/branch") == "feature/branch"

    def test_sha_unchanged(self):
        assert _strip_rev_suffixes("abcdef123456") == "abcdef123456"


class TestIsAllowedRef:
    """Unit tests for branch isolation ref checking."""

    def test_head_relative(self):
        assert _is_allowed_ref("HEAD~2", "my-branch")
        assert _is_allowed_ref("HEAD", "my-branch")
        assert _is_allowed_ref("HEAD^", "my-branch")

    def test_upstream_ref(self):
        assert _is_allowed_ref("@{upstream}", "my-branch")
        assert _is_allowed_ref("branch@{1}", "my-branch")

    def test_own_branch(self):
        assert _is_allowed_ref("my-branch", "my-branch")
        assert _is_allowed_ref("refs/heads/my-branch", "my-branch")

    def test_well_known_branches(self):
        assert _is_allowed_ref("main", "my-branch")
        assert _is_allowed_ref("master", "my-branch")
        assert _is_allowed_ref("develop", "my-branch")
        assert _is_allowed_ref("release/1.0", "my-branch")
        assert _is_allowed_ref("hotfix/urgent", "my-branch")

    def test_other_sandbox_blocked(self):
        assert not _is_allowed_ref("other-sandbox-branch", "my-branch")
        assert not _is_allowed_ref("refs/heads/other-sandbox", "my-branch")

    def test_remote_other_sandbox_blocked(self):
        """Remote tracking refs for other sandboxes should be blocked."""
        assert not _is_allowed_ref("origin/other-sandbox", "my-branch")
        assert not _is_allowed_ref("refs/remotes/origin/other-sandbox", "my-branch")

    def test_remote_well_known_allowed(self):
        assert _is_allowed_ref("origin/main", "my-branch")
        assert _is_allowed_ref("refs/remotes/origin/main", "my-branch")
        assert _is_allowed_ref("origin/my-branch", "my-branch")

    def test_tags_allowed(self):
        assert _is_allowed_ref("refs/tags/v1.0", "my-branch")
        assert _is_allowed_ref("tags/v1.0", "my-branch")

    def test_sha_hashes(self):
        # 12+ hex chars -> allowed (SHA)
        assert _is_allowed_ref("abcdef123456", "my-branch")
        assert _is_allowed_ref("a" * 40, "my-branch")
        # Short hex strings -> blocked (could be branch names)
        assert not _is_allowed_ref("deadbeef", "my-branch")
        assert not _is_allowed_ref("cafebabe", "my-branch")

    def test_range_operators(self):
        assert _is_allowed_ref("main..my-branch", "my-branch")
        assert _is_allowed_ref("main...my-branch", "my-branch")
        assert not _is_allowed_ref("main..other-sandbox", "my-branch")

    def test_range_with_caret(self):
        assert _is_allowed_ref("^main..my-branch", "my-branch")

    def test_fetch_head_blocked(self):
        """FETCH_HEAD can contain commits from any fetched branch."""
        assert not _is_allowed_ref("FETCH_HEAD", "my-branch")

    def test_branch_with_slashes(self):
        """Branch names with slashes (e.g. user/feature) should work."""
        assert _is_allowed_ref("user/my-feature", "user/my-feature")
        assert not _is_allowed_ref("user/other-feature", "user/my-feature")

    def test_rev_suffixes_on_allowed_refs(self):
        """Refs with ~N/^N suffixes should resolve to the base ref."""
        assert _is_allowed_ref("main~3", "my-branch")
        assert _is_allowed_ref("my-branch^2", "my-branch")
        assert _is_allowed_ref("develop~1^2", "my-branch")
        assert _is_allowed_ref("main~1^2~3", "my-branch")
        assert _is_allowed_ref("origin/main~5", "my-branch")

    def test_rev_suffixes_on_blocked_refs(self):
        """Suffixes don't bypass isolation -- base ref is still checked."""
        assert not _is_allowed_ref("other-sandbox~3", "my-branch")
        assert not _is_allowed_ref("other-sandbox^2", "my-branch")
        assert not _is_allowed_ref("FETCH_HEAD~1", "my-branch")

    def test_range_with_rev_suffixes(self):
        """Range operators combined with rev suffixes."""
        assert _is_allowed_ref("main~3..my-branch^2", "my-branch")
        assert not _is_allowed_ref("main~3..other-sandbox^2", "my-branch")
```

## 6C. Test `validate_branch_isolation`

```python
class TestValidateBranchIsolation:
    """Unit tests for the full isolation validator."""

    META = {"sandbox_branch": "my-branch"}

    def test_no_metadata_allows_all(self):
        assert validate_branch_isolation(["log", "anything"], None) is None

    def test_no_sandbox_branch_allows_all(self):
        assert validate_branch_isolation(
            ["log", "anything"], {"sandbox_branch": ""}
        ) is None

    def test_blocks_other_branch_in_log(self):
        err = validate_branch_isolation(
            ["log", "other-sandbox"], self.META
        )
        assert err is not None
        assert "other-sandbox" in err.reason

    def test_allows_own_branch(self):
        assert validate_branch_isolation(
            ["log", "my-branch"], self.META
        ) is None

    def test_pathspecs_after_double_dash(self):
        # Args after -- are pathspecs, not refs -- should not be checked
        assert validate_branch_isolation(
            ["log", "--", "other-sandbox"], self.META
        ) is None

    def test_paths_without_double_dash_are_checked_as_refs(self):
        """File paths without -- separator are treated as refs and blocked.

        Users must use -- to separate refs from paths (git standard).
        No pathspec heuristic -- avoids false-allows on branch names
        like src/exploit.py or feature/component.tsx.
        """
        err = validate_branch_isolation(
            ["log", "my-branch", "src/file.py"], self.META
        )
        assert err is not None

    def test_paths_with_double_dash_allowed(self):
        """Same paths are fine when properly separated with --."""
        assert validate_branch_isolation(
            ["log", "my-branch", "--", "src/file.py"], self.META
        ) is None

    def test_blocks_branch_deletion(self):
        err = validate_branch_isolation(
            ["branch", "-D", "other-sandbox"], self.META
        )
        assert err is not None

    def test_blocks_checkout_other_branch(self):
        err = validate_branch_isolation(
            ["checkout", "other-sandbox"], self.META
        )
        assert err is not None

    def test_blocks_checkout_b_startpoint(self):
        """checkout -b new-branch start-point: start-point must be checked."""
        err = validate_branch_isolation(
            ["checkout", "-b", "new-branch", "other-sandbox"], self.META
        )
        assert err is not None
        assert "other-sandbox" in err.reason

    def test_allows_checkout_b_from_own_branch(self):
        assert validate_branch_isolation(
            ["checkout", "-b", "new-branch", "my-branch"], self.META
        ) is None

    def test_blocks_switch_c_startpoint(self):
        err = validate_branch_isolation(
            ["switch", "-c", "new-branch", "other-sandbox"], self.META
        )
        assert err is not None

    def test_blocks_log_all_flag(self):
        """--all exposes all branches -- must be blocked."""
        err = validate_branch_isolation(
            ["log", "--all"], self.META
        )
        assert err is not None
        assert "--all" in err.reason

    def test_blocks_log_branches_flag(self):
        err = validate_branch_isolation(
            ["log", "--branches"], self.META
        )
        assert err is not None

    def test_blocks_log_remotes_flag(self):
        err = validate_branch_isolation(
            ["log", "--remotes"], self.META
        )
        assert err is not None

    def test_for_each_ref_not_input_blocked(self):
        """for-each-ref is handled by output filtering, not input blocking."""
        assert validate_branch_isolation(
            ["for-each-ref", "refs/heads/"], self.META
        ) is None

    def test_ls_remote_not_input_blocked(self):
        assert validate_branch_isolation(
            ["ls-remote", ".", "refs/heads/*"], self.META
        ) is None

    def test_blocks_fetch_other_branch(self):
        """git fetch origin other-sandbox-branch must be blocked."""
        err = validate_branch_isolation(
            ["fetch", "origin", "other-sandbox"], self.META
        )
        assert err is not None
        assert "other-sandbox" in err.reason

    def test_allows_fetch_own_branch(self):
        assert validate_branch_isolation(
            ["fetch", "origin", "my-branch"], self.META
        ) is None

    def test_allows_fetch_well_known(self):
        assert validate_branch_isolation(
            ["fetch", "origin", "main"], self.META
        ) is None

    def test_allows_fetch_no_refspec(self):
        """Plain `git fetch origin` (no refspec) should be allowed."""
        assert validate_branch_isolation(
            ["fetch", "origin"], self.META
        ) is None

    def test_fetch_depth_flag_not_misread_as_remote(self):
        """--depth N should not count N as a positional (the remote name)."""
        err = validate_branch_isolation(
            ["fetch", "--depth", "1", "origin", "other-sandbox"], self.META
        )
        assert err is not None
        assert "other-sandbox" in err.reason

    def test_fetch_depth_equals_form(self):
        """--depth=1 (single token) should also work correctly."""
        err = validate_branch_isolation(
            ["fetch", "--depth=1", "origin", "other-sandbox"], self.META
        )
        assert err is not None

    def test_blocks_fetch_explicit_refspec(self):
        """git fetch origin +other-sandbox:refs/remotes/origin/other must be blocked."""
        err = validate_branch_isolation(
            ["fetch", "origin", "+other-sandbox:refs/remotes/origin/other-sandbox"],
            self.META,
        )
        assert err is not None

    def test_blocks_pull_other_branch(self):
        """git pull origin other-sandbox-branch must be blocked."""
        err = validate_branch_isolation(
            ["pull", "origin", "other-sandbox"], self.META
        )
        assert err is not None

    def test_blocks_rev_parse_other_branch(self):
        """git rev-parse other-sandbox-branch leaks SHAs."""
        err = validate_branch_isolation(
            ["rev-parse", "other-sandbox"], self.META
        )
        assert err is not None

    def test_allows_rev_parse_own_branch(self):
        assert validate_branch_isolation(
            ["rev-parse", "my-branch"], self.META
        ) is None

    def test_blocks_worktree_add_other_branch(self):
        """git worktree add ../path other-sandbox-branch must be blocked."""
        err = validate_branch_isolation(
            ["worktree", "add", "../new-tree", "other-sandbox"], self.META
        )
        assert err is not None
        assert "other-sandbox" in err.reason

    def test_allows_worktree_add_own_branch(self):
        assert validate_branch_isolation(
            ["worktree", "add", "../new-tree", "my-branch"], self.META
        ) is None

    def test_allows_worktree_add_no_commitish(self):
        """git worktree add ../path (no explicit branch) should be allowed."""
        assert validate_branch_isolation(
            ["worktree", "add", "../new-tree"], self.META
        ) is None

    def test_blocks_reset_other_branch(self):
        """git reset --hard other-sandbox-branch must be blocked."""
        err = validate_branch_isolation(
            ["reset", "--hard", "other-sandbox"], self.META
        )
        assert err is not None
        assert "other-sandbox" in err.reason

    def test_allows_reset_own_branch(self):
        assert validate_branch_isolation(
            ["reset", "--hard", "my-branch"], self.META
        ) is None

    def test_allows_reset_head_relative(self):
        assert validate_branch_isolation(
            ["reset", "--soft", "HEAD~3"], self.META
        ) is None

    def test_blocks_bisect_start_other_branch(self):
        """git bisect start <bad> <good> -- both refs must be checked."""
        err = validate_branch_isolation(
            ["bisect", "start", "other-sandbox", "main"], self.META
        )
        assert err is not None
        assert "other-sandbox" in err.reason

    def test_allows_bisect_start_own_refs(self):
        assert validate_branch_isolation(
            ["bisect", "start", "my-branch", "main"], self.META
        ) is None

    def test_bisect_good_bad_not_checked(self):
        """bisect good/bad operate on HEAD -- no ref args to check."""
        assert validate_branch_isolation(
            ["bisect", "good"], self.META
        ) is None
        assert validate_branch_isolation(
            ["bisect", "bad"], self.META
        ) is None

    def test_blocks_checkout_orphan_startpoint(self):
        """checkout --orphan new start-point: start-point must be checked."""
        err = validate_branch_isolation(
            ["checkout", "--orphan", "new-branch", "other-sandbox"], self.META
        )
        assert err is not None
        assert "other-sandbox" in err.reason

    def test_allows_checkout_orphan_from_own_branch(self):
        assert validate_branch_isolation(
            ["checkout", "--orphan", "new-branch", "my-branch"], self.META
        ) is None

    def test_blocks_name_rev_other_branch(self):
        """git name-rev resolves SHAs to branch names -- leaks branch names."""
        err = validate_branch_isolation(
            ["name-rev", "other-sandbox"], self.META
        )
        assert err is not None

    def test_blocks_shortlog_other_branch(self):
        err = validate_branch_isolation(
            ["shortlog", "other-sandbox"], self.META
        )
        assert err is not None

    def test_allows_log_with_rev_suffixes(self):
        """main~3, my-branch^2 should be allowed (suffix stripped to base ref)."""
        assert validate_branch_isolation(
            ["log", "main~3"], self.META
        ) is None
        assert validate_branch_isolation(
            ["log", "my-branch^2"], self.META
        ) is None

    def test_blocks_log_with_rev_suffixes_on_other(self):
        """Suffixes on other sandbox's branch should still be blocked."""
        err = validate_branch_isolation(
            ["log", "other-sandbox~3"], self.META
        )
        assert err is not None

    def test_blocks_diff_second_ref(self):
        """git diff my-branch other-sandbox -- second arg is a ref too."""
        err = validate_branch_isolation(
            ["diff", "my-branch", "other-sandbox"], self.META
        )
        assert err is not None

    def test_allows_log_with_flags_before_ref(self):
        """git log -p my-branch -- flags before the ref should not interfere."""
        assert validate_branch_isolation(
            ["log", "-p", "my-branch"], self.META
        ) is None

    def test_error_message_suggests_double_dash(self):
        """Error message should suggest using -- for path separation."""
        err = validate_branch_isolation(
            ["log", "other-sandbox"], self.META
        )
        assert err is not None
        assert "--" in err.reason

    def test_blocks_log_glob_flag(self):
        """--glob=refs/heads/* achieves the same result as --all."""
        err = validate_branch_isolation(
            ["log", "--glob=refs/heads/*"], self.META
        )
        assert err is not None
        assert "--glob" in err.reason

    def test_blocks_log_glob_bare(self):
        """--glob without = (two-token form) must also be blocked."""
        err = validate_branch_isolation(
            ["log", "--glob", "refs/heads/*"], self.META
        )
        assert err is not None

    def test_blocks_branches_pattern(self):
        """--branches=sandbox-* expands to matching branches."""
        err = validate_branch_isolation(
            ["log", "--branches=sandbox-*"], self.META
        )
        assert err is not None
        assert "--branches" in err.reason

    def test_blocks_remotes_pattern(self):
        """--remotes=origin/sandbox-* expands to matching remote refs."""
        err = validate_branch_isolation(
            ["log", "--remotes=origin/*"], self.META
        )
        assert err is not None

    def test_blocks_archive_other_branch(self):
        """git archive other-sandbox-branch extracts another sandbox's tree."""
        err = validate_branch_isolation(
            ["archive", "other-sandbox"], self.META
        )
        assert err is not None

    def test_allows_archive_own_branch(self):
        assert validate_branch_isolation(
            ["archive", "my-branch"], self.META
        ) is None

    def test_blocks_format_patch_other_branch(self):
        """git format-patch other-sandbox..main exposes another sandbox's patches."""
        err = validate_branch_isolation(
            ["format-patch", "other-sandbox..main"], self.META
        )
        assert err is not None

    def test_allows_format_patch_own_range(self):
        assert validate_branch_isolation(
            ["format-patch", "main..my-branch"], self.META
        ) is None

    def test_show_ref_not_input_blocked(self):
        """show-ref is handled by output filtering, not input blocking."""
        assert validate_branch_isolation(
            ["show-ref", "--heads"], self.META
        ) is None
```

## 6D. Test output filtering

```python
class TestFilterRefListingOutput:
    """Unit tests for ref listing output filtering."""

    def test_branch_listing_hides_other(self):
        stdout = "* my-branch\n  main\n  other-sandbox\n"
        result = _filter_ref_listing_output(
            ["branch"], stdout, "my-branch"
        )
        assert "my-branch" in result
        assert "main" in result
        assert "other-sandbox" not in result

    def test_for_each_ref_hides_other(self):
        stdout = (
            "abc123 commit refs/heads/main\n"
            "def456 commit refs/heads/my-branch\n"
            "789abc commit refs/heads/other-sandbox\n"
        )
        result = _filter_ref_listing_output(
            ["for-each-ref", "refs/heads/"], stdout, "my-branch"
        )
        assert "refs/heads/main" in result
        assert "refs/heads/my-branch" in result
        assert "refs/heads/other-sandbox" not in result

    def test_for_each_ref_keeps_tags(self):
        stdout = (
            "abc123 commit refs/tags/v1.0\n"
            "def456 commit refs/heads/other-sandbox\n"
        )
        result = _filter_ref_listing_output(
            ["for-each-ref"], stdout, "my-branch"
        )
        assert "refs/tags/v1.0" in result
        assert "other-sandbox" not in result

    def test_branch_verbose_hides_other(self):
        """git branch -v output includes SHA and commit message."""
        stdout = (
            "* my-branch  abc1234 My commit message\n"
            "  main       def5678 Another commit\n"
            "  other-sandbox 789abc0 Secret commit\n"
        )
        result = _filter_ref_listing_output(
            ["branch", "-v"], stdout, "my-branch"
        )
        assert "my-branch" in result
        assert "main" in result
        assert "other-sandbox" not in result

    def test_log_decoration_hides_other(self):
        """git log --oneline decorations should hide other sandboxes."""
        stdout = (
            "abc1234 (HEAD -> my-branch, origin/main, origin/other-sandbox) msg\n"
            "def5678 (tag: v1.0) another msg\n"
        )
        result = _filter_ref_listing_output(
            ["log", "--oneline"], stdout, "my-branch"
        )
        assert "my-branch" in result
        assert "origin/main" in result
        assert "tag: v1.0" in result
        assert "other-sandbox" not in result

    def test_log_decoration_preserves_head(self):
        stdout = "abc1234 (HEAD -> my-branch) msg\n"
        result = _filter_ref_listing_output(
            ["log"], stdout, "my-branch"
        )
        assert "HEAD -> my-branch" in result

    def test_log_decoration_detached_head(self):
        """Detached HEAD annotations should be preserved."""
        stdout = "abc1234 (HEAD detached at abc1234) msg\n"
        result = _filter_ref_listing_output(
            ["log"], stdout, "my-branch"
        )
        assert "HEAD detached at abc1234" in result

    def test_log_decoration_all_removed(self):
        """If all refs in a decoration are removed, the parens are stripped."""
        stdout = "abc1234 (origin/other-sandbox) msg\n"
        result = _filter_ref_listing_output(
            ["log"], stdout, "my-branch"
        )
        assert "other-sandbox" not in result
        assert "()" not in result

    def test_log_decoration_ignores_commit_message_parens(self):
        """Parenthesized text in commit messages should NOT be filtered."""
        stdout = "abc1234 (HEAD -> my-branch) Fix bug (see issue #123)\n"
        result = _filter_ref_listing_output(
            ["log"], stdout, "my-branch"
        )
        assert "see issue #123" in result
        assert "HEAD -> my-branch" in result

    def test_show_ref_hides_other(self):
        """git show-ref --heads output should hide other sandboxes."""
        stdout = (
            "abc123 refs/heads/main\n"
            "def456 refs/heads/my-branch\n"
            "789abc refs/heads/other-sandbox\n"
        )
        result = _filter_ref_listing_output(
            ["show-ref", "--heads"], stdout, "my-branch"
        )
        assert "refs/heads/main" in result
        assert "refs/heads/my-branch" in result
        assert "refs/heads/other-sandbox" not in result

    def test_log_format_pct_d_hides_other(self):
        """--format=%d produces parenthesized decorations without SHA prefix."""
        stdout = " (HEAD -> my-branch, origin/main, origin/other-sandbox)\n"
        result = _filter_ref_listing_output(
            ["log", "--format=%d"], stdout, "my-branch"
        )
        assert "my-branch" in result
        assert "origin/main" in result
        assert "other-sandbox" not in result

    def test_log_format_pct_D_hides_other(self):
        """--format=%D produces bare decorations (no parens)."""
        stdout = "HEAD -> my-branch, origin/main, origin/other-sandbox\n"
        result = _filter_ref_listing_output(
            ["log", "--format=%D"], stdout, "my-branch"
        )
        assert "my-branch" in result
        assert "origin/main" in result
        assert "other-sandbox" not in result

    def test_log_format_without_d_unchanged(self):
        """--format without %d/%D should use SHA-anchored regex."""
        stdout = "abc1234 (HEAD -> my-branch, origin/other-sandbox) msg\n"
        result = _filter_ref_listing_output(
            ["log", "--format=%H %s"], stdout, "my-branch"
        )
        # SHA-anchored regex handles this normally
        assert "my-branch" in result
```

## 6E. Integration and security regression tests

Add end-to-end tests so isolation regressions are caught outside unit scope.

**Files:**
- `tests/integration/test_branch_isolation_flow.py` (new)
- `tests/security/test_git_branch_isolation.sh` (new)

**Integration coverage (`tests/integration/test_branch_isolation_flow.py`):**
- Create two sandboxes on the same repo and register both proxies.
- Assert blocked cross-sandbox refs for `log/show/diff/cherry-pick/rev-parse/worktree add/fetch`.
- Assert filtered output for `branch -a`, `show-ref --heads`, `for-each-ref`, `log --decorate`.
- Assert legacy startup without branch metadata fails closed unless override is set.
- Assert `fetch`/`pull` deny when lock scope cannot be resolved.

**Security coverage (`tests/security/test_git_branch_isolation.sh`):**
- Treat branch-name disclosure and SHA-based access as threat cases.
- Verify `reflog`, `notes`, `for-each-ref --format`, and `git log --source` do not expose another sandbox's private branch names after Phase 7 controls.
- Emit pass/fail output suitable for CI gating.

Run in CI:

```bash
./tests/run.sh
./tests/security/run.sh
```

## Verification

- Unit: `cd unified-proxy && python -m pytest tests/unit/test_branch_isolation.py -v`
- Integration: `python -m pytest tests/integration/test_branch_isolation_flow.py -v`
- Security: `./tests/security/run.sh`
