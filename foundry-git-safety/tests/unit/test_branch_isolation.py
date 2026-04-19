"""Tests for foundry_git_safety.branch_isolation."""

import os

import pytest

from foundry_git_safety.branch_isolation import (
    ValidationError,
    _extract_sha_args,
    _is_allowed_ref,
    normalize_pathspec_args,
    resolve_bare_repo_path,
    validate_branch_isolation,
)


def _make_metadata(
    sandbox_branch: str = "sandbox/test-alice",
    from_branch: str = "main",
    **extra,
) -> dict:
    """Build a standard metadata dict for testing."""
    meta: dict = {
        "sandbox_branch": sandbox_branch,
        "from_branch": from_branch,
    }
    meta.update(extra)
    return meta


# ---------------------------------------------------------------------------
# TestDenyByDefault
# ---------------------------------------------------------------------------


class TestDenyByDefault:
    """Fail-closed when metadata is missing or incomplete."""

    def test_none_metadata_allows(self):
        """None metadata returns None (no validation applied).

        This is intentional fail-open: when no flow metadata is available
        (e.g., local-only operation without proxy), branch isolation is
        not enforced. The proxy layer always provides metadata, so this
        path is only reachable outside the proxy context.
        """
        result = validate_branch_isolation(["checkout", "main"], None)
        assert result is None

    def test_empty_metadata_blocks(self):
        """Empty dict has no sandbox_branch -> blocks."""
        result = validate_branch_isolation(["checkout", "main"], {})
        assert isinstance(result, ValidationError)
        assert "missing sandbox_branch" in result.reason

    def test_none_sandbox_branch_blocks(self):
        """sandbox_branch=None is falsy -> blocks."""
        meta = _make_metadata(sandbox_branch=None)
        # _make_metadata won't let us pass None for sandbox_branch easily;
        # build manually.
        meta = {"sandbox_branch": None, "from_branch": "main"}
        result = validate_branch_isolation(["checkout", "main"], meta)
        assert isinstance(result, ValidationError)

    def test_empty_string_sandbox_branch_blocks(self):
        """Empty-string sandbox_branch is falsy -> blocks."""
        meta = {"sandbox_branch": "", "from_branch": "main"}
        result = validate_branch_isolation(["checkout", "main"], meta)
        assert isinstance(result, ValidationError)
        assert "missing sandbox_branch" in result.reason


# ---------------------------------------------------------------------------
# TestCheckoutIsolation
# ---------------------------------------------------------------------------


class TestCheckoutIsolation:
    """Tests for checkout/switch branch isolation."""

    def test_switch_to_own_branch_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["checkout", "sandbox/alice"], meta)
        assert result is None

    def test_switch_to_well_known_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["checkout", "main"], meta)
        assert result is None

    def test_switch_to_cross_sandbox_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["checkout", "sandbox/bob"], meta)
        assert isinstance(result, ValidationError)
        assert "cannot switch to" in result.reason

    def test_switch_command_own_branch_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["switch", "sandbox/alice"], meta)
        assert result is None

    def test_switch_command_cross_sandbox_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["switch", "sandbox/bob"], meta)
        assert isinstance(result, ValidationError)

    def test_checkout_b_new_branch_allowed_startpoint(self):
        """checkout -b <new> <start-point> where start-point is allowed."""
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["checkout", "-b", "feature/x", "main"], meta
        )
        assert result is None

    def test_checkout_b_blocked_bad_startpoint(self):
        """checkout -b <new> <start-point> where start-point is blocked."""
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["checkout", "-b", "feature/x", "sandbox/bob"], meta
        )
        assert isinstance(result, ValidationError)
        assert "start-point" in result.reason

    def test_checkout_head_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["checkout", "HEAD"], meta)
        assert result is None


# ---------------------------------------------------------------------------
# TestFetchIsolation
# ---------------------------------------------------------------------------


class TestFetchIsolation:
    """Tests for fetch/pull branch isolation."""

    def test_fetch_own_branch_refspec_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["fetch", "origin", "sandbox/alice"], meta
        )
        assert result is None

    def test_fetch_cross_sandbox_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["fetch", "origin", "sandbox/bob"], meta
        )
        assert isinstance(result, ValidationError)
        assert "refspec source" in result.reason

    def test_fetch_all_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["fetch", "--all"], meta
        )
        assert isinstance(result, ValidationError)
        assert "--all" in result.reason

    def test_pull_own_branch_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["pull", "origin", "sandbox/alice"], meta
        )
        assert result is None

    def test_fetch_no_refspec_allowed(self):
        """fetch with no refspecs (just remote) is allowed."""
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["fetch", "origin"], meta)
        assert result is None


# ---------------------------------------------------------------------------
# TestPushIsolation
# ---------------------------------------------------------------------------


class TestPushIsolation:
    """Tests for push branch isolation."""

    def test_push_own_branch_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["push", "origin", "sandbox/alice"], meta
        )
        assert result is None

    def test_push_cross_sandbox_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["push", "origin", "sandbox/bob"], meta
        )
        assert isinstance(result, ValidationError)

    def test_push_all_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["push", "--all"], meta)
        assert isinstance(result, ValidationError)
        assert "--all" in result.reason

    def test_push_mirror_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["push", "--mirror"], meta)
        assert isinstance(result, ValidationError)
        assert "--mirror" in result.reason

    def test_push_force_own_branch_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["push", "origin", "+sandbox/alice"], meta
        )
        assert result is None


# ---------------------------------------------------------------------------
# TestRefReadingIsolation
# ---------------------------------------------------------------------------


class TestRefReadingIsolation:
    """Tests for ref-reading command isolation (log, show, diff, etc.)."""

    def test_log_all_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["log", "--all"], meta)
        assert isinstance(result, ValidationError)
        assert "--all" in result.reason

    def test_log_branches_flag_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["log", "--branches"], meta)
        assert isinstance(result, ValidationError)

    def test_log_cross_sandbox_ref_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["log", "sandbox/bob"], meta
        )
        assert isinstance(result, ValidationError)
        assert "not allowed" in result.reason

    def test_log_own_ref_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["log", "sandbox/alice"], meta
        )
        assert result is None

    def test_log_main_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["log", "main"], meta)
        assert result is None

    def test_diff_own_branch_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["diff", "sandbox/alice"], meta
        )
        assert result is None

    def test_show_sha_allowed(self):
        """A SHA-like argument is allowed (reachability checked separately)."""
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["show", "a" * 40], meta
        )
        assert result is None

    def test_log_glob_prefix_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["log", "--glob=sandbox/*"], meta
        )
        assert isinstance(result, ValidationError)


# ---------------------------------------------------------------------------
# TestBranchDeletion
# ---------------------------------------------------------------------------


class TestBranchDeletion:
    """Tests for branch deletion isolation."""

    def test_delete_own_branch_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["branch", "-d", "sandbox/alice"], meta
        )
        assert result is None

    def test_delete_cross_sandbox_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["branch", "-D", "sandbox/bob"], meta
        )
        assert isinstance(result, ValidationError)
        assert "cannot delete" in result.reason

    def test_delete_main_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["branch", "-d", "main"], meta
        )
        assert result is None

    def test_delete_capital_d_blocked_cross_sandbox(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["branch", "-D", "sandbox/bob"], meta
        )
        assert isinstance(result, ValidationError)


# ---------------------------------------------------------------------------
# TestTagIsolation
# ---------------------------------------------------------------------------


class TestTagIsolation:
    """Tests for tag creation isolation."""

    def test_tag_with_allowed_commitish(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["tag", "v1.0", "main"], meta
        )
        assert result is None

    def test_tag_with_own_branch_commitish(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["tag", "v1.0", "sandbox/alice"], meta
        )
        assert result is None

    def test_tag_with_cross_sandbox_blocked(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["tag", "v1.0", "sandbox/bob"], meta
        )
        assert isinstance(result, ValidationError)
        assert "commit-ish" in result.reason

    def test_tag_no_commitish_allowed(self):
        """git tag v1.0 (no commit-ish) is always allowed."""
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(["tag", "v1.0"], meta)
        assert result is None

    def test_tag_with_sha_commitish_allowed(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        result = validate_branch_isolation(
            ["tag", "v1.0", "a" * 40], meta
        )
        assert result is None


# ---------------------------------------------------------------------------
# TestNormalizePathspecArgs
# ---------------------------------------------------------------------------


class TestNormalizePathspecArgs:
    """Tests for normalize_pathspec_args()."""

    def test_inserts_separator_before_path(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        args = ["diff", "docs/foo.md"]
        new_args, changed = normalize_pathspec_args(args, meta)
        assert changed is True
        assert new_args == ["diff", "--", "docs/foo.md"]

    def test_no_insertion_when_separator_present(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        args = ["diff", "--", "docs/foo.md"]
        new_args, changed = normalize_pathspec_args(args, meta)
        assert changed is False
        assert new_args == args

    def test_non_path_args_untouched(self):
        meta = _make_metadata(sandbox_branch="sandbox/alice")
        args = ["log", "main"]
        new_args, changed = normalize_pathspec_args(args, meta)
        assert changed is False
        assert new_args == args

    def test_no_metadata_returns_unchanged(self):
        args = ["diff", "docs/foo.md"]
        new_args, changed = normalize_pathspec_args(args, None)
        assert changed is False
        assert new_args == args

    def test_no_sandbox_branch_returns_unchanged(self):
        args = ["diff", "docs/foo.md"]
        new_args, changed = normalize_pathspec_args(args, {})
        assert changed is False
        assert new_args == args


# ---------------------------------------------------------------------------
# TestIsAllowedRef
# ---------------------------------------------------------------------------


class TestIsAllowedRef:
    """Tests for _is_allowed_ref()."""

    def test_head_allowed(self):
        assert _is_allowed_ref("HEAD", "sandbox/alice") is True

    def test_tag_allowed(self):
        assert _is_allowed_ref("refs/tags/v1.0", "sandbox/alice") is True

    def test_tags_prefix_allowed(self):
        assert _is_allowed_ref("tags/v1.0", "sandbox/alice") is True

    def test_own_branch_allowed(self):
        assert _is_allowed_ref("sandbox/alice", "sandbox/alice") is True

    def test_cross_sandbox_blocked(self):
        assert _is_allowed_ref("sandbox/bob", "sandbox/alice") is False

    def test_sha_allowed(self):
        assert _is_allowed_ref("a" * 40, "sandbox/alice") is True

    def test_well_known_branch_allowed(self):
        assert _is_allowed_ref("main", "sandbox/alice") is True

    def test_well_known_prefix_same_prefix_allowed(self):
        """release/* branches visible from a release/* sandbox."""
        assert _is_allowed_ref("release/v1.0", "release/my-fix") is True

    def test_well_known_prefix_cross_prefix_blocked(self):
        """release/* branches NOT visible from a non-release sandbox."""
        assert _is_allowed_ref("release/v1.0", "sandbox/alice") is False

    def test_remote_tracking_own_branch_allowed(self):
        assert _is_allowed_ref(
            "refs/remotes/origin/sandbox/alice", "sandbox/alice"
        ) is True

    def test_remote_tracking_blocked_branch(self):
        assert _is_allowed_ref(
            "refs/remotes/origin/sandbox/bob", "sandbox/alice"
        ) is False

    def test_fetch_head_blocked(self):
        assert _is_allowed_ref("FETCH_HEAD", "sandbox/alice") is False

    def test_at_form_allowed(self):
        assert _is_allowed_ref("@{u}", "sandbox/alice") is True

    def test_range_both_allowed(self):
        assert _is_allowed_ref("main..sandbox/alice", "sandbox/alice") is True

    def test_range_one_blocked(self):
        assert _is_allowed_ref("main..sandbox/bob", "sandbox/alice") is False

    def test_stash_allowed(self):
        assert _is_allowed_ref("stash", "sandbox/alice") is True

    def test_base_branch_allowed(self):
        assert _is_allowed_ref("develop", "sandbox/alice", base_branch="develop") is True

    def test_head_with_suffix_allowed(self):
        assert _is_allowed_ref("HEAD~3", "sandbox/alice") is True

    def test_three_dot_range(self):
        assert _is_allowed_ref("main...sandbox/alice", "sandbox/alice") is True


# ---------------------------------------------------------------------------
# TestResolveBareRepoPath
# ---------------------------------------------------------------------------


class TestResolveBareRepoPath:
    """Tests for resolve_bare_repo_path()."""

    def test_nonexistent_path_returns_none(self):
        result = resolve_bare_repo_path("/nonexistent/path/that/does/not/exist")
        assert result is None

    def test_git_file_chain(self, tmp_path):
        """Follow .git file -> gitdir -> commondir chain."""
        # Create a bare repo directory
        bare_repo = tmp_path / "bare.git"
        bare_repo.mkdir()

        # Create gitdir (worktree-specific)
        gitdir = tmp_path / "worktrees" / "wt1"
        gitdir.mkdir(parents=True)

        # Create commondir in gitdir pointing to bare repo
        (gitdir / "commondir").write_text(str(bare_repo) + "\n")

        # Create worktree root with .git file pointing to gitdir
        worktree = tmp_path / "worktree1"
        worktree.mkdir()
        (worktree / ".git").write_text("gitdir: " + str(gitdir) + "\n")

        result = resolve_bare_repo_path(str(worktree))
        assert result is not None
        assert os.path.realpath(str(bare_repo)) == result

    def test_git_dir_without_commondir(self, tmp_path):
        """A .git directory (not a file) without commondir returns itself."""
        repo = tmp_path / "repo"
        repo.mkdir()
        dot_git = repo / ".git"
        dot_git.mkdir()

        result = resolve_bare_repo_path(str(repo))
        assert result is not None
        assert result == os.path.realpath(str(dot_git))

    def test_git_dir_with_commondir(self, tmp_path):
        """A .git directory with a commondir file follows it."""
        bare_repo = tmp_path / "bare.git"
        bare_repo.mkdir()

        repo = tmp_path / "repo"
        repo.mkdir()
        dot_git = repo / ".git"
        dot_git.mkdir()
        (dot_git / "commondir").write_text(str(bare_repo) + "\n")

        result = resolve_bare_repo_path(str(repo))
        assert result is not None
        assert result == os.path.realpath(str(bare_repo))

    def test_git_file_missing_gitdir_dir(self, tmp_path):
        """If .git file points to a non-existent gitdir, returns None."""
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        (worktree / ".git").write_text("gitdir: /nonexistent/gitdir\n")

        result = resolve_bare_repo_path(str(worktree))
        assert result is None

    def test_git_file_invalid_content(self, tmp_path):
        """If .git file doesn't start with gitdir:, returns None."""
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        (worktree / ".git").write_text("something else\n")

        result = resolve_bare_repo_path(str(worktree))
        assert result is None


# ---------------------------------------------------------------------------
# TestExtractShaArgs
# ---------------------------------------------------------------------------


class TestExtractShaArgs:
    """Tests for _extract_sha_args()."""

    def test_extracts_bare_sha(self):
        result = _extract_sha_args(["a" * 40])
        assert result == ["a" * 40]

    def test_extracts_abbreviated_sha(self):
        result = _extract_sha_args(["a" * 12])
        assert result == ["a" * 12]

    def test_skips_short_hex(self):
        result = _extract_sha_args(["abc1234"])
        assert result == []

    def test_stops_at_separator(self):
        result = _extract_sha_args(["a" * 40, "--", "b" * 40])
        assert result == ["a" * 40]

    def test_extracts_sha_from_range(self):
        result = _extract_sha_args(["a" * 40 + ".." + "b" * 40])
        assert result == ["a" * 40, "b" * 40]

    def test_skips_flags(self):
        result = _extract_sha_args(["--oneline", "a" * 40])
        assert result == ["a" * 40]

    def test_skips_value_flag_args(self):
        """Flags like -n consume the next arg."""
        result = _extract_sha_args(["-n", "5", "a" * 40])
        assert result == ["a" * 40]

    def test_strips_rev_suffixes(self):
        sha = "a" * 40
        result = _extract_sha_args([sha + "~3"])
        assert result == [sha]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
