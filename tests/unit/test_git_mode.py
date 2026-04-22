"""Tests for git_mode.py — dual-layout path validation and resolution."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from foundry_sandbox.commands.git_mode import (
    _apply_git_mode,
    _is_within,
    _resolve_git_paths,
    _validate_git_paths,
    _validate_legacy_layout_paths,
    _validate_new_layout_paths,
)


# ---------------------------------------------------------------------------
# Helpers to create realistic filesystem structures for both layouts
# ---------------------------------------------------------------------------


def _setup_new_layout(tmp_path: Path) -> dict[str, Path]:
    """Create an sbx-managed worktree on disk and return key paths."""
    repo_root = tmp_path / "my-repo"
    worktree = repo_root / ".sbx" / "sandbox1-worktrees" / "feature"
    gitdir = repo_root / ".git" / "worktrees" / "feature"
    repo_git = repo_root / ".git"

    worktree.mkdir(parents=True)
    gitdir.mkdir(parents=True)
    repo_git.mkdir(parents=True, exist_ok=True)

    # worktree/.git → gitdir
    (worktree / ".git").write_text(f"gitdir: {gitdir}\n")
    # gitdir/commondir → repo .git
    (gitdir / "commondir").write_text("../..\n")
    # gitdir HEAD
    (gitdir / "HEAD").write_text("ref: refs/heads/feature\n")
    # repo .git config (must exist for _apply_git_mode)
    (repo_git / "config").write_text("[core]\n\trepositoryformatversion = 0\n")

    return {
        "repo_root": repo_root,
        "worktree": worktree,
        "gitdir": gitdir,
        "repo_git": repo_git,
    }


def _setup_legacy_layout(tmp_path: Path) -> dict[str, Path]:
    """Create a legacy cast-managed worktree on disk."""
    worktrees_dir = tmp_path / "worktrees"
    repos_dir = tmp_path / "repos"
    bare_repo = repos_dir / "github.com" / "org" / "repo.git"
    worktree = worktrees_dir / "sandbox1"
    gitdir = bare_repo / "worktrees" / "feature"

    worktree.mkdir(parents=True)
    gitdir.mkdir(parents=True)
    bare_repo.mkdir(parents=True, exist_ok=True)

    (worktree / ".git").write_text(f"gitdir: {gitdir}\n")
    (gitdir / "commondir").write_text("../..\n")
    (gitdir / "HEAD").write_text("ref: refs/heads/feature\n")
    (bare_repo / "config").write_text("[core]\n\trepositoryformatversion = 0\n")

    return {
        "worktrees_dir": worktrees_dir,
        "repos_dir": repos_dir,
        "worktree": worktree,
        "gitdir": gitdir,
        "bare_repo": bare_repo,
    }


# ---------------------------------------------------------------------------
# _is_within
# ---------------------------------------------------------------------------


class TestIsWithin:
    def test_child_is_within(self, tmp_path: Path):
        assert _is_within(tmp_path / "sub", tmp_path)

    def test_unrelated_path_not_within(self, tmp_path: Path):
        assert not _is_within(Path("/tmp/other"), tmp_path)


# ---------------------------------------------------------------------------
# _resolve_git_paths — layout-agnostic chain traversal
# ---------------------------------------------------------------------------


class TestResolveGitPaths:
    def test_new_layout_chain(self, tmp_path: Path):
        paths = _setup_new_layout(tmp_path)
        gitdir, bare_dir = _resolve_git_paths(paths["worktree"])
        assert gitdir == paths["gitdir"]
        assert bare_dir == paths["repo_git"]

    def test_legacy_layout_chain(self, tmp_path: Path):
        paths = _setup_legacy_layout(tmp_path)
        gitdir, bare_dir = _resolve_git_paths(paths["worktree"])
        assert gitdir == paths["gitdir"]
        assert bare_dir == paths["bare_repo"]

    def test_missing_dot_git_file(self, tmp_path: Path):
        empty_wt = tmp_path / "empty-worktree"
        empty_wt.mkdir()
        with pytest.raises(RuntimeError, match="Expected .git file"):
            _resolve_git_paths(empty_wt)

    def test_bad_gitdir_format(self, tmp_path: Path):
        wt = tmp_path / "bad-wt"
        wt.mkdir()
        (wt / ".git").write_text("not a gitdir line\n")
        with pytest.raises(RuntimeError, match="Unexpected .git file format"):
            _resolve_git_paths(wt)


# ---------------------------------------------------------------------------
# _validate_new_layout_paths
# ---------------------------------------------------------------------------


class TestValidateNewLayoutPaths:
    def test_valid_new_layout(self, tmp_path: Path):
        paths = _setup_new_layout(tmp_path)
        host_worktree_path = str(paths["worktree"])
        # Should not raise
        _validate_new_layout_paths(
            paths["worktree"], paths["gitdir"], paths["repo_git"], host_worktree_path
        )

    def test_mismatched_host_worktree_path(self, tmp_path: Path):
        paths = _setup_new_layout(tmp_path)
        wrong_ws = str(tmp_path / "other-repo" / ".sbx" / "sandbox1-worktrees" / "feature")
        with pytest.raises(RuntimeError, match="doesn't match metadata"):
            _validate_new_layout_paths(
                paths["worktree"], paths["gitdir"], paths["repo_git"], wrong_ws
            )

    def test_missing_sbx_component(self, tmp_path: Path):
        worktree = tmp_path / "plain-dir"
        worktree.mkdir()
        with pytest.raises(RuntimeError, match="missing .sbx component"):
            _validate_new_layout_paths(
                worktree, tmp_path / ".git" / "worktrees" / "x", tmp_path / ".git",
                str(worktree),
            )

    def test_gitdir_escapes_repo(self, tmp_path: Path):
        paths = _setup_new_layout(tmp_path)
        rogue_gitdir = tmp_path / "other-repo" / ".git" / "worktrees" / "feature"
        rogue_gitdir.mkdir(parents=True)
        with pytest.raises(RuntimeError, match="Gitdir escapes repo .git/worktrees"):
            _validate_new_layout_paths(
                paths["worktree"], rogue_gitdir, paths["repo_git"],
                str(paths["worktree"]),
            )

    def test_bare_dir_wrong_repo(self, tmp_path: Path):
        paths = _setup_new_layout(tmp_path)
        wrong_git = (tmp_path / "other-repo" / ".git")
        wrong_git.mkdir(parents=True)
        with pytest.raises(RuntimeError, match="Commondir doesn't point to repo .git"):
            _validate_new_layout_paths(
                paths["worktree"], paths["gitdir"], wrong_git,
                str(paths["worktree"]),
            )


# ---------------------------------------------------------------------------
# _validate_legacy_layout_paths
# ---------------------------------------------------------------------------


class TestValidateLegacyLayoutPaths:
    @patch("foundry_sandbox.commands.git_mode.get_worktrees_dir")
    @patch("foundry_sandbox.commands.git_mode.get_repos_dir")
    def test_valid_legacy_layout(self, mock_repos, mock_wts, tmp_path: Path):
        paths = _setup_legacy_layout(tmp_path)
        mock_wts.return_value = paths["worktrees_dir"]
        mock_repos.return_value = paths["repos_dir"]
        _validate_legacy_layout_paths(
            paths["worktree"], paths["gitdir"], paths["bare_repo"]
        )

    @patch("foundry_sandbox.commands.git_mode.get_worktrees_dir")
    @patch("foundry_sandbox.commands.git_mode.get_repos_dir")
    def test_worktree_escapes(self, mock_repos, mock_wts, tmp_path: Path):
        paths = _setup_legacy_layout(tmp_path)
        mock_wts.return_value = paths["worktrees_dir"]
        mock_repos.return_value = paths["repos_dir"]
        with pytest.raises(RuntimeError, match="Worktree path escapes"):
            _validate_legacy_layout_paths(
                Path("/tmp/rogue"), paths["gitdir"], paths["bare_repo"]
            )

    @patch("foundry_sandbox.commands.git_mode.get_worktrees_dir")
    @patch("foundry_sandbox.commands.git_mode.get_repos_dir")
    def test_gitdir_escapes(self, mock_repos, mock_wts, tmp_path: Path):
        paths = _setup_legacy_layout(tmp_path)
        mock_wts.return_value = paths["worktrees_dir"]
        mock_repos.return_value = paths["repos_dir"]
        with pytest.raises(RuntimeError, match="Gitdir path escapes"):
            _validate_legacy_layout_paths(
                paths["worktree"], Path("/tmp/rogue"), paths["bare_repo"]
            )


# ---------------------------------------------------------------------------
# _validate_git_paths — top-level dispatcher
# ---------------------------------------------------------------------------


class TestValidateGitPathsDispatch:
    @patch("foundry_sandbox.commands.git_mode.load_sandbox_metadata")
    def test_dispatches_new_layout(self, mock_meta, tmp_path: Path):
        paths = _setup_new_layout(tmp_path)
        mock_meta.return_value = {"host_worktree_path": str(paths["worktree"])}
        _validate_git_paths(
            "sandbox1", paths["worktree"], paths["gitdir"], paths["repo_git"]
        )

    @patch("foundry_sandbox.commands.git_mode.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.git_mode.get_worktrees_dir")
    @patch("foundry_sandbox.commands.git_mode.get_repos_dir")
    def test_dispatches_legacy_when_empty_host_worktree_path(
        self, mock_repos, mock_wts, mock_meta, tmp_path: Path
    ):
        paths = _setup_legacy_layout(tmp_path)
        mock_meta.return_value = {"host_worktree_path": ""}
        mock_wts.return_value = paths["worktrees_dir"]
        mock_repos.return_value = paths["repos_dir"]
        _validate_git_paths(
            "sandbox1", paths["worktree"], paths["gitdir"], paths["bare_repo"]
        )

    @patch("foundry_sandbox.commands.git_mode.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.git_mode.get_worktrees_dir")
    @patch("foundry_sandbox.commands.git_mode.get_repos_dir")
    def test_falls_back_to_path_shape_when_no_metadata(
        self, mock_repos, mock_wts, mock_meta, tmp_path: Path
    ):
        paths = _setup_legacy_layout(tmp_path)
        mock_meta.return_value = None
        mock_wts.return_value = paths["worktrees_dir"]
        mock_repos.return_value = paths["repos_dir"]
        _validate_git_paths(
            "sandbox1", paths["worktree"], paths["gitdir"], paths["bare_repo"]
        )

    @patch("foundry_sandbox.commands.git_mode.load_sandbox_metadata")
    def test_fails_closed_on_unrecognised_layout(self, mock_meta, tmp_path: Path):
        mock_meta.return_value = None
        with pytest.raises(RuntimeError, match="Cannot determine layout"):
            _validate_git_paths(
                "unknown", Path("/not/under/worktrees"),
                Path("/x/.git/worktrees/b"), Path("/x/.git"),
            )

    @patch("foundry_sandbox.commands.git_mode.load_sandbox_metadata")
    def test_new_layout_rejects_rogue_gitdir(self, mock_meta, tmp_path: Path):
        paths = _setup_new_layout(tmp_path)
        rogue = tmp_path / "evil" / ".git" / "worktrees" / "feature"
        rogue.mkdir(parents=True)
        mock_meta.return_value = {"host_worktree_path": str(paths["worktree"])}
        with pytest.raises(RuntimeError, match="Gitdir escapes"):
            _validate_git_paths(
                "sandbox1", paths["worktree"], rogue, paths["repo_git"]
            )


# ---------------------------------------------------------------------------
# _apply_git_mode — config write operations
# ---------------------------------------------------------------------------


def _read_git_config(config_file: Path, key: str) -> str | None:
    """Read a single key from a git config file."""
    import subprocess

    result = subprocess.run(
        ["git", "config", "--file", str(config_file), "--get", key],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


class TestApplyGitMode:
    def test_host_mode_sets_core_worktree(self, tmp_path: Path):
        paths = _setup_new_layout(tmp_path)
        _apply_git_mode(
            mode="host",
            name="sandbox1",
            worktree_path=paths["worktree"],
            gitdir=paths["gitdir"],
            bare_dir=paths["repo_git"],
        )
        worktree_config = paths["gitdir"] / "config.worktree"
        assert _read_git_config(worktree_config, "core.worktree") == str(
            paths["worktree"]
        )
        assert _read_git_config(worktree_config, "core.bare") == "false"

    def test_sandbox_mode_sets_core_worktree(self, tmp_path: Path):
        paths = _setup_new_layout(tmp_path)
        _apply_git_mode(
            mode="sandbox",
            name="sandbox1",
            worktree_path=paths["worktree"],
            gitdir=paths["gitdir"],
            bare_dir=paths["repo_git"],
        )
        worktree_config = paths["gitdir"] / "config.worktree"
        assert _read_git_config(worktree_config, "core.worktree") == "/git-workspace"
        assert _read_git_config(worktree_config, "core.bare") == "false"

        bare_config = paths["repo_git"] / "config"
        assert _read_git_config(bare_config, "extensions.worktreeConfig") == "true"
        assert (
            _read_git_config(bare_config, "core.repositoryformatversion") == "1"
        )

    def test_sandbox_mode_raises_on_missing_bare_config(self, tmp_path: Path):
        paths = _setup_new_layout(tmp_path)
        (paths["repo_git"] / "config").unlink()
        with pytest.raises(RuntimeError, match="Bare config file not found"):
            _apply_git_mode(
                mode="sandbox",
                name="sandbox1",
                worktree_path=paths["worktree"],
                gitdir=paths["gitdir"],
                bare_dir=paths["repo_git"],
            )
