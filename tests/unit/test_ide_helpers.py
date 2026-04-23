"""Tests for shared IDE helpers (_ide_helpers.py)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from foundry_sandbox.commands._ide_helpers import get_ide_args, maybe_auto_git_mode


class TestGetIdeArgs:
    def test_none_config_returns_empty(self):
        assert get_ide_args(None) == []

    def test_config_with_args(self):
        cfg = MagicMock()
        cfg.args = ["--reuse-window", "--new-window"]
        assert get_ide_args(cfg) == ["--reuse-window", "--new-window"]

    def test_config_with_no_args_attr(self):
        cfg = object()
        assert get_ide_args(cfg) == []

    def test_config_with_empty_args(self):
        cfg = MagicMock()
        cfg.args = []
        assert get_ide_args(cfg) == []


class TestMaybeAutoGitMode:
    def test_skipped_when_config_none(self):
        maybe_auto_git_mode("test-sandbox", None)

    def test_skipped_when_flag_false(self):
        cfg = MagicMock()
        cfg.auto_git_mode_host = False
        maybe_auto_git_mode("test-sandbox", cfg)

    @patch("foundry_sandbox.commands.git_mode._apply_git_mode")
    @patch("foundry_sandbox.commands.git_mode._validate_git_paths")
    @patch("foundry_sandbox.commands.git_mode._resolve_git_paths")
    @patch("foundry_sandbox.paths.resolve_host_worktree_path")
    def test_triggered_when_flag_true(self, mock_resolve, mock_git_paths,
                                       mock_validate, mock_apply):
        from pathlib import Path
        cfg = MagicMock()
        cfg.auto_git_mode_host = True

        mock_resolve.return_value = Path("/fake/worktree")
        mock_git_paths.return_value = (Path("/fake/.git/worktrees/branch"),
                                        Path("/fake/.git"))

        maybe_auto_git_mode("test-sandbox", cfg)

        mock_apply.assert_called_once()

    @patch("foundry_sandbox.paths.resolve_host_worktree_path",
           side_effect=RuntimeError("no metadata"))
    def test_warns_on_failure(self, mock_resolve):
        cfg = MagicMock()
        cfg.auto_git_mode_host = True
        # Should not raise
        maybe_auto_git_mode("test-sandbox", cfg)
