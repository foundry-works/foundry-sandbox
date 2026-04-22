"""Tests for _helpers.py — sandbox discovery and listing."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from foundry_sandbox.commands._helpers import (
    auto_detect_sandbox,
    list_sandbox_names,
    fzf_select_sandbox,
)


class TestAutoDetectSandbox:
    """auto_detect_sandbox: match cwd against metadata workspace_path."""

    @patch("foundry_sandbox.commands._helpers.get_worktrees_dir")
    @patch("foundry_sandbox.state.list_sandboxes")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name", return_value=(True, ""))
    def test_detects_new_layout_sandbox(self, mock_validate, mock_list, mock_wt_dir, tmp_path):
        # Simulate cwd inside an sbx worktree
        workspace = tmp_path / ".sbx" / "test-wt-worktrees" / "feature"
        workspace.mkdir(parents=True)

        mock_list.return_value = [
            {"name": "test-wt", "workspace_path": str(workspace)},
        ]
        mock_wt_dir.return_value = Path("/nonexistent")

        with patch("foundry_sandbox.commands._helpers.Path.cwd", return_value=workspace):
            result = auto_detect_sandbox()
        assert result == "test-wt"

    @patch("foundry_sandbox.commands._helpers.get_worktrees_dir")
    @patch("foundry_sandbox.state.list_sandboxes")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name", return_value=(True, ""))
    def test_no_match_returns_none(self, mock_validate, mock_list, mock_wt_dir, tmp_path):
        mock_list.return_value = []
        mock_wt_dir.return_value = Path("/nonexistent")

        with patch("foundry_sandbox.commands._helpers.Path.cwd", return_value=tmp_path):
            result = auto_detect_sandbox()
        assert result is None


class TestListSandboxNames:
    """list_sandbox_names: scan claude-config dirs with metadata.json."""

    @patch("foundry_sandbox.commands._helpers.get_claude_configs_dir")
    def test_returns_sorted_names(self, mock_dir, tmp_path):
        for name in ["charlie", "alpha", "bravo"]:
            d = tmp_path / name
            d.mkdir()
            (d / "metadata.json").write_text("{}")

        (tmp_path / "no-metadata").mkdir()

        mock_dir.return_value = tmp_path
        result = list_sandbox_names()
        assert result == ["alpha", "bravo", "charlie"]

    @patch("foundry_sandbox.commands._helpers.get_claude_configs_dir")
    def test_returns_empty_when_dir_missing(self, mock_dir, tmp_path):
        mock_dir.return_value = tmp_path / "nonexistent"
        result = list_sandbox_names()
        assert result == []


class TestFzfSelectSandbox:
    """fzf_select_sandbox: fzf-based interactive selection."""

    @patch("foundry_sandbox.commands._helpers.list_sandbox_names", return_value=[])
    @patch("foundry_sandbox.commands._helpers.shutil.which", return_value="/usr/bin/fzf")
    def test_returns_none_when_no_sandboxes(self, mock_which, mock_list):
        result = fzf_select_sandbox()
        assert result is None

    @patch("foundry_sandbox.commands._helpers.shutil.which", return_value=None)
    def test_returns_none_when_fzf_missing(self, mock_which):
        result = fzf_select_sandbox()
        assert result is None
