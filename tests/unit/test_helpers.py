"""Tests for _helpers.py — sandbox discovery, listing, and resolution."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from foundry_sandbox.commands._helpers import (
    auto_detect_sandbox,
    list_sandbox_names,
    fzf_select_sandbox,
    resolve_sandbox_name,
)


class TestAutoDetectSandbox:
    """auto_detect_sandbox: match cwd against metadata host_worktree_path."""

    @patch("foundry_sandbox.state.list_sandboxes")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name", return_value=(True, ""))
    def test_detects_new_layout_sandbox(self, mock_validate, mock_list, tmp_path):
        # Simulate cwd inside an sbx worktree
        workspace = tmp_path / ".sbx" / "test-wt-worktrees" / "feature"
        workspace.mkdir(parents=True)

        mock_list.return_value = [
            {"name": "test-wt", "host_worktree_path": str(workspace)},
        ]

        with patch("foundry_sandbox.commands._helpers.Path.cwd", return_value=workspace):
            result = auto_detect_sandbox()
        assert result == "test-wt"

    @patch("foundry_sandbox.state.list_sandboxes")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name", return_value=(True, ""))
    def test_no_match_returns_none(self, mock_validate, mock_list, tmp_path):
        mock_list.return_value = []

        with patch("foundry_sandbox.commands._helpers.Path.cwd", return_value=tmp_path):
            result = auto_detect_sandbox()
        assert result is None


class TestListSandboxNames:
    """list_sandbox_names: scan sandbox config dirs with metadata.json."""

    @patch("foundry_sandbox.commands._helpers.get_sandbox_configs_dir")
    def test_returns_sorted_names(self, mock_dir, tmp_path):
        for name in ["charlie", "alpha", "bravo"]:
            d = tmp_path / name
            d.mkdir()
            (d / "metadata.json").write_text("{}")

        (tmp_path / "no-metadata").mkdir()

        mock_dir.return_value = tmp_path
        result = list_sandbox_names()
        assert result == ["alpha", "bravo", "charlie"]

    @patch("foundry_sandbox.commands._helpers.get_sandbox_configs_dir")
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


class TestResolveSandboxName:
    """resolve_sandbox_name: shared name resolution cascade."""

    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name", return_value=(True, ""))
    def test_explicit_name_returns_directly(self, mock_validate):
        result = resolve_sandbox_name("my-sandbox")
        assert result == "my-sandbox"
        mock_validate.assert_called_once_with("my-sandbox")

    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name", return_value=(True, ""))
    @patch("foundry_sandbox.state.load_last_attach", return_value="last-sandbox")
    def test_use_last_returns_last_attached(self, mock_last, mock_validate):
        result = resolve_sandbox_name(None, use_last=True)
        assert result == "last-sandbox"

    @patch("foundry_sandbox.state.load_last_attach", return_value=None)
    def test_use_last_exits_when_none_found(self, mock_last):
        with pytest.raises(SystemExit):
            resolve_sandbox_name(None, use_last=True)

    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name", return_value=(True, ""))
    @patch("foundry_sandbox.commands._helpers.auto_detect_sandbox", return_value="detected-sb")
    def test_auto_detect_fallback(self, mock_detect, mock_validate):
        result = resolve_sandbox_name(None)
        assert result == "detected-sb"

    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name", return_value=(True, ""))
    @patch("foundry_sandbox.commands._helpers.fzf_select_sandbox", return_value="fzf-sb")
    @patch("foundry_sandbox.commands._helpers.auto_detect_sandbox", return_value=None)
    def test_fzf_fallback_when_allowed(self, mock_detect, mock_fzf, mock_validate):
        result = resolve_sandbox_name(None, allow_fzf=True)
        assert result == "fzf-sb"

    @patch("foundry_sandbox.commands._helpers.fzf_select_sandbox")
    @patch("foundry_sandbox.commands._helpers.auto_detect_sandbox", return_value=None)
    def test_fzf_skipped_when_disallowed(self, mock_detect, mock_fzf):
        with pytest.raises(SystemExit):
            resolve_sandbox_name(None, allow_fzf=False)
        mock_fzf.assert_not_called()

    @patch("foundry_sandbox.commands._helpers.list_sandbox_names", return_value=["sb1", "sb2"])
    @patch("foundry_sandbox.commands._helpers.fzf_select_sandbox", return_value=None)
    @patch("foundry_sandbox.commands._helpers.auto_detect_sandbox", return_value=None)
    def test_exits_with_sandbox_list_when_unresolved(self, mock_detect, mock_fzf, mock_list):
        with pytest.raises(SystemExit):
            resolve_sandbox_name(None)

    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name", return_value=(False, "bad name"))
    def test_exits_on_invalid_name(self, mock_validate):
        with pytest.raises(SystemExit):
            resolve_sandbox_name("invalid!")
