"""Unit tests for `foundry_sandbox.commands.prune`."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import click.testing
import pytest

from foundry_sandbox.commands.prune import (
    _container_name_from_sandbox,
    _load_prune_metadata,
    prune,
)


@pytest.fixture()
def runner() -> click.testing.CliRunner:
    return click.testing.CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestPruneHelpers:

    @patch("foundry_sandbox.commands.prune.load_sandbox_metadata")
    def test_load_prune_metadata_returns_branch_and_url(self, mock_meta: MagicMock) -> None:
        mock_meta.return_value = {"branch": "sandbox/feat", "repo_url": "https://github.com/user/repo"}
        branch, url = _load_prune_metadata("test")
        assert branch == "sandbox/feat"
        assert url == "https://github.com/user/repo"

    @patch("foundry_sandbox.commands.prune.load_sandbox_metadata")
    def test_load_prune_metadata_returns_empty_on_none(self, mock_meta: MagicMock) -> None:
        mock_meta.return_value = None
        branch, url = _load_prune_metadata("test")
        assert branch == ""
        assert url == ""

    @patch("foundry_sandbox.commands.prune.load_sandbox_metadata", side_effect=OSError("no file"))
    def test_load_prune_metadata_handles_os_error(self, mock_meta: MagicMock) -> None:
        branch, url = _load_prune_metadata("test")
        assert branch == ""
        assert url == ""

    def test_container_name_from_sandbox(self) -> None:
        name = _container_name_from_sandbox("my-project")
        assert name == "sandbox-my-project"


# ---------------------------------------------------------------------------
# Stage 1: Orphaned configs
# ---------------------------------------------------------------------------


class TestPruneOrphanedConfigs:

    @patch("foundry_sandbox.commands.prune._cleanup_orphaned_networks", return_value=[])
    @patch("foundry_sandbox.commands.prune.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.prune.safe_remove")
    @patch("foundry_sandbox.commands.prune._load_prune_metadata", return_value=("", ""))
    @patch("foundry_sandbox.commands.prune.get_worktrees_dir")
    @patch("foundry_sandbox.commands.prune.get_claude_configs_dir")
    def test_removes_orphaned_config(
        self,
        mock_configs_dir: MagicMock,
        mock_wt_dir: MagicMock,
        mock_meta: MagicMock,
        mock_remove: MagicMock,
        mock_branch: MagicMock,
        mock_networks: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        configs = tmp_path / "configs"
        configs.mkdir()
        (configs / "orphan-sb").mkdir()

        worktrees = tmp_path / "worktrees"
        worktrees.mkdir()
        # No matching worktree for "orphan-sb"

        mock_configs_dir.return_value = configs
        mock_wt_dir.return_value = worktrees

        result = runner.invoke(prune, ["--force"])
        assert result.exit_code == 0
        mock_remove.assert_called_once()
        assert "orphan-sb" in result.output

    @patch("foundry_sandbox.commands.prune._cleanup_orphaned_networks", return_value=[])
    @patch("foundry_sandbox.commands.prune.get_worktrees_dir")
    @patch("foundry_sandbox.commands.prune.get_claude_configs_dir")
    def test_no_orphans_shows_message(
        self,
        mock_configs_dir: MagicMock,
        mock_wt_dir: MagicMock,
        mock_networks: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        configs = tmp_path / "configs"
        configs.mkdir()
        worktrees = tmp_path / "worktrees"
        worktrees.mkdir()

        mock_configs_dir.return_value = configs
        mock_wt_dir.return_value = worktrees

        result = runner.invoke(prune, ["--force"])
        assert result.exit_code == 0
        assert "no orphaned configs" in result.output.lower()


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


class TestPruneJsonOutput:

    @patch("foundry_sandbox.commands.prune._cleanup_orphaned_networks", return_value=[])
    @patch("foundry_sandbox.commands.prune.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.prune.safe_remove")
    @patch("foundry_sandbox.commands.prune._load_prune_metadata", return_value=("", ""))
    @patch("foundry_sandbox.commands.prune.get_worktrees_dir")
    @patch("foundry_sandbox.commands.prune.get_claude_configs_dir")
    def test_json_output_format(
        self,
        mock_configs_dir: MagicMock,
        mock_wt_dir: MagicMock,
        mock_meta: MagicMock,
        mock_remove: MagicMock,
        mock_branch: MagicMock,
        mock_networks: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        configs = tmp_path / "configs"
        configs.mkdir()
        (configs / "orphan-sb").mkdir()

        worktrees = tmp_path / "worktrees"
        worktrees.mkdir()

        mock_configs_dir.return_value = configs
        mock_wt_dir.return_value = worktrees

        result = runner.invoke(prune, ["--force", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["name"] == "orphan-sb"
        assert data[0]["type"] == "orphaned_config"

    @patch("foundry_sandbox.commands.prune._cleanup_orphaned_networks", return_value=[])
    @patch("foundry_sandbox.commands.prune.get_worktrees_dir")
    @patch("foundry_sandbox.commands.prune.get_claude_configs_dir")
    def test_json_empty_output(
        self,
        mock_configs_dir: MagicMock,
        mock_wt_dir: MagicMock,
        mock_networks: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        configs = tmp_path / "configs"
        configs.mkdir()
        worktrees = tmp_path / "worktrees"
        worktrees.mkdir()

        mock_configs_dir.return_value = configs
        mock_wt_dir.return_value = worktrees

        result = runner.invoke(prune, ["--force", "--json"])
        data = json.loads(result.output)
        assert data == []


# ---------------------------------------------------------------------------
# --all flag
# ---------------------------------------------------------------------------


class TestPruneAllFlag:

    @patch("foundry_sandbox.commands.prune._cleanup_orphaned_networks", return_value=["net1"])
    @patch("foundry_sandbox.commands.prune.get_worktrees_dir")
    @patch("foundry_sandbox.commands.prune.get_claude_configs_dir")
    def test_all_flag_enables_networks(
        self,
        mock_configs_dir: MagicMock,
        mock_wt_dir: MagicMock,
        mock_networks: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        configs = tmp_path / "configs"
        configs.mkdir()
        worktrees = tmp_path / "worktrees"
        worktrees.mkdir()

        mock_configs_dir.return_value = configs
        mock_wt_dir.return_value = worktrees

        result = runner.invoke(prune, ["--force", "--all"])
        assert result.exit_code == 0
        mock_networks.assert_called_once()
        assert "net1" in result.output
