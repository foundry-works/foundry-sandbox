"""Tests for the rewritten cast list command (sbx backend)."""

from __future__ import annotations

import json
from unittest.mock import patch

from click.testing import CliRunner

from foundry_sandbox.commands.list_cmd import list_cmd


class TestListCommand:
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.state.sbx_ls")
    def test_list_empty(self, mock_ls, mock_metadata):
        mock_ls.return_value = []
        runner = CliRunner()
        result = runner.invoke(list_cmd)
        assert result.exit_code == 0
        assert "none" in result.output

    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.state.sbx_ls")
    def test_list_with_sandboxes(self, mock_ls, mock_metadata):
        mock_ls.return_value = [
            {"name": "sbx-1", "status": "running", "agent": "claude", "branch": "main"},
            {"name": "sbx-2", "status": "stopped", "agent": "codex", "branch": "dev"},
        ]
        mock_metadata.return_value = {"repo_url": "org/repo", "from_branch": "", "git_safety_enabled": True}
        runner = CliRunner()
        result = runner.invoke(list_cmd)
        assert result.exit_code == 0
        assert "sbx-1" in result.output
        assert "sbx-2" in result.output

    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.state.sbx_ls")
    def test_list_json(self, mock_ls, mock_metadata):
        mock_ls.return_value = [
            {"name": "sbx-1", "status": "running", "agent": "claude", "branch": "main"},
        ]
        mock_metadata.return_value = {"repo_url": "org/repo", "from_branch": "", "git_safety_enabled": True}
        runner = CliRunner()
        result = runner.invoke(list_cmd, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["name"] == "sbx-1"
        assert data[0]["git_safety"] == "True"

    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.state.sbx_ls")
    def test_list_no_metadata(self, mock_ls, mock_metadata):
        mock_ls.return_value = [
            {"name": "sbx-1", "status": "running", "agent": "claude", "branch": "main"},
        ]
        mock_metadata.return_value = None
        runner = CliRunner()
        result = runner.invoke(list_cmd, ["--json"])
        data = json.loads(result.output)
        assert data[0]["repo"] == ""
        assert data[0]["git_safety"] == "False"
