"""Tests for the rewritten cast status command (sbx backend)."""

from __future__ import annotations

import json
from unittest.mock import patch

from click.testing import CliRunner

from foundry_sandbox.commands.status import status


class TestStatusCommand:
    @patch("foundry_sandbox.commands.status.sbx_check_available")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.state.sbx_ls")
    def test_status_all(self, mock_ls, mock_metadata, mock_check):
        mock_ls.return_value = [
            {"name": "sbx-1", "status": "running", "agent": "claude", "branch": "main"},
        ]
        mock_metadata.return_value = {"repo_url": "org/repo", "from_branch": "", "git_safety_enabled": True}
        runner = CliRunner()
        result = runner.invoke(status)
        assert result.exit_code == 0
        assert "sbx-1" in result.output

    @patch("foundry_sandbox.commands.status.sbx_check_available")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.status.sbx_is_running")
    @patch("foundry_sandbox.state.sbx_ls")
    def test_status_single(self, mock_ls, mock_running, mock_metadata, mock_check):
        mock_ls.return_value = [
            {"name": "my-sandbox", "status": "running", "agent": "claude", "branch": "feature-x"},
        ]
        mock_running.return_value = True
        mock_metadata.return_value = {
            "repo_url": "org/repo",
            "from_branch": "main",
            "working_dir": "",
            "pip_requirements": "",
            "git_safety_enabled": True,
            "allow_pr": False,
            "copies": [],
        }
        runner = CliRunner()
        result = runner.invoke(status, ["my-sandbox"])
        assert result.exit_code == 0
        assert "my-sandbox" in result.output
        assert "running" in result.output

    @patch("foundry_sandbox.commands.status.sbx_check_available")
    @patch("foundry_sandbox.state.sbx_ls")
    def test_status_single_not_found(self, mock_ls, mock_check):
        mock_ls.return_value = []
        runner = CliRunner()
        result = runner.invoke(status, ["nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output

    @patch("foundry_sandbox.commands.status.sbx_check_available")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.status.sbx_is_running")
    @patch("foundry_sandbox.state.sbx_ls")
    def test_status_single_json(self, mock_ls, mock_running, mock_metadata, mock_check):
        mock_ls.return_value = [
            {"name": "my-sandbox", "status": "stopped", "agent": "codex", "branch": "dev"},
        ]
        mock_running.return_value = False
        mock_metadata.return_value = {
            "repo_url": "org/repo",
            "from_branch": "",
            "working_dir": "",
            "pip_requirements": "",
            "git_safety_enabled": False,
            "allow_pr": False,
            "copies": [],
        }
        runner = CliRunner()
        result = runner.invoke(status, ["my-sandbox", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "my-sandbox"
        assert data["git_safety"] == "False"
