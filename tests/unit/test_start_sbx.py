"""Tests for the rewritten cast start command (sbx backend)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.start import start


class TestStartCommand:
    @patch("foundry_sandbox.commands.start.verify_git_wrapper", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_start_success(self, mock_meta, mock_check, mock_gs_running, mock_run, mock_exists, mock_verify):
        mock_meta.return_value = {"sbx_name": "test-1"}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        assert result.exit_code == 0
        assert "started" in result.output
        mock_run.assert_called_once_with("my-sandbox")

    @patch("foundry_sandbox.commands.start.verify_git_wrapper", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=False)
    @patch("foundry_sandbox.commands.start.git_safety_server_start")
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_starts_git_safety_server(self, mock_meta, mock_check, mock_gs_start, mock_gs_running, mock_run, mock_exists, mock_verify):
        mock_meta.return_value = {}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        assert result.exit_code == 0
        mock_gs_start.assert_called_once()

    @patch("foundry_sandbox.commands.start.inject_git_wrapper")
    @patch("foundry_sandbox.commands.start.verify_git_wrapper", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_reinjects_wrapper(self, mock_meta, mock_check, mock_gs, mock_run, mock_exists, mock_verify, mock_inject):
        mock_meta.return_value = {"sbx_name": "test-1", "workspace_dir": "/workspace"}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        assert result.exit_code == 0
        mock_inject.assert_called_once_with("my-sandbox", sandbox_id="test-1", workspace_dir="/workspace")

    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    def test_sandbox_not_found(self, mock_check, mock_exists):
        runner = CliRunner()
        result = runner.invoke(start, ["nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output

    @patch("foundry_sandbox.commands.start._install_pip_requirements_sbx")
    @patch("foundry_sandbox.commands.start.verify_git_wrapper", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_installs_pip_requirements(self, mock_meta, mock_check, mock_gs, mock_run, mock_exists, mock_verify, mock_pip):
        mock_meta.return_value = {"pip_requirements": "requirements.txt"}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        assert result.exit_code == 0
        mock_pip.assert_called_once_with("my-sandbox", "requirements.txt")
