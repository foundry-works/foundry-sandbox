"""Tests for the rewritten cast stop command (sbx backend)."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.stop import stop


class TestStopCommand:
    @patch("foundry_sandbox.commands.stop.sbx_stop")
    @patch("foundry_sandbox.commands.stop.sbx_check_available")
    def test_stop_success(self, mock_check, mock_stop):
        mock_stop.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(stop, ["my-sandbox"])
        assert result.exit_code == 0
        assert "stopped" in result.output
        mock_stop.assert_called_once_with("my-sandbox")

    @patch("foundry_sandbox.commands.stop.sbx_stop")
    @patch("foundry_sandbox.commands.stop.sbx_check_available")
    def test_stop_failure_logs_warning(self, mock_check, mock_stop):
        mock_stop.side_effect = subprocess.CalledProcessError(1, "sbx stop")
        runner = CliRunner()
        result = runner.invoke(stop, ["my-sandbox"])
        # Should not crash, just log warning
        assert result.exit_code == 0

    @patch("foundry_sandbox.commands.stop.sbx_check_available")
    def test_invalid_name(self, mock_check):
        runner = CliRunner()
        result = runner.invoke(stop, [""])
        assert result.exit_code == 1
        assert "required" in result.output.lower() or "Error" in result.output

    @patch("foundry_sandbox.commands.stop.sbx_stop")
    @patch("foundry_sandbox.commands.stop.sbx_check_available")
    def test_sbx_not_installed(self, mock_check, mock_stop):
        mock_check.side_effect = SystemExit(1)
        runner = CliRunner()
        result = runner.invoke(stop, ["my-sandbox"])
        assert result.exit_code == 1
        mock_stop.assert_not_called()
