"""Tests for the cast destroy-all command."""

from __future__ import annotations

import os
from unittest.mock import patch

from click.testing import CliRunner

from foundry_sandbox.commands.destroy_all import destroy_all


class TestDestroyAll:
    @patch("foundry_sandbox.commands.destroy_all.destroy_impl")
    @patch("foundry_sandbox.commands.destroy_all.list_sandbox_names")
    @patch("foundry_sandbox.commands.destroy_all.sbx_ls")
    @patch("foundry_sandbox.commands.destroy_all.sbx_check_available")
    def test_destroys_all_sandboxes(self, mock_check, mock_ls, mock_names, mock_impl):
        mock_ls.return_value = [
            {"name": "sbx-1", "status": "running"},
            {"name": "sbx-2", "status": "stopped"},
        ]
        mock_names.return_value = ["sbx-1", "sbx-2"]
        os.environ["SANDBOX_NONINTERACTIVE"] = "1"
        try:
            runner = CliRunner()
            result = runner.invoke(destroy_all)
            assert result.exit_code == 0
            assert mock_impl.call_count == 2
        finally:
            del os.environ["SANDBOX_NONINTERACTIVE"]

    @patch("foundry_sandbox.commands.destroy_all.destroy_impl")
    @patch("foundry_sandbox.commands.destroy_all.list_sandbox_names")
    @patch("foundry_sandbox.commands.destroy_all.sbx_ls")
    @patch("foundry_sandbox.commands.destroy_all.sbx_check_available")
    def test_destroys_orphans(self, mock_check, mock_ls, mock_names, mock_impl):
        mock_ls.return_value = [
            {"name": "sbx-1", "status": "running"},
        ]
        mock_names.return_value = ["sbx-1", "orphan-sbx"]
        os.environ["SANDBOX_NONINTERACTIVE"] = "1"
        try:
            runner = CliRunner()
            result = runner.invoke(destroy_all)
            assert result.exit_code == 0
            destroyed = {call.args[0] for call in mock_impl.call_args_list}
            assert "sbx-1" in destroyed
            assert "orphan-sbx" in destroyed
            assert "orphan" in result.output
        finally:
            del os.environ["SANDBOX_NONINTERACTIVE"]

    @patch("foundry_sandbox.commands.destroy_all.list_sandbox_names")
    @patch("foundry_sandbox.commands.destroy_all.sbx_ls")
    @patch("foundry_sandbox.commands.destroy_all.sbx_check_available")
    def test_no_sandboxes(self, mock_check, mock_ls, mock_names):
        mock_ls.return_value = []
        mock_names.return_value = []
        runner = CliRunner()
        result = runner.invoke(destroy_all)
        assert result.exit_code == 0
        assert "No sandboxes" in result.output
