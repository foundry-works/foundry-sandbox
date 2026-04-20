"""Tests for the rewritten cast attach command (sbx backend)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.attach import attach, _resolve_sandbox_name


class TestAttachCommand:
    @patch("foundry_sandbox.commands.attach.sbx_check_available")
    @patch("foundry_sandbox.commands.attach.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.attach.sbx_exec_streaming")
    @patch("foundry_sandbox.commands.attach.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.attach.save_last_attach")
    @patch("foundry_sandbox.commands.attach.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.attach.validate_existing_sandbox_name")
    def test_attach_running(
        self, mock_validate, mock_paths, mock_save, mock_meta,
        mock_streaming, mock_running, mock_check,
    ):
        mock_validate.return_value = (True, "")
        mock_path = MagicMock()
        mock_path.worktree_path = MagicMock()
        mock_path.worktree_path.is_dir.return_value = True
        mock_paths.return_value = mock_path
        mock_meta.return_value = {"working_dir": ""}
        mock_proc = MagicMock()
        mock_proc.wait.return_value = None
        mock_streaming.return_value = mock_proc

        runner = CliRunner()
        result = runner.invoke(attach, ["my-sandbox"])
        assert result.exit_code == 0
        mock_streaming.assert_called_once_with(
            "my-sandbox", ["bash", "-l"], interactive=True,
        )
        mock_save.assert_called_once_with("my-sandbox")

    @patch("foundry_sandbox.commands.attach.sbx_check_available")
    @patch("foundry_sandbox.commands.attach.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.attach.sbx_exec_streaming")
    @patch("foundry_sandbox.commands.attach.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.attach.save_last_attach")
    @patch("foundry_sandbox.commands.attach.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.attach.validate_existing_sandbox_name")
    def test_attach_with_working_dir(
        self, mock_validate, mock_paths, mock_save, mock_meta,
        mock_streaming, mock_running, mock_check,
    ):
        mock_validate.return_value = (True, "")
        mock_path = MagicMock()
        mock_path.worktree_path = MagicMock()
        mock_path.worktree_path.is_dir.return_value = True
        mock_paths.return_value = mock_path
        mock_meta.return_value = {"working_dir": "src/subdir"}
        mock_proc = MagicMock()
        mock_proc.wait.return_value = None
        mock_streaming.return_value = mock_proc

        runner = CliRunner()
        result = runner.invoke(attach, ["my-sandbox"])
        assert result.exit_code == 0
        cmd = mock_streaming.call_args[0][1]
        assert "bash" in cmd
        assert "-lc" in cmd
        assert "cd src/subdir" in cmd[2]
        mock_streaming.assert_called_once()
        _, kwargs = mock_streaming.call_args
        assert kwargs["interactive"] is True

    @patch("foundry_sandbox.commands.attach._start_sandbox")
    @patch("foundry_sandbox.commands.attach.sbx_check_available")
    @patch("foundry_sandbox.commands.attach.sbx_is_running", return_value=False)
    @patch("foundry_sandbox.commands.attach.sbx_exec_streaming")
    @patch("foundry_sandbox.commands.attach.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.attach.save_last_attach")
    @patch("foundry_sandbox.commands.attach.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.attach.validate_existing_sandbox_name")
    def test_attach_auto_starts(
        self, mock_validate, mock_paths, mock_save, mock_meta,
        mock_streaming, mock_running, mock_check, mock_start,
    ):
        mock_validate.return_value = (True, "")
        mock_path = MagicMock()
        mock_path.worktree_path = MagicMock()
        mock_path.worktree_path.is_dir.return_value = True
        mock_paths.return_value = mock_path
        mock_meta.return_value = {"working_dir": ""}
        mock_proc = MagicMock()
        mock_proc.wait.return_value = None
        mock_streaming.return_value = mock_proc

        runner = CliRunner()
        result = runner.invoke(attach, ["my-sandbox"])
        assert result.exit_code == 0
        mock_start.assert_called_once_with("my-sandbox")


class TestResolveSandboxName:
    @patch("foundry_sandbox.commands.attach.validate_existing_sandbox_name")
    def test_explicit_name(self, mock_validate):
        mock_validate.return_value = (True, "")
        result = _resolve_sandbox_name("my-sandbox", False)
        assert result == "my-sandbox"

    @patch("foundry_sandbox.commands.attach.validate_existing_sandbox_name")
    @patch("foundry_sandbox.commands.attach.load_last_attach")
    def test_last_flag(self, mock_last, mock_validate):
        mock_last.return_value = "previous-sandbox"
        mock_validate.return_value = (True, "")
        result = _resolve_sandbox_name(None, True)
        assert result == "previous-sandbox"
