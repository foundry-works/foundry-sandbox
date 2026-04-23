"""Tests for the rewritten cast attach command (sbx backend)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.attach import attach


def _mock_sandbox(mock_validate, mock_resolve, mock_meta, mock_streaming,
                  mock_save, mock_running, mock_check, working_dir=""):
    mock_validate.return_value = (True, "")
    mock_workspace = MagicMock()
    mock_workspace.is_dir.return_value = True
    mock_resolve.return_value = mock_workspace
    mock_meta.return_value = {"working_dir": working_dir}
    mock_running.return_value = True
    mock_proc = MagicMock()
    mock_proc.wait.return_value = None
    mock_streaming.return_value = mock_proc


class TestAttachCommand:
    @patch("foundry_sandbox.commands.attach.sbx_check_available")
    @patch("foundry_sandbox.commands.attach.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.attach.sbx_exec_streaming")
    @patch("foundry_sandbox.commands.attach.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.attach.save_last_attach")
    @patch("foundry_sandbox.commands.attach.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    def test_attach_running(
        self, mock_validate, mock_resolve, mock_save, mock_meta,
        mock_streaming, mock_running, mock_check,
    ):
        _mock_sandbox(mock_validate, mock_resolve, mock_meta, mock_streaming,
                       mock_save, mock_running, mock_check)

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
    @patch("foundry_sandbox.commands.attach.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    def test_attach_with_working_dir(
        self, mock_validate, mock_resolve, mock_save, mock_meta,
        mock_streaming, mock_running, mock_check,
    ):
        _mock_sandbox(mock_validate, mock_resolve, mock_meta, mock_streaming,
                       mock_save, mock_running, mock_check, working_dir="src/subdir")

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
    @patch("foundry_sandbox.commands.attach.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    def test_attach_auto_starts(
        self, mock_validate, mock_resolve, mock_save, mock_meta,
        mock_streaming, mock_running, mock_check, mock_start,
    ):
        _mock_sandbox(mock_validate, mock_resolve, mock_meta, mock_streaming,
                       mock_save, mock_running, mock_check)
        mock_running.return_value = False

        runner = CliRunner()
        result = runner.invoke(attach, ["my-sandbox"])
        assert result.exit_code == 0
        mock_start.assert_called_once_with("my-sandbox")

    @patch("foundry_sandbox.commands.attach.sbx_check_available")
    @patch("foundry_sandbox.commands.attach.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    def test_attach_not_found(
        self, mock_validate, mock_resolve, mock_check,
    ):
        mock_validate.return_value = (True, "")
        mock_workspace = MagicMock()
        mock_workspace.is_dir.return_value = False
        mock_resolve.return_value = mock_workspace

        runner = CliRunner()
        result = runner.invoke(attach, ["missing-sandbox"])
        assert result.exit_code == 1
        assert "not found" in result.output


# ---------------------------------------------------------------------------
# IDE config-aware tests
# ---------------------------------------------------------------------------


class TestAttachIdeConfig:
    """Tests for attach IDE config integration."""

    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("foundry_sandbox.commands.attach.sbx_check_available")
    @patch("foundry_sandbox.commands.attach.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.attach.sbx_exec_streaming")
    @patch("foundry_sandbox.commands.attach.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.attach.save_last_attach")
    @patch("foundry_sandbox.commands.attach.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    def test_no_ide_flag_suppresses_auto_open(
        self, mock_validate, mock_resolve, mock_save, mock_meta,
        mock_streaming, mock_running, mock_check, mock_ide_config,
    ):
        from foundry_sandbox.foundry_config import IdeConfig
        mock_ide_config.return_value = IdeConfig(preferred="cursor", auto_open_on_attach=True)
        _mock_sandbox(mock_validate, mock_resolve, mock_meta, mock_streaming,
                       mock_save, mock_running, mock_check)

        runner = CliRunner()
        result = runner.invoke(attach, ["my-sandbox", "--no-ide"])
        assert result.exit_code == 0
        mock_streaming.assert_called_once()

    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("shutil.which", return_value="/usr/bin/code")
    @patch("foundry_sandbox.ide._launch_via_cli", return_value=True)
    @patch("foundry_sandbox.ide._try_macos_open", return_value=False)
    @patch("foundry_sandbox.commands.attach.sbx_check_available")
    @patch("foundry_sandbox.commands.attach.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.attach.sbx_exec_streaming")
    @patch("foundry_sandbox.commands.attach.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.attach.save_last_attach")
    @patch("foundry_sandbox.commands.attach.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    def test_with_ide_uses_config_default(
        self, mock_validate, mock_resolve, mock_save,
        mock_meta, mock_streaming, mock_running, mock_check,
        mock_macos, mock_cli, mock_which, mock_ide_config,
    ):
        from foundry_sandbox.foundry_config import IdeConfig
        mock_ide_config.return_value = IdeConfig(preferred="code")
        _mock_sandbox(mock_validate, mock_resolve, mock_meta, mock_streaming,
                       mock_save, mock_running, mock_check)

        runner = CliRunner()
        # --with-ide with no value → flag_value="auto" → falls through to prompt path
        # In non-tty (CliRunner), returns False and continues to attach
        result = runner.invoke(attach, ["my-sandbox"])
        assert result.exit_code == 0

    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("shutil.which", return_value="/usr/bin/code")
    @patch("foundry_sandbox.ide._launch_via_cli", return_value=True)
    @patch("foundry_sandbox.ide._try_macos_open", return_value=False)
    @patch("foundry_sandbox.commands.attach.sbx_check_available")
    @patch("foundry_sandbox.commands.attach.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.attach.sbx_exec_streaming")
    @patch("foundry_sandbox.commands.attach.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.attach.save_last_attach")
    @patch("foundry_sandbox.commands.attach.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    def test_with_ide_explicit_override(
        self, mock_validate, mock_resolve, mock_save,
        mock_meta, mock_streaming, mock_running, mock_check,
        mock_macos, mock_cli, mock_which, mock_ide_config,
    ):
        from foundry_sandbox.foundry_config import IdeConfig
        mock_ide_config.return_value = IdeConfig(preferred="zed")
        _mock_sandbox(mock_validate, mock_resolve, mock_meta, mock_streaming,
                       mock_save, mock_running, mock_check)

        runner = CliRunner()
        result = runner.invoke(attach, ["my-sandbox", "--with-ide", "code"])
        assert result.exit_code == 0

    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("shutil.which", return_value=None)
    @patch("foundry_sandbox.commands.attach.sbx_check_available")
    @patch("foundry_sandbox.commands.attach.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.attach.sbx_exec_streaming")
    @patch("foundry_sandbox.commands.attach.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.attach.save_last_attach")
    @patch("foundry_sandbox.commands.attach.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    def test_ide_only_failure_exits_nonzero(
        self, mock_validate, mock_resolve, mock_save,
        mock_meta, mock_streaming, mock_running, mock_check,
        mock_which, mock_ide_config,
    ):
        mock_ide_config.return_value = None
        _mock_sandbox(mock_validate, mock_resolve, mock_meta, mock_streaming,
                       mock_save, mock_running, mock_check)

        runner = CliRunner()
        # --ide-only with unresolvable IDE → resolve_ide returns None → exit 1
        # CliRunner is not a tty, so we need to patch os.isatty to test this path
        with patch("os.isatty", return_value=True):
            result = runner.invoke(attach, ["my-sandbox", "--ide-only", "nonexistent-xyz"])
        assert result.exit_code != 0
