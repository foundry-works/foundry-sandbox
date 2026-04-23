"""Tests for the cast up command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.up import up


def _mock_sandbox(mock_validate, mock_resolve):
    mock_validate.return_value = (True, "")
    mock_workspace = MagicMock()
    mock_workspace.is_dir.return_value = True
    mock_workspace.__str__ = lambda self: "/fake/worktree"
    mock_resolve.return_value = mock_workspace


# Common mocks for up command tests (bottom-up decorator order)
_UP_MOCKS = [
    patch("foundry_sandbox.commands.attach.sbx_exec_streaming"),
    patch("foundry_sandbox.commands.up.sbx_is_running", return_value=True),
    patch("foundry_sandbox.commands.up.sbx_check_available"),
    patch("foundry_sandbox.ide._launch_via_cli", return_value=True),
    patch("foundry_sandbox.ide._try_macos_open", return_value=False),
    patch("foundry_sandbox.commands.up.resolve_host_worktree_path"),
    patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name"),
    patch("foundry_sandbox.foundry_config.load_user_ide_config"),
    patch("shutil.which", return_value="/usr/bin/code"),
    patch("foundry_sandbox.state.load_sandbox_metadata", return_value={}),
    patch("foundry_sandbox.state.save_last_attach"),
    patch("foundry_sandbox.state.load_last_ide", return_value=None),
]


def _apply_mocks(func):
    """Apply common mocks to a test method."""
    for mock in reversed(_UP_MOCKS):
        func = mock(func)
    return func


class TestUpCommand:
    @_apply_mocks
    def test_up_basic_flow(
        self, mock_last_ide, mock_save, mock_metadata, mock_which,
        mock_ide_config, mock_validate, mock_resolve,
        mock_macos, mock_cli, mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import IdeConfig
        mock_ide_config.return_value = IdeConfig(preferred="code")
        _mock_sandbox(mock_validate, mock_resolve)

        mock_proc = MagicMock()
        mock_exec.return_value = mock_proc

        runner = CliRunner()
        result = runner.invoke(up, ["my-sandbox"])
        assert result.exit_code == 0

    @_apply_mocks
    def test_up_no_ide(
        self, mock_last_ide, mock_save, mock_metadata, mock_which,
        mock_ide_config, mock_validate, mock_resolve,
        mock_macos, mock_cli, mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import IdeConfig
        mock_ide_config.return_value = IdeConfig(preferred="code")
        _mock_sandbox(mock_validate, mock_resolve)

        mock_proc = MagicMock()
        mock_exec.return_value = mock_proc

        runner = CliRunner()
        result = runner.invoke(up, ["my-sandbox", "--no-ide"])
        assert result.exit_code == 0
        mock_cli.assert_not_called()

    @patch("foundry_sandbox.commands.up.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("foundry_sandbox.commands.up.sbx_check_available")
    def test_up_missing_sandbox(
        self, mock_check, mock_ide_config, mock_validate, mock_resolve,
    ):
        mock_ide_config.return_value = None
        mock_validate.return_value = (True, "")
        mock_workspace = MagicMock()
        mock_workspace.is_dir.return_value = False
        mock_resolve.return_value = mock_workspace

        runner = CliRunner()
        result = runner.invoke(up, ["missing-sandbox"])
        assert result.exit_code != 0

    @_apply_mocks
    def test_up_uses_last_ide(
        self, mock_last_ide, mock_save, mock_metadata, mock_which,
        mock_ide_config, mock_validate, mock_resolve,
        mock_macos, mock_cli, mock_check, mock_running, mock_exec,
    ):
        mock_ide_config.return_value = None  # no user config
        mock_last_ide.return_value = "code"
        _mock_sandbox(mock_validate, mock_resolve)

        mock_proc = MagicMock()
        mock_exec.return_value = mock_proc

        runner = CliRunner()
        result = runner.invoke(up, ["my-sandbox"])
        assert result.exit_code == 0
