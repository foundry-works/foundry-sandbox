"""Tests for the cast open command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.open_cmd import open_cmd


def _mock_sandbox(mock_validate, mock_resolve):
    mock_validate.return_value = (True, "")
    mock_workspace = MagicMock()
    mock_workspace.is_dir.return_value = True
    mock_resolve.return_value = mock_workspace


class TestOpenCommand:
    @patch("foundry_sandbox.ide._launch_via_cli", return_value=True)
    @patch("foundry_sandbox.ide._try_macos_open", return_value=False)
    @patch("foundry_sandbox.commands.open_cmd.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("shutil.which", return_value="/usr/bin/code")
    def test_open_with_config_ide(
        self, mock_which, mock_ide_config, mock_validate, mock_resolve,
        mock_macos, mock_cli,
    ):
        from foundry_sandbox.foundry_config import IdeConfig
        mock_ide_config.return_value = IdeConfig(preferred="code")
        _mock_sandbox(mock_validate, mock_resolve)

        runner = CliRunner()
        result = runner.invoke(open_cmd, ["my-sandbox"])
        assert result.exit_code == 0

    @patch("foundry_sandbox.ide._launch_via_cli", return_value=True)
    @patch("foundry_sandbox.ide._try_macos_open", return_value=False)
    @patch("foundry_sandbox.commands.open_cmd.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("shutil.which", return_value="/usr/bin/zed")
    def test_open_with_ide_override(
        self, mock_which, mock_ide_config, mock_validate, mock_resolve,
        mock_macos, mock_cli,
    ):
        from foundry_sandbox.foundry_config import IdeConfig
        mock_ide_config.return_value = IdeConfig(preferred="code")
        _mock_sandbox(mock_validate, mock_resolve)

        runner = CliRunner()
        result = runner.invoke(open_cmd, ["my-sandbox", "--ide", "zed"])
        assert result.exit_code == 0

    @patch("foundry_sandbox.ide._launch_via_cli", return_value=True)
    @patch("foundry_sandbox.ide._try_macos_open", return_value=False)
    @patch("foundry_sandbox.commands.open_cmd.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("foundry_sandbox.state.load_last_attach", return_value="last-sandbox")
    @patch("shutil.which", return_value="/usr/bin/code")
    def test_open_last(
        self, mock_which, mock_last, mock_ide_config, mock_validate,
        mock_resolve, mock_macos, mock_cli,
    ):
        from foundry_sandbox.foundry_config import IdeConfig
        mock_ide_config.return_value = IdeConfig(preferred="code")
        _mock_sandbox(mock_validate, mock_resolve)

        runner = CliRunner()
        result = runner.invoke(open_cmd, ["--last"])
        assert result.exit_code == 0

    @patch("foundry_sandbox.commands.open_cmd.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    def test_open_invalid_sandbox(
        self, mock_ide_config, mock_validate, mock_resolve,
    ):
        mock_ide_config.return_value = None
        mock_validate.return_value = (False, "not found")

        runner = CliRunner()
        result = runner.invoke(open_cmd, ["missing-sandbox"])
        assert result.exit_code != 0

    @patch("foundry_sandbox.commands.open_cmd.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("shutil.which", return_value=None)
    def test_open_no_ide_available(
        self, mock_which, mock_ide_config, mock_validate, mock_resolve,
    ):
        mock_ide_config.return_value = None
        _mock_sandbox(mock_validate, mock_resolve)

        runner = CliRunner()
        result = runner.invoke(open_cmd, ["my-sandbox"])
        assert result.exit_code != 0

    @patch("foundry_sandbox.ide._launch_via_cli", return_value=False)
    @patch("foundry_sandbox.ide._try_macos_open", return_value=False)
    @patch("foundry_sandbox.commands.open_cmd.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("shutil.which", return_value="/usr/bin/code")
    def test_open_launch_failure_exits_nonzero(
        self, mock_which, mock_ide_config, mock_validate, mock_resolve,
        mock_macos, mock_cli,
    ):
        from foundry_sandbox.foundry_config import IdeConfig
        mock_ide_config.return_value = IdeConfig(preferred="code")
        _mock_sandbox(mock_validate, mock_resolve)

        runner = CliRunner()
        result = runner.invoke(open_cmd, ["my-sandbox"])
        assert result.exit_code != 0

    @patch("foundry_sandbox.ide._launch_via_cli", return_value=True)
    @patch("foundry_sandbox.ide._try_macos_open", return_value=False)
    @patch("foundry_sandbox.commands.open_cmd.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("shutil.which", return_value="/usr/bin/zed")
    @patch("foundry_sandbox.state.load_sandbox_metadata",
           return_value={"ide": "zed"})
    @patch("foundry_sandbox.state.load_last_ide", return_value=None)
    def test_open_uses_sandbox_metadata_ide(
        self, mock_last_ide, mock_metadata, mock_which, mock_ide_config,
        mock_validate, mock_resolve, mock_macos, mock_cli,
    ):
        """Sandbox metadata ide field is used when no user config preferred."""
        mock_ide_config.return_value = None
        _mock_sandbox(mock_validate, mock_resolve)

        runner = CliRunner()
        result = runner.invoke(open_cmd, ["my-sandbox"])
        assert result.exit_code == 0

    @patch("foundry_sandbox.ide._launch_via_cli", return_value=True)
    @patch("foundry_sandbox.ide._try_macos_open", return_value=False)
    @patch("foundry_sandbox.commands.open_cmd.resolve_host_worktree_path")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name")
    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("shutil.which", return_value="/usr/bin/code")
    @patch("foundry_sandbox.state.load_sandbox_metadata", return_value={})
    @patch("foundry_sandbox.state.load_last_ide", return_value="code")
    def test_open_uses_last_ide(
        self, mock_last_ide, mock_metadata, mock_which, mock_ide_config,
        mock_validate, mock_resolve, mock_macos, mock_cli,
    ):
        """Last IDE is used when no user config or metadata IDE."""
        mock_ide_config.return_value = None
        _mock_sandbox(mock_validate, mock_resolve)

        runner = CliRunner()
        result = runner.invoke(open_cmd, ["my-sandbox"])
        assert result.exit_code == 0
