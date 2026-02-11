"""Unit tests for `foundry_sandbox.commands.attach` helpers."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import click.testing
import pytest

from foundry_sandbox.commands.attach import (
    _handle_ide_options,
    _resolve_sandbox_name,
    attach,
)


@pytest.fixture()
def runner() -> click.testing.CliRunner:
    return click.testing.CliRunner()


# ---------------------------------------------------------------------------
# _resolve_sandbox_name
# ---------------------------------------------------------------------------


class TestResolveSandboxName:

    @patch("foundry_sandbox.commands.attach.validate_existing_sandbox_name")
    def test_explicit_name_returned(self, mock_validate: MagicMock) -> None:
        mock_validate.return_value = (True, "")
        assert _resolve_sandbox_name("my-sandbox", use_last=False) == "my-sandbox"

    @patch("foundry_sandbox.commands.attach.validate_existing_sandbox_name")
    def test_last_flag_loads_from_state(self, mock_validate: MagicMock) -> None:
        mock_validate.return_value = (True, "")
        with patch("foundry_sandbox.commands.attach.load_last_attach", return_value="prev-sandbox"):
            result = _resolve_sandbox_name(None, use_last=True)
        assert result == "prev-sandbox"

    def test_last_flag_exits_when_no_previous(self) -> None:
        with patch("foundry_sandbox.commands.attach.load_last_attach", return_value=None):
            with pytest.raises(SystemExit):
                _resolve_sandbox_name(None, use_last=True)

    @patch("foundry_sandbox.commands.attach.validate_existing_sandbox_name")
    @patch("foundry_sandbox.commands.attach._fzf_select_sandbox", return_value=None)
    @patch("foundry_sandbox.commands.attach._auto_detect_sandbox", return_value="auto-detected")
    def test_auto_detect_fallback(
        self, mock_auto: MagicMock, mock_fzf: MagicMock, mock_validate: MagicMock,
    ) -> None:
        mock_validate.return_value = (True, "")
        result = _resolve_sandbox_name(None, use_last=False)
        assert result == "auto-detected"

    @patch("foundry_sandbox.commands.attach._list_sandboxes")
    @patch("foundry_sandbox.commands.attach._fzf_select_sandbox", return_value=None)
    @patch("foundry_sandbox.commands.attach._auto_detect_sandbox", return_value=None)
    def test_exits_when_no_sandbox_found(
        self, mock_auto: MagicMock, mock_fzf: MagicMock, mock_list: MagicMock,
    ) -> None:
        with pytest.raises(SystemExit):
            _resolve_sandbox_name(None, use_last=False)

    def test_invalid_name_exits(self) -> None:
        with patch(
            "foundry_sandbox.commands.attach.validate_existing_sandbox_name",
            return_value=(False, "bad name"),
        ):
            with pytest.raises(SystemExit):
                _resolve_sandbox_name("../bad", use_last=False)


# ---------------------------------------------------------------------------
# _handle_ide_options
# ---------------------------------------------------------------------------


class TestHandleIdeOptions:

    def test_no_ide_returns_false(self) -> None:
        with patch("os.isatty", return_value=True):
            result = _handle_ide_options("sb", "/tmp/wt", no_ide=True, with_ide=None, ide_only=None)
        assert result is False

    def test_not_tty_returns_false(self) -> None:
        with patch("os.isatty", return_value=False):
            result = _handle_ide_options("sb", "/tmp/wt", no_ide=False, with_ide="cursor", ide_only=None)
        assert result is False

    @patch("foundry_sandbox.commands.attach._launch_ide", return_value=True)
    def test_ide_only_named_returns_true(self, mock_launch: MagicMock) -> None:
        with patch("os.isatty", return_value=True):
            result = _handle_ide_options("sb", "/tmp/wt", no_ide=False, with_ide=None, ide_only="cursor")
        assert result is True
        mock_launch.assert_called_once_with("cursor", "/tmp/wt")

    @patch("foundry_sandbox.commands.attach._launch_ide", return_value=False)
    def test_ide_only_named_fails_returns_false(self, mock_launch: MagicMock) -> None:
        with patch("os.isatty", return_value=True):
            result = _handle_ide_options("sb", "/tmp/wt", no_ide=False, with_ide=None, ide_only="cursor")
        assert result is False

    @patch("foundry_sandbox.commands.attach._launch_ide", return_value=True)
    def test_with_ide_named_returns_false(self, mock_launch: MagicMock) -> None:
        """--with-ide launches IDE but still returns False (terminal continues)."""
        with patch("os.isatty", return_value=True):
            result = _handle_ide_options("sb", "/tmp/wt", no_ide=False, with_ide="cursor", ide_only=None)
        assert result is False
        mock_launch.assert_called_once_with("cursor", "/tmp/wt")

    @patch("foundry_sandbox.commands.attach._prompt_ide_selection", return_value=True)
    def test_ide_only_auto_prompts(self, mock_prompt: MagicMock) -> None:
        with patch("os.isatty", return_value=True):
            result = _handle_ide_options("sb", "/tmp/wt", no_ide=False, with_ide=None, ide_only="auto")
        assert result is True
        mock_prompt.assert_called_once()

    @patch("foundry_sandbox.commands.attach._prompt_ide_selection", return_value=False)
    def test_with_ide_auto_prompts(self, mock_prompt: MagicMock) -> None:
        with patch("os.isatty", return_value=True):
            result = _handle_ide_options("sb", "/tmp/wt", no_ide=False, with_ide="auto", ide_only=None)
        assert result is False
        mock_prompt.assert_called_once()


# ---------------------------------------------------------------------------
# Full attach command
# ---------------------------------------------------------------------------


class TestAttachCommand:

    @patch("foundry_sandbox.commands.attach._tmux_attach")
    @patch("foundry_sandbox.commands.attach.save_last_attach")
    @patch("foundry_sandbox.commands.attach.load_sandbox_metadata", return_value=None)
    @patch("foundry_sandbox.commands.attach.container_is_running", return_value=True)
    @patch("foundry_sandbox.commands.attach.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.attach._resolve_sandbox_name", return_value="test-sb")
    def test_basic_attach_flow(
        self,
        mock_resolve: MagicMock,
        mock_paths: MagicMock,
        mock_running: MagicMock,
        mock_metadata: MagicMock,
        mock_save: MagicMock,
        mock_tmux: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        wt = tmp_path / "wt"
        wt.mkdir()
        mock_paths.return_value = MagicMock(
            worktree_path=wt,
            container_name="sandbox-test-sb",
        )

        result = runner.invoke(attach, ["test-sb", "--no-ide"])
        assert result.exit_code == 0
        mock_save.assert_called_once_with("test-sb")
        mock_tmux.assert_called_once()

    @patch("foundry_sandbox.commands.attach._list_sandboxes")
    @patch("foundry_sandbox.commands.attach.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.attach._resolve_sandbox_name", return_value="test-sb")
    def test_missing_worktree_exits(
        self,
        mock_resolve: MagicMock,
        mock_paths: MagicMock,
        mock_list: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        mock_paths.return_value = MagicMock(
            worktree_path=tmp_path / "nonexistent",
            container_name="sandbox-test-sb",
        )

        result = runner.invoke(attach, ["test-sb"])
        assert result.exit_code != 0

    @patch("foundry_sandbox.commands.attach._tmux_attach")
    @patch("foundry_sandbox.commands.attach.save_last_attach")
    @patch("foundry_sandbox.commands.attach.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.attach._start_container")
    @patch("foundry_sandbox.commands.attach.container_is_running", return_value=False)
    @patch("foundry_sandbox.commands.attach.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.attach._resolve_sandbox_name", return_value="test-sb")
    def test_starts_container_when_not_running(
        self,
        mock_resolve: MagicMock,
        mock_paths: MagicMock,
        mock_running: MagicMock,
        mock_start: MagicMock,
        mock_metadata: MagicMock,
        mock_save: MagicMock,
        mock_tmux: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        wt = tmp_path / "wt"
        wt.mkdir()
        mock_paths.return_value = MagicMock(
            worktree_path=wt,
            container_name="sandbox-test-sb",
        )
        mock_metadata.return_value = None

        result = runner.invoke(attach, ["test-sb", "--no-ide"])
        assert result.exit_code == 0
        mock_start.assert_called_once_with("test-sb")
