"""Unit tests for foundry_sandbox.compose override assembly."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from foundry_sandbox.compose import assemble_override, ensure_override_dir


class TestAssembleOverride:
    """Test assemble_override() orchestration."""

    @patch("foundry_sandbox.compose.add_ssh_agent_to_override")
    @patch("foundry_sandbox.compose.add_timezone_to_override")
    @patch("foundry_sandbox.compose.add_claude_home_to_override")
    @patch("foundry_sandbox.compose.add_network_to_override")
    @patch("foundry_sandbox.compose.append_override_list_item")
    @patch("foundry_sandbox.compose.ensure_override_header")
    def test_calls_helpers_in_correct_order(
        self,
        mock_header: MagicMock,
        mock_append: MagicMock,
        mock_network: MagicMock,
        mock_claude_home: MagicMock,
        mock_tz: MagicMock,
        mock_ssh: MagicMock,
    ) -> None:
        assemble_override(
            "/tmp/override.yml",
            claude_home="/home/user/.claude",
            network_mode="limited",
            ssh_agent_sock="/tmp/ssh.sock",
        )

        mock_header.assert_called_once_with("/tmp/override.yml")
        mock_network.assert_called_once_with("limited", "/tmp/override.yml")
        mock_claude_home.assert_called_once_with("/tmp/override.yml", "/home/user/.claude")
        mock_tz.assert_called_once_with("/tmp/override.yml")
        mock_ssh.assert_called_once_with("/tmp/override.yml", "/tmp/ssh.sock")

    @patch("foundry_sandbox.compose.add_ssh_agent_to_override")
    @patch("foundry_sandbox.compose.add_timezone_to_override")
    @patch("foundry_sandbox.compose.add_claude_home_to_override")
    @patch("foundry_sandbox.compose.add_network_to_override")
    @patch("foundry_sandbox.compose.append_override_list_item")
    @patch("foundry_sandbox.compose.ensure_override_header")
    def test_network_skipped_when_isolate_credentials(
        self,
        mock_header: MagicMock,
        mock_append: MagicMock,
        mock_network: MagicMock,
        mock_claude_home: MagicMock,
        mock_tz: MagicMock,
        mock_ssh: MagicMock,
    ) -> None:
        assemble_override(
            "/tmp/override.yml",
            isolate_credentials=True,
        )

        mock_network.assert_not_called()

    @patch("foundry_sandbox.compose.add_ssh_agent_to_override")
    @patch("foundry_sandbox.compose.add_timezone_to_override")
    @patch("foundry_sandbox.compose.add_claude_home_to_override")
    @patch("foundry_sandbox.compose.add_network_to_override")
    @patch("foundry_sandbox.compose.append_override_list_item")
    @patch("foundry_sandbox.compose.ensure_override_header")
    def test_extra_volumes_appended(
        self,
        mock_header: MagicMock,
        mock_append: MagicMock,
        mock_network: MagicMock,
        mock_claude_home: MagicMock,
        mock_tz: MagicMock,
        mock_ssh: MagicMock,
    ) -> None:
        assemble_override(
            "/tmp/override.yml",
            extra_volumes=["/host/a:/container/a", "/host/b:/container/b"],
        )

        assert mock_append.call_count == 2
        mock_append.assert_any_call("/tmp/override.yml", "volumes", "/host/a:/container/a")
        mock_append.assert_any_call("/tmp/override.yml", "volumes", "/host/b:/container/b")

    @patch("foundry_sandbox.compose.add_ssh_agent_to_override")
    @patch("foundry_sandbox.compose.add_timezone_to_override")
    @patch("foundry_sandbox.compose.add_claude_home_to_override")
    @patch("foundry_sandbox.compose.add_network_to_override")
    @patch("foundry_sandbox.compose.append_override_list_item")
    @patch("foundry_sandbox.compose.ensure_override_header")
    def test_no_extra_volumes_skips_append(
        self,
        mock_header: MagicMock,
        mock_append: MagicMock,
        mock_network: MagicMock,
        mock_claude_home: MagicMock,
        mock_tz: MagicMock,
        mock_ssh: MagicMock,
    ) -> None:
        assemble_override("/tmp/override.yml")
        mock_append.assert_not_called()

    @patch("foundry_sandbox.compose.add_ssh_agent_to_override")
    @patch("foundry_sandbox.compose.add_timezone_to_override")
    @patch("foundry_sandbox.compose.add_claude_home_to_override")
    @patch("foundry_sandbox.compose.add_network_to_override")
    @patch("foundry_sandbox.compose.append_override_list_item")
    @patch("foundry_sandbox.compose.ensure_override_header")
    def test_ssh_agent_called_with_empty_sock(
        self,
        mock_header: MagicMock,
        mock_append: MagicMock,
        mock_network: MagicMock,
        mock_claude_home: MagicMock,
        mock_tz: MagicMock,
        mock_ssh: MagicMock,
    ) -> None:
        assemble_override("/tmp/override.yml", ssh_agent_sock="")
        mock_ssh.assert_called_once_with("/tmp/override.yml", "")


class TestEnsureOverrideDir:
    """Test ensure_override_dir() directory creation."""

    def test_creates_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            override_path = f"{tmpdir}/subdir/nested/override.yml"
            ensure_override_dir(override_path)
            assert Path(f"{tmpdir}/subdir/nested").is_dir()

    def test_existing_directory_no_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            override_path = f"{tmpdir}/override.yml"
            ensure_override_dir(override_path)  # Should not raise
            ensure_override_dir(override_path)  # Idempotent
