"""Unit tests for `foundry_sandbox.commands.destroy`."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import click.testing
import pytest

from foundry_sandbox.commands.destroy import destroy


@pytest.fixture()
def runner() -> click.testing.CliRunner:
    return click.testing.CliRunner()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestDestroyValidation:

    def test_rejects_empty_name(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(destroy, [""])
        assert result.exit_code != 0

    def test_rejects_path_separator(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(destroy, ["../escape"])
        assert result.exit_code != 0
        assert "path separator" in result.output.lower() or "Error" in result.output

    def test_rejects_dot_name(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(destroy, [".."])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Confirmation prompt
# ---------------------------------------------------------------------------


class TestDestroyConfirmation:

    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_aborts_on_deny(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        mock_validate.return_value = (True, "")
        mock_paths.return_value = MagicMock(
            worktree_path=tmp_path / "wt",
            container_name="sandbox-test",
            claude_config_path=tmp_path / "cc",
            override_file=tmp_path / "override.yml",
        )
        # Respond "n" to the confirmation prompt
        result = runner.invoke(destroy, ["test-sandbox"], input="n\n")
        assert result.exit_code == 0
        assert "Aborted" in result.output

    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_force_flag_skips_prompt(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_subproc: MagicMock,
        mock_proxy: MagicMock,
        mock_compose: MagicMock,
        mock_stubs: MagicMock,
        mock_hmac: MagicMock,
        mock_metadata: MagicMock,
        mock_rm_wt: MagicMock,
        mock_branch: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        mock_validate.return_value = (True, "")
        wt = tmp_path / "wt"
        wt.mkdir()
        mock_paths.return_value = MagicMock(
            worktree_path=wt,
            container_name="sandbox-test",
            claude_config_path=tmp_path / "cc",
            override_file=tmp_path / "override.yml",
        )
        mock_metadata.return_value = None
        mock_subproc.return_value = MagicMock(returncode=1)

        result = runner.invoke(destroy, ["test-sandbox", "--force"])
        assert result.exit_code == 0
        assert "destroyed" in result.output.lower()

    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_yes_flag_skips_prompt(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_subproc: MagicMock,
        mock_proxy: MagicMock,
        mock_compose: MagicMock,
        mock_stubs: MagicMock,
        mock_hmac: MagicMock,
        mock_metadata: MagicMock,
        mock_rm_wt: MagicMock,
        mock_branch: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        mock_validate.return_value = (True, "")
        wt = tmp_path / "wt"
        wt.mkdir()
        mock_paths.return_value = MagicMock(
            worktree_path=wt,
            container_name="sandbox-test",
            claude_config_path=tmp_path / "cc",
            override_file=tmp_path / "override.yml",
        )
        mock_metadata.return_value = None
        mock_subproc.return_value = MagicMock(returncode=1)

        result = runner.invoke(destroy, ["test-sandbox", "-y"])
        assert result.exit_code == 0
        assert "destroyed" in result.output.lower()

    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_noninteractive_env_skips_prompt(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_subproc: MagicMock,
        mock_proxy: MagicMock,
        mock_compose: MagicMock,
        mock_stubs: MagicMock,
        mock_hmac: MagicMock,
        mock_metadata: MagicMock,
        mock_rm_wt: MagicMock,
        mock_branch: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        mock_validate.return_value = (True, "")
        wt = tmp_path / "wt"
        wt.mkdir()
        mock_paths.return_value = MagicMock(
            worktree_path=wt,
            container_name="sandbox-test",
            claude_config_path=tmp_path / "cc",
            override_file=tmp_path / "override.yml",
        )
        mock_metadata.return_value = None
        mock_subproc.return_value = MagicMock(returncode=1)

        result = runner.invoke(
            destroy, ["test-sandbox"], env={"SANDBOX_NONINTERACTIVE": "1"}
        )
        assert result.exit_code == 0
        assert "destroyed" in result.output.lower()


# ---------------------------------------------------------------------------
# Cleanup sequence
# ---------------------------------------------------------------------------


class TestDestroyCleanup:

    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_calls_all_cleanup_steps(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_subproc: MagicMock,
        mock_proxy: MagicMock,
        mock_compose: MagicMock,
        mock_stubs: MagicMock,
        mock_hmac: MagicMock,
        mock_metadata: MagicMock,
        mock_rm_wt: MagicMock,
        mock_branch: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        mock_validate.return_value = (True, "")
        wt = tmp_path / "wt"
        wt.mkdir()
        cc = tmp_path / "cc"
        cc.mkdir()
        mock_paths.return_value = MagicMock(
            worktree_path=wt,
            container_name="sandbox-test",
            claude_config_path=cc,
            override_file=tmp_path / "override.yml",
        )
        mock_metadata.return_value = {"branch": "sandbox/feat", "repo_url": "https://github.com/user/repo"}
        mock_subproc.return_value = MagicMock(returncode=1)

        result = runner.invoke(destroy, ["test-sandbox", "--force"])

        assert result.exit_code == 0
        mock_proxy.assert_called_once()
        mock_compose.assert_called_once()
        mock_stubs.assert_called_once()
        mock_hmac.assert_called_once()
        mock_rm_wt.assert_called_once()
        mock_branch.assert_called_once()

    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_keep_worktree_skips_worktree_removal(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_subproc: MagicMock,
        mock_proxy: MagicMock,
        mock_compose: MagicMock,
        mock_stubs: MagicMock,
        mock_hmac: MagicMock,
        mock_metadata: MagicMock,
        mock_rm_wt: MagicMock,
        mock_branch: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        mock_validate.return_value = (True, "")
        wt = tmp_path / "wt"
        wt.mkdir()
        cc = tmp_path / "cc"
        cc.mkdir()
        mock_paths.return_value = MagicMock(
            worktree_path=wt,
            container_name="sandbox-test",
            claude_config_path=cc,
            override_file=tmp_path / "override.yml",
        )
        mock_metadata.return_value = None
        mock_subproc.return_value = MagicMock(returncode=1)

        result = runner.invoke(destroy, ["test-sandbox", "--force", "--keep-worktree"])

        assert result.exit_code == 0
        mock_rm_wt.assert_not_called()
        # Config dir should NOT be removed either
        assert cc.is_dir()

    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down", side_effect=OSError("docker not found"))
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run", side_effect=OSError("tmux not found"))
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_continues_on_cleanup_errors(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_subproc: MagicMock,
        mock_proxy: MagicMock,
        mock_compose: MagicMock,
        mock_stubs: MagicMock,
        mock_hmac: MagicMock,
        mock_metadata: MagicMock,
        mock_rm_wt: MagicMock,
        mock_branch: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        """Cleanup is best-effort: errors in early steps don't prevent later steps."""
        mock_validate.return_value = (True, "")
        wt = tmp_path / "wt"
        wt.mkdir()
        mock_paths.return_value = MagicMock(
            worktree_path=wt,
            container_name="sandbox-test",
            claude_config_path=tmp_path / "cc",
            override_file=tmp_path / "override.yml",
        )
        mock_metadata.return_value = None

        result = runner.invoke(destroy, ["test-sandbox", "--force"])
        # Should still succeed despite errors in tmux kill and compose down
        assert result.exit_code == 0
        assert "destroyed" in result.output.lower()

    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_skips_branch_cleanup_when_no_metadata(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_subproc: MagicMock,
        mock_proxy: MagicMock,
        mock_compose: MagicMock,
        mock_stubs: MagicMock,
        mock_hmac: MagicMock,
        mock_metadata: MagicMock,
        mock_rm_wt: MagicMock,
        mock_branch: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        mock_validate.return_value = (True, "")
        wt = tmp_path / "wt"
        wt.mkdir()
        mock_paths.return_value = MagicMock(
            worktree_path=wt,
            container_name="sandbox-test",
            claude_config_path=tmp_path / "cc",
            override_file=tmp_path / "override.yml",
        )
        mock_metadata.return_value = None
        mock_subproc.return_value = MagicMock(returncode=1)

        result = runner.invoke(destroy, ["test-sandbox", "--force"])
        assert result.exit_code == 0
        mock_branch.assert_not_called()
