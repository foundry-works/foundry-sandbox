"""Unit tests for remaining command modules.

Covers: stop, build, status, list_cmd, refresh_creds, destroy_all, preset,
upgrade.  Each command gets a focused test class exercising validation, flag
handling, output formatting, and key error paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import click.testing
import pytest


@pytest.fixture()
def runner() -> click.testing.CliRunner:
    return click.testing.CliRunner()


# =========================================================================
# stop
# =========================================================================


class TestStopCommand:

    def _get_cmd(self):
        from foundry_sandbox.commands.stop import stop
        return stop

    def test_rejects_invalid_name(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(self._get_cmd(), ["../bad"])
        assert result.exit_code != 0

    @patch("foundry_sandbox.commands.stop.compose_down")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.stop.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.stop.validate_existing_sandbox_name")
    def test_stop_calls_compose_down(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_subproc: MagicMock,
        mock_compose: MagicMock,
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

        result = runner.invoke(self._get_cmd(), ["test-sb"])
        assert result.exit_code == 0
        mock_compose.assert_called_once()
        # remove_volumes should be False for stop
        _, kwargs = mock_compose.call_args
        assert kwargs.get("remove_volumes") is False

    @patch("foundry_sandbox.commands.stop.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.stop.validate_existing_sandbox_name")
    def test_stop_missing_worktree(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        mock_validate.return_value = (True, "")
        mock_paths.return_value = MagicMock(
            worktree_path=tmp_path / "nonexistent",
        )

        result = runner.invoke(self._get_cmd(), ["test-sb"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()


# =========================================================================
# build
# =========================================================================


class TestBuildCommand:

    def _get_cmd(self):
        from foundry_sandbox.commands.build import build
        return build

    @patch("subprocess.run")
    def test_build_default_no_cache(self, mock_run: MagicMock, runner: click.testing.CliRunner) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        result = runner.invoke(self._get_cmd(), [])
        assert result.exit_code == 0
        # Should have been called twice: compose build + proxy build
        assert mock_run.call_count == 2
        # First call should NOT have --no-cache
        first_call_args = mock_run.call_args_list[0][0][0]
        assert "--no-cache" not in first_call_args

    @patch("subprocess.run")
    def test_build_with_no_cache(self, mock_run: MagicMock, runner: click.testing.CliRunner) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        result = runner.invoke(self._get_cmd(), ["--no-cache"])
        assert result.exit_code == 0
        first_call_args = mock_run.call_args_list[0][0][0]
        assert "--no-cache" in first_call_args

    @patch("subprocess.run")
    def test_build_without_opencode(self, mock_run: MagicMock, runner: click.testing.CliRunner) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        result = runner.invoke(self._get_cmd(), ["--without-opencode"])
        assert result.exit_code == 0
        first_call_args = mock_run.call_args_list[0][0][0]
        assert "--build-arg" in first_call_args
        assert "INCLUDE_OPENCODE=0" in first_call_args

    @patch("subprocess.run")
    def test_build_exits_on_failure(self, mock_run: MagicMock, runner: click.testing.CliRunner) -> None:
        mock_run.return_value = MagicMock(returncode=1)
        result = runner.invoke(self._get_cmd(), [])
        assert result.exit_code == 1


# =========================================================================
# status
# =========================================================================


class TestStatusCommand:

    def _get_cmd(self):
        from foundry_sandbox.commands.status import status
        return status

    @patch("foundry_sandbox.commands.status.load_sandbox_metadata", return_value=None)
    @patch("foundry_sandbox.commands.status._tmux_session_exists", return_value=False)
    @patch("foundry_sandbox.commands.status._get_docker_status", return_value="no container")
    @patch("foundry_sandbox.commands.status.get_claude_configs_dir")
    @patch("foundry_sandbox.commands.status.get_worktrees_dir")
    @patch("foundry_sandbox.commands.status.validate_existing_sandbox_name")
    def test_single_sandbox_json_output(
        self,
        mock_validate: MagicMock,
        mock_wt_dir: MagicMock,
        mock_cc_dir: MagicMock,
        mock_docker: MagicMock,
        mock_tmux: MagicMock,
        mock_meta: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
        mock_validate.return_value = (True, "")
        mock_wt_dir.return_value = tmp_path / "wt"
        mock_cc_dir.return_value = tmp_path / "cc"

        result = runner.invoke(self._get_cmd(), ["test-sb", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "test-sb"
        assert data["docker_status"] == "no container"
        assert data["tmux"] == "none"

    @patch("foundry_sandbox.commands.status.get_worktrees_dir")
    def test_all_sandboxes_empty(
        self, mock_wt_dir: MagicMock, runner: click.testing.CliRunner, tmp_path: Path,
    ) -> None:
        wt = tmp_path / "wt"
        wt.mkdir()
        mock_wt_dir.return_value = wt
        result = runner.invoke(self._get_cmd(), ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []


# =========================================================================
# list_cmd
# =========================================================================


class TestListCommand:

    def _get_cmd(self):
        from foundry_sandbox.commands.list_cmd import list_cmd
        return list_cmd

    @patch("foundry_sandbox.commands.list_cmd.get_worktrees_dir")
    def test_empty_worktrees_json(
        self, mock_wt_dir: MagicMock, runner: click.testing.CliRunner, tmp_path: Path,
    ) -> None:
        wt = tmp_path / "wt"
        wt.mkdir()
        mock_wt_dir.return_value = wt
        result = runner.invoke(self._get_cmd(), ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []

    @patch("foundry_sandbox.commands.list_cmd.get_worktrees_dir")
    def test_no_worktrees_dir_json(
        self, mock_wt_dir: MagicMock, runner: click.testing.CliRunner, tmp_path: Path,
    ) -> None:
        mock_wt_dir.return_value = tmp_path / "nonexistent"
        result = runner.invoke(self._get_cmd(), ["--json"])
        assert result.exit_code == 0
        assert result.output.strip() == "[]"

    @patch("foundry_sandbox.commands.list_cmd.get_worktrees_dir")
    def test_no_worktrees_dir_text(
        self, mock_wt_dir: MagicMock, runner: click.testing.CliRunner, tmp_path: Path,
    ) -> None:
        mock_wt_dir.return_value = tmp_path / "nonexistent"
        result = runner.invoke(self._get_cmd(), [])
        assert result.exit_code == 0
        assert "Sandboxes:" in result.output


# =========================================================================
# refresh_creds
# =========================================================================


class TestRefreshCredsCommand:

    def _get_cmd(self):
        from foundry_sandbox.commands.refresh_creds import refresh_creds
        return refresh_creds

    def test_rejects_invalid_name(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(self._get_cmd(), ["../bad"])
        assert result.exit_code != 0

    @patch("foundry_sandbox.commands.refresh_creds._refresh_direct_mode")
    @patch("foundry_sandbox.commands.refresh_creds._check_isolation_mode", return_value=False)
    @patch("foundry_sandbox.commands.refresh_creds.container_is_running", return_value=True)
    @patch("foundry_sandbox.commands.refresh_creds.load_sandbox_metadata", return_value={"branch": "main"})
    @patch("foundry_sandbox.commands.refresh_creds.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.refresh_creds.validate_existing_sandbox_name")
    def test_direct_mode_refresh(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_meta: MagicMock,
        mock_running: MagicMock,
        mock_isolation: MagicMock,
        mock_refresh: MagicMock,
        runner: click.testing.CliRunner,
    ) -> None:
        mock_validate.return_value = (True, "")
        mock_paths.return_value = MagicMock(
            container_name="sandbox-test",
            override_file=Path("/tmp/override.yml"),
        )

        result = runner.invoke(self._get_cmd(), ["test-sb"])
        assert result.exit_code == 0
        mock_refresh.assert_called_once_with("sandbox-test-dev-1")

    @patch("foundry_sandbox.commands.refresh_creds._refresh_isolation_mode")
    @patch("foundry_sandbox.commands.refresh_creds._check_isolation_mode", return_value=True)
    @patch("foundry_sandbox.commands.refresh_creds.container_is_running", return_value=True)
    @patch("foundry_sandbox.commands.refresh_creds.load_sandbox_metadata", return_value={"branch": "main"})
    @patch("foundry_sandbox.commands.refresh_creds.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.refresh_creds.validate_existing_sandbox_name")
    def test_isolation_mode_refresh(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_meta: MagicMock,
        mock_running: MagicMock,
        mock_isolation: MagicMock,
        mock_refresh: MagicMock,
        runner: click.testing.CliRunner,
    ) -> None:
        mock_validate.return_value = (True, "")
        mock_paths.return_value = MagicMock(
            container_name="sandbox-test",
            override_file=Path("/tmp/override.yml"),
        )

        result = runner.invoke(self._get_cmd(), ["test-sb"])
        assert result.exit_code == 0
        mock_refresh.assert_called_once()

    @patch("foundry_sandbox.commands.refresh_creds.container_is_running", return_value=False)
    @patch("foundry_sandbox.commands.refresh_creds.load_sandbox_metadata", return_value={"branch": "main"})
    @patch("foundry_sandbox.commands.refresh_creds.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.refresh_creds.validate_existing_sandbox_name")
    def test_not_running_exits(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_meta: MagicMock,
        mock_running: MagicMock,
        runner: click.testing.CliRunner,
    ) -> None:
        mock_validate.return_value = (True, "")
        mock_paths.return_value = MagicMock(
            container_name="sandbox-test",
            override_file=Path("/tmp/override.yml"),
        )

        result = runner.invoke(self._get_cmd(), ["test-sb"])
        assert result.exit_code != 0

    @patch("foundry_sandbox.commands.refresh_creds.load_sandbox_metadata", return_value=None)
    @patch("foundry_sandbox.commands.refresh_creds.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.refresh_creds.validate_existing_sandbox_name")
    def test_no_metadata_exits(
        self,
        mock_validate: MagicMock,
        mock_paths: MagicMock,
        mock_meta: MagicMock,
        runner: click.testing.CliRunner,
    ) -> None:
        mock_validate.return_value = (True, "")
        mock_paths.return_value = MagicMock(
            container_name="sandbox-test",
            override_file=Path("/tmp/override.yml"),
        )

        result = runner.invoke(self._get_cmd(), ["test-sb"])
        assert result.exit_code != 0


# =========================================================================
# destroy_all
# =========================================================================


class TestDestroyAllCommand:

    def _get_cmd(self):
        from foundry_sandbox.commands.destroy_all import destroy_all
        return destroy_all

    @patch("foundry_sandbox.commands.destroy_all._list_all_sandboxes", return_value=[])
    def test_no_sandboxes_exits_cleanly(
        self, mock_list: MagicMock, runner: click.testing.CliRunner,
    ) -> None:
        result = runner.invoke(self._get_cmd(), [])
        assert result.exit_code == 0
        assert "No sandboxes" in result.output

    @patch("foundry_sandbox.commands.destroy_all._list_all_sandboxes", return_value=["sb1"])
    def test_aborts_on_deny(self, mock_list: MagicMock, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(self._get_cmd(), [], input="n\n")
        assert result.exit_code == 0
        assert "Aborted" in result.output

    @patch("foundry_sandbox.commands.destroy_all._list_all_sandboxes", return_value=["sb1"])
    def test_aborts_on_wrong_confirmation_text(
        self, mock_list: MagicMock, runner: click.testing.CliRunner,
    ) -> None:
        result = runner.invoke(self._get_cmd(), [], input="y\nwrong text\n")
        assert result.exit_code == 0
        assert "Aborted" in result.output

    @patch("foundry_sandbox.commands.destroy_all._cleanup_orphaned_networks", return_value=0)
    @patch("foundry_sandbox.commands.destroy_all.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy_all.remove_worktree")
    @patch("foundry_sandbox.commands.destroy_all.load_sandbox_metadata", return_value=None)
    @patch("foundry_sandbox.commands.destroy_all.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy_all.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy_all.compose_down")
    @patch("foundry_sandbox.commands.destroy_all._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy_all.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy_all._list_all_sandboxes", return_value=["sb1", "sb2"])
    def test_noninteractive_destroys_all(
        self,
        mock_list: MagicMock,
        mock_paths: MagicMock,
        mock_subproc: MagicMock,
        mock_proxy: MagicMock,
        mock_compose: MagicMock,
        mock_stubs: MagicMock,
        mock_hmac: MagicMock,
        mock_meta: MagicMock,
        mock_rm_wt: MagicMock,
        mock_branch: MagicMock,
        mock_networks: MagicMock,
        runner: click.testing.CliRunner,
        tmp_path: Path,
    ) -> None:
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
        mock_subproc.return_value = MagicMock(returncode=1)

        result = runner.invoke(
            self._get_cmd(), [], env={"SANDBOX_NONINTERACTIVE": "1"},
        )
        assert result.exit_code == 0
        assert "Destroyed 2 sandbox(es)" in result.output


# =========================================================================
# preset
# =========================================================================


class TestPresetCommand:

    def _get_group(self):
        from foundry_sandbox.commands.preset import preset
        return preset

    @patch("foundry_sandbox.commands.preset.list_cast_presets", return_value=["demo", "prod"])
    def test_list_presets(self, mock_list: MagicMock, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(self._get_group(), ["list"])
        assert result.exit_code == 0
        assert "demo" in result.output
        assert "prod" in result.output

    @patch("foundry_sandbox.commands.preset.show_cast_preset", return_value="repo: user/repo\nbranch: main")
    def test_show_preset(self, mock_show: MagicMock, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(self._get_group(), ["show", "demo"])
        assert result.exit_code == 0
        assert "repo: user/repo" in result.output

    @patch("foundry_sandbox.commands.preset.show_cast_preset", return_value=None)
    def test_show_nonexistent_preset(self, mock_show: MagicMock, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(self._get_group(), ["show", "missing"])
        assert result.exit_code != 0

    @patch("foundry_sandbox.commands.preset.delete_cast_preset", return_value=True)
    def test_delete_preset(self, mock_del: MagicMock, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(self._get_group(), ["delete", "demo"])
        assert result.exit_code == 0
        assert "Deleted" in result.output

    @patch("foundry_sandbox.commands.preset.delete_cast_preset", return_value=False)
    def test_delete_nonexistent_preset(self, mock_del: MagicMock, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(self._get_group(), ["delete", "missing"])
        assert result.exit_code != 0

    def test_validate_rejects_path_traversal(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(self._get_group(), ["show", "../escape"])
        assert result.exit_code != 0
        assert "Invalid" in result.output

    def test_validate_rejects_dotfile(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(self._get_group(), ["show", ".hidden"])
        assert result.exit_code != 0

    @patch("foundry_sandbox.commands.preset.list_cast_presets", return_value=["demo"])
    def test_no_subcommand_lists_presets(self, mock_list: MagicMock, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(self._get_group(), [])
        assert result.exit_code == 0
        assert "demo" in result.output


# =========================================================================
# upgrade
# =========================================================================


class TestUpgradeCommand:

    def _get_cmd(self):
        from foundry_sandbox.commands.upgrade import upgrade
        return upgrade

    @patch("subprocess.run")
    def test_local_upgrade_runs_installer(
        self, mock_run: MagicMock, runner: click.testing.CliRunner,
        tmp_path: Path, monkeypatch,
    ) -> None:
        # Create a fake install.sh
        from foundry_sandbox.commands import upgrade as upgrade_mod
        fake_script_dir = tmp_path / "project"
        fake_script_dir.mkdir()
        install_sh = fake_script_dir / "install.sh"
        install_sh.write_text("#!/bin/bash\necho ok")

        monkeypatch.setattr(upgrade_mod, "SCRIPT_DIR", fake_script_dir)
        mock_run.return_value = MagicMock(returncode=0)

        result = runner.invoke(self._get_cmd(), ["--local"])
        assert result.exit_code == 0
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "bash" in call_args[0]

    @patch("subprocess.run")
    def test_local_upgrade_missing_script(
        self, mock_run: MagicMock, runner: click.testing.CliRunner,
        tmp_path: Path, monkeypatch,
    ) -> None:
        from foundry_sandbox.commands import upgrade as upgrade_mod
        monkeypatch.setattr(upgrade_mod, "SCRIPT_DIR", tmp_path / "empty")

        result = runner.invoke(self._get_cmd(), ["--local"])
        assert result.exit_code != 0
