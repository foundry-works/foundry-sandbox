"""Tests for the rewritten cast start command (sbx backend)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.start import start
from foundry_sandbox.git_safety import ProvisioningResult


class TestStartCommand:
    @patch("foundry_sandbox.commands.start.is_template_stale", return_value=False)
    @patch("foundry_sandbox.commands.start.verify_wrapper_integrity", return_value=(True, "abc"))
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_start_success(self, mock_meta, mock_check, mock_gs_running, mock_run, mock_exists, mock_verify, mock_stale):
        mock_meta.return_value = {"sbx_name": "test-1"}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        assert result.exit_code == 0
        assert "started" in result.output
        mock_run.assert_called_once_with("my-sandbox")

    @patch("foundry_sandbox.commands.start.is_template_stale", return_value=False)
    @patch("foundry_sandbox.commands.start.verify_wrapper_integrity", return_value=(True, "abc"))
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", side_effect=[False, True])
    @patch("foundry_sandbox.commands.start.git_safety_server_start")
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_starts_git_safety_server(self, mock_meta, mock_check, mock_gs_start, mock_gs_running, mock_run, mock_exists, mock_verify, mock_stale):
        mock_meta.return_value = {}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        assert result.exit_code == 0
        mock_gs_start.assert_called_once()

    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=False)
    @patch("foundry_sandbox.commands.start.git_safety_server_start", side_effect=OSError("not found"))
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_fails_closed_when_git_safety_not_installed(self, mock_meta, mock_check, mock_gs_start, mock_gs_running, mock_exists):
        mock_meta.return_value = {}
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        assert result.exit_code == 1
        assert "not installed" in result.output

    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=False)
    @patch("foundry_sandbox.commands.start.git_safety_server_start")
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_fails_closed_when_server_unhealthy_after_start(self, mock_meta, mock_check, mock_gs_start, mock_gs_running, mock_exists):
        mock_meta.return_value = {}
        # Server starts without error but is_running still returns False
        mock_gs_start.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        assert result.exit_code == 1
        assert "did not become healthy" in result.output

    @patch("foundry_sandbox.commands.start.repair_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="newhash"))
    @patch("foundry_sandbox.commands.start.verify_wrapper_integrity", return_value=(False, "wrong"))
    @patch("foundry_sandbox.commands.start.is_template_stale", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_reinjects_wrapper(self, mock_meta, mock_check, mock_gs, mock_run, mock_exists, mock_stale, mock_verify, mock_repair):
        mock_meta.return_value = {"sbx_name": "test-1", "workspace_dir": "/workspace"}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        assert result.exit_code == 0
        mock_repair.assert_called_once_with(
            "my-sandbox",
            sandbox_id="test-1",
            workspace_dir="/workspace",
            expected_checksum="",
        )

    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    def test_sandbox_not_found(self, mock_check, mock_exists):
        runner = CliRunner()
        result = runner.invoke(start, ["nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output

    @patch("foundry_sandbox.commands.start.install_pip_requirements")
    @patch("foundry_sandbox.commands.start.is_template_stale", return_value=False)
    @patch("foundry_sandbox.commands.start.verify_wrapper_integrity", return_value=(True, "abc"))
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_installs_pip_requirements(self, mock_meta, mock_check, mock_gs, mock_run, mock_exists, mock_verify, mock_stale, mock_pip):
        mock_meta.return_value = {"pip_requirements": "requirements.txt"}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        assert result.exit_code == 0
        mock_pip.assert_called_once_with("my-sandbox", "requirements.txt")

    @patch("foundry_sandbox.commands.start.is_template_stale", return_value=False)
    @patch("foundry_sandbox.commands.start.verify_wrapper_integrity", return_value=(True, "abc"))
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    @patch("foundry_sandbox.watchdog.start_watchdog")
    def test_watchdog_flag(self, mock_start_wd, mock_meta, mock_check, mock_gs, mock_run, mock_exists, mock_verify, mock_stale):
        mock_meta.return_value = {"sbx_name": "test-1"}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox", "--watchdog"])
        assert result.exit_code == 0
        mock_start_wd.assert_called_once()
        assert "watchdog" in result.output

    @patch("foundry_sandbox.commands.start.repair_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="newhash"))
    @patch("foundry_sandbox.commands.start.verify_wrapper_integrity", side_effect=FileNotFoundError("missing"))
    @patch("foundry_sandbox.commands.start.is_template_stale", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_file_not_found_triggers_reinject(
        self, mock_meta, mock_check, mock_gs, mock_run, mock_exists,
        mock_stale, mock_verify, mock_repair,
    ):
        """FileNotFoundError triggers re-injection attempt via repair_git_safety."""
        mock_meta.return_value = {"sbx_name": "test-1", "workspace_dir": "/workspace"}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        # Should have attempted repair
        mock_repair.assert_called_once()
        assert result.exit_code == 0

    @patch("foundry_sandbox.commands.start.patch_sandbox_metadata")
    @patch("foundry_sandbox.commands.start.repair_git_safety", return_value=ProvisioningResult(success=False, error="broken"))
    @patch("foundry_sandbox.commands.start.verify_wrapper_integrity", side_effect=FileNotFoundError("missing"))
    @patch("foundry_sandbox.commands.start.is_template_stale", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_reinject_failure_downgrades_metadata(
        self, mock_meta, mock_check, mock_gs, mock_run, mock_exists,
        mock_stale, mock_verify, mock_repair, mock_patch,
    ):
        """Re-injection failure writes git_safety_enabled=False to metadata."""
        mock_meta.return_value = {"sbx_name": "test-1", "workspace_dir": "/workspace"}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        # Should downgrade metadata
        downgrade_call = mock_patch.call_args_list[-1]
        assert downgrade_call[1].get("git_safety_enabled") is False
        assert "re-injection failed" in result.output

    @patch("foundry_sandbox.commands.start.repair_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="newhash"))
    @patch("foundry_sandbox.commands.start.verify_wrapper_integrity", return_value=(True, "abc"))
    @patch("foundry_sandbox.commands.start.is_template_stale", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_stale_template_forces_reinjection(self, mock_meta, mock_check, mock_gs, mock_run, mock_exists, mock_stale, mock_verify, mock_repair):
        """Stale template forces re-injection even when wrapper integrity is OK."""
        mock_meta.return_value = {"sbx_name": "test-1", "workspace_dir": "/workspace"}
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["my-sandbox"])
        assert result.exit_code == 0
        mock_repair.assert_called_once()


class TestMissingSbxSandbox:
    """Tests for the start command when sbx sandbox doesn't exist."""

    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_metadata_but_no_sbx_rejected(self, mock_meta, mock_check, mock_exists):
        """Metadata exists but no sbx sandbox — error with destroy-and-recreate hint."""
        mock_meta.return_value = {
            "sbx_name": "test-sandbox",
            "git_safety_enabled": False,
            "repo_url": "https://github.com/org/repo",
        }
        runner = CliRunner()
        result = runner.invoke(start, ["test-sandbox"])

        assert result.exit_code == 1
        assert "no sbx sandbox" in result.output
        assert "destroy" in result.output.lower()

    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_provisioned_but_missing_rejected(self, mock_meta, mock_check, mock_exists):
        """Metadata claims provisioned but sbx sandbox is missing."""
        mock_meta.return_value = {
            "sbx_name": "test-sandbox",
            "git_safety_enabled": True,
        }
        runner = CliRunner()
        result = runner.invoke(start, ["test-sandbox"])

        assert result.exit_code == 1
        assert "no sbx sandbox" in result.output

    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_not_found_no_metadata(self, mock_meta, mock_check, mock_exists):
        """No metadata, no sbx sandbox — simple not-found error."""
        mock_meta.return_value = None
        runner = CliRunner()
        result = runner.invoke(start, ["test-sandbox"])

        assert result.exit_code == 1
        assert "not found" in result.output
