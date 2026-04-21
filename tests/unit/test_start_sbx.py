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

    @patch("foundry_sandbox.commands.start._install_pip_requirements_sbx")
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


class TestLazyProvisioning:
    """Tests for lazy provisioning of migrated-but-unprovisioned sandboxes."""

    # Minimal metadata representing a migrated sandbox
    MIGRATED_METADATA = {
        "sbx_name": "test-sandbox",
        "repo_url": "https://github.com/org/repo",
        "branch": "main",
        "from_branch": "",
        "agent": "claude",
        "git_safety_enabled": False,
        "workspace_dir": "/workspace",
        "allow_pr": False,
        "copies": [],
        "template": "",
    }

    @staticmethod
    def _patch_provisioning():
        """Return a decorator that mocks all provisioning dependencies.

        Patches are applied in reverse order so that the first mock argument
        corresponds to load_sandbox_metadata (innermost decorator = first arg).
        """
        def decorator(fn):
            # Applied last → innermost decorator → first mock argument
            fn = patch("foundry_sandbox.commands.start.load_sandbox_metadata")(fn)
            fn = patch("foundry_sandbox.commands.start.sbx_check_available")(fn)
            fn = patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=False)(fn)
            fn = patch("foundry_sandbox.commands.start.sbx_run")(fn)
            fn = patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)(fn)
            fn = patch("foundry_sandbox.commands.start.ensure_bare_repo")(fn)
            fn = patch("foundry_sandbox.commands.start.create_worktree")(fn)
            fn = patch("foundry_sandbox.commands.start.sbx_create")(fn)
            fn = patch("foundry_sandbox.commands.start.ensure_foundry_template", return_value=True)(fn)
            fn = patch("foundry_sandbox.commands.start.provision_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="sha256abc"))(fn)
            fn = patch("foundry_sandbox.commands.start.is_template_stale", return_value=False)(fn)
            fn = patch("foundry_sandbox.commands.start.verify_wrapper_integrity", return_value=(True, "sha256abc"))(fn)
            # Applied first → outermost decorator → last mock argument
            fn = patch("foundry_sandbox.commands.start.patch_sandbox_metadata")(fn)
            return fn
        return decorator

    @_patch_provisioning()
    def test_provisions_migrated_sandbox(
        self, mock_meta, mock_check, mock_exists, mock_run, mock_gs,
        mock_ensure_bare, mock_create_wt, mock_sbx_create,
        mock_ensure_tpl, mock_provision, mock_stale, mock_verify, mock_patch,
    ):
        mock_meta.return_value = self.MIGRATED_METADATA
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["test-sandbox"])

        assert result.exit_code == 0, result.output
        assert "Provisioning migrated sandbox" in result.output
        assert "Provisioning complete" in result.output
        mock_ensure_bare.assert_called_once()
        mock_create_wt.assert_called_once()
        mock_sbx_create.assert_called_once()
        # Shared helper was called for provisioning
        mock_provision.assert_called_once()

    @_patch_provisioning()
    def test_reuses_existing_worktree(
        self, mock_meta, mock_check, mock_exists, mock_run, mock_gs,
        mock_ensure_bare, mock_create_wt, mock_sbx_create,
        mock_ensure_tpl, mock_provision, mock_stale, mock_verify, mock_patch,
    ):
        mock_meta.return_value = self.MIGRATED_METADATA
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["test-sandbox"])

        assert result.exit_code == 0, result.output
        # create_worktree handles existing worktrees via --ff-only pull
        mock_create_wt.assert_called_once()

    @patch("foundry_sandbox.commands.start.patch_sandbox_metadata")
    @patch("foundry_sandbox.commands.start.provision_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="sha256abc"))
    @patch("foundry_sandbox.commands.start.is_template_stale", return_value=False)
    @patch("foundry_sandbox.commands.start.verify_wrapper_integrity", return_value=(True, "sha256abc"))
    @patch("foundry_sandbox.commands.start.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_create", side_effect=RuntimeError("sbx failed"))
    @patch("foundry_sandbox.commands.start.create_worktree")
    @patch("foundry_sandbox.commands.start.ensure_bare_repo")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_failure_does_not_enable_git_safety(
        self, mock_meta, mock_check, mock_exists, mock_run, mock_gs,
        mock_ensure_bare, mock_create_wt, mock_sbx_create,
        mock_ensure_tpl, mock_verify, mock_stale, mock_provision, mock_patch,
    ):
        mock_meta.return_value = self.MIGRATED_METADATA
        runner = CliRunner()
        result = runner.invoke(start, ["test-sandbox"])

        assert result.exit_code != 0
        assert "sbx create failed" in result.output
        # provision_git_safety should never be called on sbx_create failure
        mock_provision.assert_not_called()

    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_corrupted_state_rejected(self, mock_meta, mock_check, mock_exists):
        # Metadata claims provisioned but sbx sandbox doesn't exist
        mock_meta.return_value = {
            "sbx_name": "test-sandbox",
            "git_safety_enabled": True,
        }
        runner = CliRunner()
        result = runner.invoke(start, ["test-sandbox"])

        assert result.exit_code == 1
        assert "corrupted" in result.output

    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_no_repo_url_fails(self, mock_meta, mock_check, mock_exists):
        mock_meta.return_value = {
            "sbx_name": "test-sandbox",
            "git_safety_enabled": False,
            "repo_url": "",
            "branch": "main",
        }
        runner = CliRunner()
        result = runner.invoke(start, ["test-sandbox"])

        assert result.exit_code == 1
        assert "no repo_url" in result.output

    @patch("foundry_sandbox.commands.start.patch_sandbox_metadata")
    @patch("foundry_sandbox.commands.start.is_template_stale", return_value=False)
    @patch("foundry_sandbox.commands.start.verify_wrapper_integrity", return_value=(True, "sha256abc"))
    @patch("foundry_sandbox.commands.start.provision_git_safety", return_value=ProvisioningResult(success=False, error="HMAC failed"))
    @patch("foundry_sandbox.commands.start.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_create")
    @patch("foundry_sandbox.commands.start.create_worktree")
    @patch("foundry_sandbox.commands.start.ensure_bare_repo")
    @patch("foundry_sandbox.commands.start.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.start.sbx_run")
    @patch("foundry_sandbox.commands.start.sbx_sandbox_exists", return_value=False)
    @patch("foundry_sandbox.commands.start.sbx_check_available")
    @patch("foundry_sandbox.commands.start.load_sandbox_metadata")
    def test_provision_failure_does_not_enable_git_safety(
        self, mock_meta, mock_check, mock_exists, mock_run, mock_gs,
        mock_ensure_bare, mock_create_wt, mock_sbx_create,
        mock_ensure_tpl, mock_provision, mock_verify, mock_stale, mock_patch,
    ):
        """If provision_git_safety fails, git_safety_enabled=True is never written."""
        mock_meta.return_value = self.MIGRATED_METADATA
        mock_sbx_create.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(start, ["test-sandbox"])

        assert result.exit_code != 0
        assert "provisioning failed" in result.output
        # git_safety_enabled=True should never be written on failure
        enabled_calls = [c for c in mock_patch.call_args_list
                        if c[1].get("git_safety_enabled") is True]
        assert len(enabled_calls) == 0
