"""Tests for the rewritten cast new command (sbx backend)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from foundry_sandbox.commands.new import new
from foundry_sandbox.commands.new_setup import new_sbx_setup, rollback_new_sbx
from foundry_sandbox.git_safety import ProvisioningResult


class TestNewSbxSetup:
    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.provision_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="abc123"))
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_full_setup(
        self, mock_check, mock_create, mock_ensure,
        mock_gs_running, mock_provision, mock_metadata, tmp_path,
    ):
        mock_create.return_value = MagicMock(returncode=0, stdout="")
        repo_root = str(tmp_path / "repo")
        host_worktree_path = new_sbx_setup(
            repo_url="https://github.com/org/repo",
            repo_root=repo_root,
            branch="feature-x",
            from_branch="main",
            name="test-sandbox",
            agent="claude",
            sandbox_config_path=tmp_path / "config",
            copies=[],
            allow_pr=False,
            pip_requirements="",
            with_opencode=False,
            with_zai=False,
            wd="",
        )
        mock_create.assert_called_once()
        call_args = mock_create.call_args
        assert call_args[0][0] == "test-sandbox"
        assert call_args[0][1] == "claude"
        assert call_args[0][2] == repo_root
        assert call_args[1]["branch"] == "feature-x"
        assert host_worktree_path == f"{repo_root}/.sbx/test-sandbox-worktrees/feature-x"
        # Shared helper was called
        mock_provision.assert_called_once()
        mock_metadata.assert_called_once()

    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.sbx_create", side_effect=Exception("sbx failed"))
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_sbx_create_failure(
        self, mock_check, mock_create, mock_ensure, mock_gs_running, tmp_path,
    ):

        repo_root = str(tmp_path / "repo")
        with pytest.raises(RuntimeError, match="sbx create failed"):
            new_sbx_setup(
                repo_url="https://github.com/org/repo",
                repo_root=repo_root,
                branch="feature-x",
                from_branch="main",
                name="test-sandbox",
                agent="claude",
                sandbox_config_path=tmp_path / "config",
                copies=[],
                allow_pr=False,
                pip_requirements="",
                with_opencode=False,
                with_zai=False,
                wd="",
            )

    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.provision_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="abc123"))
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_host_worktree_path_stored_in_metadata(
        self, mock_check, mock_create, mock_ensure,
        mock_gs_running, mock_provision, mock_metadata, tmp_path,
    ):
        mock_create.return_value = MagicMock(returncode=0, stdout="")
        repo_root = str(tmp_path / "myrepo")
        new_sbx_setup(
            repo_url="https://github.com/org/repo",
            repo_root=repo_root,
            branch="feature-x",
            from_branch="main",
            name="test-sandbox",
            agent="claude",
            sandbox_config_path=tmp_path / "config",
            copies=[],
            allow_pr=False,
            pip_requirements="",
            with_opencode=False,
            with_zai=False,
            wd="",
        )
        mock_metadata.assert_called_once()
        call_metadata = mock_metadata.call_args[0][1]
        assert call_metadata.host_worktree_path == f"{repo_root}/.sbx/test-sandbox-worktrees/feature-x"

    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.provision_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="abc123"))
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_provision_git_safety_uses_host_worktree_path(
        self, mock_check, mock_create, mock_ensure,
        mock_gs_running, mock_provision, mock_metadata, tmp_path,
    ):
        mock_create.return_value = MagicMock(returncode=0, stdout="")
        repo_root = str(tmp_path / "repo")
        new_sbx_setup(
            repo_url="https://github.com/org/repo",
            repo_root=repo_root,
            branch="feature-x",
            from_branch="main",
            name="test-sandbox",
            agent="claude",
            sandbox_config_path=tmp_path / "config",
            copies=[],
            allow_pr=False,
            pip_requirements="",
            with_opencode=False,
            with_zai=False,
            wd="",
        )
        mock_provision.assert_called_once()
        prov_kwargs = mock_provision.call_args[1]
        assert prov_kwargs["repo_root"] == f"{repo_root}/.sbx/test-sandbox-worktrees/feature-x"


class TestWorkspaceInfoMismatch:
    """Fail-closed when sbx reports a different worktree path than expected."""

    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.provision_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="abc123"))
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_mismatch_uses_parsed_path(
        self, mock_check, mock_create, mock_ensure,
        mock_gs_running, mock_provision, mock_metadata, tmp_path,
    ):
        # sbx reports a different worktree path than our deterministic formula.
        # The parsed stdout is ground truth; mismatch is a warning, not an error.
        mock_create.return_value = MagicMock(
            returncode=0,
            stdout="Worktree: /unexpected/path\nBranch: feature-x",
        )
        repo_root = str(tmp_path / "repo")
        result = new_sbx_setup(
            repo_url="https://github.com/org/repo",
            repo_root=repo_root,
            branch="feature-x",
            from_branch="main",
            name="test-sandbox",
            agent="claude",
            sandbox_config_path=tmp_path / "config",
            copies=[],
            allow_pr=False,
            pip_requirements="",
            with_opencode=False,
            with_zai=False,
            wd="",
        )
        assert result == "/unexpected/path"

    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.provision_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="abc123"))
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_matching_stdout_succeeds(
        self, mock_check, mock_create, mock_ensure,
        mock_gs_running, mock_provision, mock_metadata, tmp_path,
    ):
        repo_root = str(tmp_path / "repo")
        expected = f"{repo_root}/.sbx/test-sandbox-worktrees/feature-x"
        mock_create.return_value = MagicMock(
            returncode=0,
            stdout=f"Worktree: {expected}\nBranch: feature-x",
        )
        # Should not raise
        new_sbx_setup(
            repo_url="https://github.com/org/repo",
            repo_root=repo_root,
            branch="feature-x",
            from_branch="main",
            name="test-sandbox",
            agent="claude",
            sandbox_config_path=tmp_path / "config",
            copies=[],
            allow_pr=False,
            pip_requirements="",
            with_opencode=False,
            with_zai=False,
            wd="",
        )


class TestTemplateValidation:
    """Custom/managed templates must exist; built-in falls back on build failure."""

    def _base_kwargs(self, tmp_path):
        repo_root = str(tmp_path / "repo")
        return dict(
            repo_url="https://github.com/org/repo",
            repo_root=repo_root,
            branch="feature-x",
            from_branch="main",
            name="test-sandbox",
            agent="claude",
            sandbox_config_path=tmp_path / "config",
            copies=[],
            allow_pr=False,
            pip_requirements="",
            with_opencode=False,
            with_zai=False,
            wd="",
        )

    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.provision_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="abc123"))
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.sbx_template_ls")
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_builtin_template_calls_ensure(
        self, mock_check, mock_create,
        mock_ensure, mock_ls, mock_gs_running, mock_provision,
        mock_metadata, tmp_path,
    ):
        """FOUNDRY_TEMPLATE_TAG goes through ensure_foundry_template()."""
        mock_create.return_value = MagicMock(returncode=0, stdout="")
        from foundry_sandbox.git_safety import FOUNDRY_TEMPLATE_TAG

        new_sbx_setup(template=FOUNDRY_TEMPLATE_TAG, **self._base_kwargs(tmp_path))

        mock_ensure.assert_called_once()
        # Custom-template existence check must NOT run for the built-in tag.
        mock_ls.assert_not_called()

    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.provision_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="abc123"))
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template")
    @patch(
        "foundry_sandbox.commands.new_setup.sbx_template_ls",
        return_value=["preset-mysetup:latest"],
    )
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_custom_template_skips_ensure(
        self, mock_check, mock_create,
        mock_ls, mock_ensure, mock_gs_running, mock_provision,
        mock_metadata, tmp_path,
    ):
        """Custom/managed tags do not call ensure_foundry_template()."""
        mock_create.return_value = MagicMock(returncode=0, stdout="")

        new_sbx_setup(template="preset-mysetup:latest", **self._base_kwargs(tmp_path))

        mock_ensure.assert_not_called()
        mock_ls.assert_called_once()

    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template")
    @patch("foundry_sandbox.commands.new_setup.sbx_template_ls", return_value=[])
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_missing_custom_template_raises_setup_error(
        self, mock_check, mock_create,
        mock_ls, mock_ensure, mock_gs_running, tmp_path,
    ):
        """Missing custom/managed template surfaces as RuntimeError, not opaque sbx failure."""


        with pytest.raises(RuntimeError, match="not found in sbx"):
            new_sbx_setup(
                template="preset-missing:latest", **self._base_kwargs(tmp_path)
            )

        mock_ensure.assert_not_called()
        # sbx_create must never be called if the template is missing.
        mock_create.assert_not_called()


class TestGitSafetyFailClosed:
    """cast new must abort when git safety is unavailable (fail-closed)."""

    def _base_kwargs(self, tmp_path):
        repo_root = str(tmp_path / "repo")
        return dict(
            repo_url="https://github.com/org/repo",
            repo_root=repo_root,
            branch="feature-x",
            from_branch="main",
            name="test-sandbox",
            agent="claude",
            sandbox_config_path=tmp_path / "config",
            copies=[],
            allow_pr=False,
            pip_requirements="",
            with_opencode=False,
            with_zai=False,
            wd="",
        )

    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=False)
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_start", side_effect=OSError("not found"))
    def test_fails_when_git_safety_not_installed(
        self, mock_gs_start, mock_gs_running, mock_check, mock_create, mock_metadata, tmp_path,
    ):

        with pytest.raises(RuntimeError, match="not installed"):
            new_sbx_setup(**self._base_kwargs(tmp_path))

    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=False)
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_start")
    def test_fails_when_server_unhealthy_after_start(
        self, mock_gs_start, mock_gs_running, mock_check, mock_create, mock_metadata, tmp_path,
    ):

        # Server starts without error but is_running still returns False
        mock_gs_start.return_value = MagicMock(returncode=0)
        with pytest.raises(RuntimeError, match="did not become healthy"):
            new_sbx_setup(**self._base_kwargs(tmp_path))

    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.provision_git_safety", return_value=ProvisioningResult(success=False, error="Wrapper injection failed: OSError"))
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_fails_closed_on_provisioning_failure(
        self, mock_check, mock_create,
        mock_ensure, mock_gs_running, mock_provision, mock_metadata, tmp_path,
    ):

        mock_create.return_value = MagicMock(returncode=0, stdout="")
        with pytest.raises(RuntimeError, match="provisioning failed"):
            new_sbx_setup(**self._base_kwargs(tmp_path))

    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.provision_git_safety", return_value=ProvisioningResult(success=False, error="Checksum computation failed: FileNotFoundError"))
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_fails_closed_on_checksum_failure(
        self, mock_check, mock_create,
        mock_ensure, mock_gs_running, mock_provision, mock_metadata, tmp_path,
    ):

        mock_create.return_value = MagicMock(returncode=0, stdout="")
        with pytest.raises(RuntimeError, match="provisioning failed"):
            new_sbx_setup(**self._base_kwargs(tmp_path))

    @patch(
        "foundry_sandbox.foundry_config.resolve_foundry_config",
        side_effect=ValueError("Invalid foundry config"),
    )
    @patch("foundry_sandbox.commands.new_setup.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_setup.provision_git_safety", return_value=ProvisioningResult(success=True, wrapper_checksum="abc123"))
    @patch("foundry_sandbox.commands.new_setup.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_setup.sbx_create")
    @patch("foundry_sandbox.commands.new_setup.sbx_check_available")
    def test_fails_closed_on_invalid_foundry_config(
        self, mock_check, mock_create,
        mock_ensure, mock_gs_running, mock_provision, mock_metadata,
        mock_resolve, tmp_path,
    ):

        mock_create.return_value = MagicMock(returncode=0, stdout="")
        with pytest.raises(RuntimeError, match="Foundry.yaml artifact apply failed"):
            new_sbx_setup(**self._base_kwargs(tmp_path))

    @patch("foundry_sandbox.commands.new_setup.sbx_rm")
    def test_rollback(self, mock_rm, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        rollback_new_sbx(config_dir, "test-sandbox")

        mock_rm.assert_called_once_with("test-sandbox")
        # Config directory should be cleaned up
        assert not config_dir.exists()


class TestSbxWorkspaceInfo:
    """Tests for sbx_get_workspace_info and sbx_worktree_path helpers."""

    def test_parse_worktree_and_branch(self):
        from foundry_sandbox.sbx import sbx_get_workspace_info
        stdout = "Worktree: /home/user/repo/.sbx/test-worktrees/feature\nBranch: feature\n"
        info = sbx_get_workspace_info(stdout)
        assert info["worktree"] == "/home/user/repo/.sbx/test-worktrees/feature"
        assert info["branch"] == "feature"

    def test_parse_empty_stdout(self):
        from foundry_sandbox.sbx import sbx_get_workspace_info
        info = sbx_get_workspace_info("")
        assert info["worktree"] == ""
        assert info["branch"] == ""

    def test_parse_partial_stdout(self):
        from foundry_sandbox.sbx import sbx_get_workspace_info
        info = sbx_get_workspace_info("Branch: main\n")
        assert info["worktree"] == ""
        assert info["branch"] == "main"

    def test_deterministic_worktree_path(self):
        from foundry_sandbox.sbx import sbx_worktree_path
        path = sbx_worktree_path("/home/user/repo", "mysandbox", "feature-x")
        assert path == "/home/user/repo/.sbx/mysandbox-worktrees/feature-x"


class TestNewCommand:
    @patch("foundry_sandbox.commands.new.new_sbx_setup")
    @patch("foundry_sandbox.commands.new.path_sandbox_config")
    @patch("foundry_sandbox.commands.new._validate_preconditions")
    @patch("foundry_sandbox.commands.new._resolve_repo_input")
    @patch("foundry_sandbox.commands.new.validate_sandbox_name")
    def test_basic_new(
        self, mock_validate_name, mock_resolve, mock_precond,
        mock_config_path, mock_setup,
    ):
        mock_validate_name.return_value = (True, "")
        mock_resolve.return_value = ("https://github.com/org/repo", "/home/user/repo", "org/repo", "main")
        mock_precond.return_value = None
        mock_path = MagicMock()
        mock_path.__truediv__ = MagicMock()
        mock_config_path.return_value = mock_path
        mock_setup.return_value = "/home/user/repo/.sbx/test-worktrees/feature-x"

        runner = CliRunner()
        with patch("foundry_sandbox.commands.new.os.makedirs"):
            runner.invoke(new, ["org/repo", "feature-x"])
