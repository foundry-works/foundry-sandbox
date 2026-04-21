"""Tests for the rewritten cast new command (sbx backend)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.new import new
from foundry_sandbox.commands.new_sbx import new_sbx_setup, rollback_new_sbx


class TestNewSbxSetup:
    @patch("foundry_sandbox.commands.new_sbx.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_sbx.inject_git_wrapper")
    @patch("foundry_sandbox.commands.new_sbx.register_sandbox_with_git_safety")
    @patch("foundry_sandbox.commands.new_sbx.write_hmac_secret_for_server")
    @patch("foundry_sandbox.commands.new_sbx.write_hmac_secret_to_worktree")
    @patch("foundry_sandbox.commands.new_sbx.generate_hmac_secret", return_value="a" * 64)
    @patch("foundry_sandbox.commands.new_sbx.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_sbx.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_sbx.sbx_create")
    @patch("foundry_sandbox.commands.new_sbx.create_worktree")
    @patch("foundry_sandbox.commands.new_sbx.ensure_bare_repo")
    @patch("foundry_sandbox.commands.new_sbx.sbx_check_available")
    def test_full_setup(
        self, mock_check, mock_bare, mock_worktree, mock_create, mock_ensure,
        mock_gs_running, mock_hmac, mock_write_hmac_wt, mock_write_hmac_srv,
        mock_register, mock_inject, mock_metadata, tmp_path,
    ):
        from pathlib import Path
        mock_create.return_value = MagicMock(returncode=0)
        # Create a mock worktree path that returns True for is_dir
        wt = MagicMock(spec=Path)
        wt.is_dir.return_value = True
        wt.__str__ = lambda s: str(tmp_path / "worktree")
        new_sbx_setup(
            repo_url="https://github.com/org/repo",
            bare_path=str(tmp_path / "bare"),
            worktree_path=wt,
            branch="feature-x",
            from_branch="main",
            name="test-sandbox",
            agent="claude",
            claude_config_path=tmp_path / "config",
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
        assert call_args[1]["branch"] == "feature-x"
        mock_register.assert_called_once()
        mock_inject.assert_called_once()
        mock_metadata.assert_called_once()

    @patch("foundry_sandbox.commands.new_sbx.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_sbx.sbx_create", side_effect=Exception("sbx failed"))
    @patch("foundry_sandbox.commands.new_sbx.create_worktree")
    @patch("foundry_sandbox.commands.new_sbx.ensure_bare_repo")
    @patch("foundry_sandbox.commands.new_sbx.sbx_check_available")
    def test_sbx_create_failure(
        self, mock_check, mock_bare, mock_worktree, mock_create, mock_ensure, tmp_path,
    ):
        from foundry_sandbox.commands.new_sbx import SetupError
        from pathlib import Path
        wt = MagicMock(spec=Path)
        wt.is_dir.return_value = True
        wt.__str__ = lambda s: str(tmp_path / "worktree")
        with pytest.raises(SetupError, match="sbx create failed"):
            new_sbx_setup(
                repo_url="https://github.com/org/repo",
                bare_path=str(tmp_path / "bare"),
                worktree_path=wt,
                branch="feature-x",
                from_branch="main",
                name="test-sandbox",
                agent="claude",
                claude_config_path=tmp_path / "config",
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
        from pathlib import Path
        wt = MagicMock(spec=Path)
        wt.is_dir.return_value = True
        wt.__str__ = lambda s: str(tmp_path / "worktree")
        return dict(
            repo_url="https://github.com/org/repo",
            bare_path=str(tmp_path / "bare"),
            worktree_path=wt,
            branch="feature-x",
            from_branch="main",
            name="test-sandbox",
            agent="claude",
            claude_config_path=tmp_path / "config",
            copies=[],
            allow_pr=False,
            pip_requirements="",
            with_opencode=False,
            with_zai=False,
            wd="",
        )

    @patch("foundry_sandbox.commands.new_sbx.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_sbx.inject_git_wrapper")
    @patch("foundry_sandbox.commands.new_sbx.register_sandbox_with_git_safety")
    @patch("foundry_sandbox.commands.new_sbx.write_hmac_secret_for_server")
    @patch("foundry_sandbox.commands.new_sbx.write_hmac_secret_to_worktree")
    @patch("foundry_sandbox.commands.new_sbx.generate_hmac_secret", return_value="a" * 64)
    @patch("foundry_sandbox.commands.new_sbx.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_sbx.sbx_template_ls")
    @patch("foundry_sandbox.commands.new_sbx.ensure_foundry_template", return_value=True)
    @patch("foundry_sandbox.commands.new_sbx.sbx_create")
    @patch("foundry_sandbox.commands.new_sbx.create_worktree")
    @patch("foundry_sandbox.commands.new_sbx.ensure_bare_repo")
    @patch("foundry_sandbox.commands.new_sbx.sbx_check_available")
    def test_builtin_template_calls_ensure(
        self, mock_check, mock_bare, mock_worktree, mock_create,
        mock_ensure, mock_ls, mock_gs_running, mock_hmac,
        mock_write_hmac_wt, mock_write_hmac_srv, mock_register,
        mock_inject, mock_metadata, tmp_path,
    ):
        """FOUNDRY_TEMPLATE_TAG goes through ensure_foundry_template()."""
        mock_create.return_value = MagicMock(returncode=0)
        from foundry_sandbox.git_safety import FOUNDRY_TEMPLATE_TAG

        new_sbx_setup(template=FOUNDRY_TEMPLATE_TAG, **self._base_kwargs(tmp_path))

        mock_ensure.assert_called_once()
        # Custom-template existence check must NOT run for the built-in tag.
        mock_ls.assert_not_called()

    @patch("foundry_sandbox.commands.new_sbx.write_sandbox_metadata")
    @patch("foundry_sandbox.commands.new_sbx.inject_git_wrapper")
    @patch("foundry_sandbox.commands.new_sbx.register_sandbox_with_git_safety")
    @patch("foundry_sandbox.commands.new_sbx.write_hmac_secret_for_server")
    @patch("foundry_sandbox.commands.new_sbx.write_hmac_secret_to_worktree")
    @patch("foundry_sandbox.commands.new_sbx.generate_hmac_secret", return_value="a" * 64)
    @patch("foundry_sandbox.commands.new_sbx.git_safety_server_is_running", return_value=True)
    @patch("foundry_sandbox.commands.new_sbx.ensure_foundry_template")
    @patch(
        "foundry_sandbox.commands.new_sbx.sbx_template_ls",
        return_value=["preset-mysetup:latest"],
    )
    @patch("foundry_sandbox.commands.new_sbx.sbx_create")
    @patch("foundry_sandbox.commands.new_sbx.create_worktree")
    @patch("foundry_sandbox.commands.new_sbx.ensure_bare_repo")
    @patch("foundry_sandbox.commands.new_sbx.sbx_check_available")
    def test_custom_template_skips_ensure(
        self, mock_check, mock_bare, mock_worktree, mock_create,
        mock_ls, mock_ensure, mock_gs_running, mock_hmac,
        mock_write_hmac_wt, mock_write_hmac_srv, mock_register,
        mock_inject, mock_metadata, tmp_path,
    ):
        """Custom/managed tags do not call ensure_foundry_template()."""
        mock_create.return_value = MagicMock(returncode=0)

        new_sbx_setup(template="preset-mysetup:latest", **self._base_kwargs(tmp_path))

        mock_ensure.assert_not_called()
        mock_ls.assert_called_once()

    @patch("foundry_sandbox.commands.new_sbx.ensure_foundry_template")
    @patch("foundry_sandbox.commands.new_sbx.sbx_template_ls", return_value=[])
    @patch("foundry_sandbox.commands.new_sbx.sbx_create")
    @patch("foundry_sandbox.commands.new_sbx.create_worktree")
    @patch("foundry_sandbox.commands.new_sbx.ensure_bare_repo")
    @patch("foundry_sandbox.commands.new_sbx.sbx_check_available")
    def test_missing_custom_template_raises_setup_error(
        self, mock_check, mock_bare, mock_worktree, mock_create,
        mock_ls, mock_ensure, tmp_path,
    ):
        """Missing custom/managed template surfaces as SetupError, not opaque sbx failure."""
        from foundry_sandbox.commands.new_sbx import SetupError

        with pytest.raises(SetupError, match="not found in sbx"):
            new_sbx_setup(
                template="preset-missing:latest", **self._base_kwargs(tmp_path)
            )

        mock_ensure.assert_not_called()
        # sbx_create must never be called if the template is missing.
        mock_create.assert_not_called()


class TestGitSafetyFailClosed:
    """cast new must abort when git safety is unavailable (fail-closed)."""

    def _base_kwargs(self, tmp_path):
        from pathlib import Path
        wt = MagicMock(spec=Path)
        wt.is_dir.return_value = True
        wt.__str__ = lambda s: str(tmp_path / "worktree")
        return dict(
            repo_url="https://github.com/org/repo",
            bare_path=str(tmp_path / "bare"),
            worktree_path=wt,
            branch="feature-x",
            from_branch="main",
            name="test-sandbox",
            agent="claude",
            claude_config_path=tmp_path / "config",
            copies=[],
            allow_pr=False,
            pip_requirements="",
            with_opencode=False,
            with_zai=False,
            wd="",
        )

    @patch("foundry_sandbox.commands.new_sbx.sbx_create")
    @patch("foundry_sandbox.commands.new_sbx.create_worktree")
    @patch("foundry_sandbox.commands.new_sbx.ensure_bare_repo")
    @patch("foundry_sandbox.commands.new_sbx.sbx_check_available")
    @patch("foundry_sandbox.commands.new_sbx.git_safety_server_is_running", return_value=False)
    @patch("foundry_sandbox.commands.new_sbx.git_safety_server_start", side_effect=OSError("not found"))
    def test_fails_when_git_safety_not_installed(
        self, mock_gs_start, mock_gs_running, mock_check, mock_bare, mock_worktree, mock_create, tmp_path,
    ):
        from foundry_sandbox.commands.new_sbx import SetupError
        with pytest.raises(SetupError, match="not installed"):
            new_sbx_setup(**self._base_kwargs(tmp_path))

    @patch("foundry_sandbox.commands.new_sbx.sbx_create")
    @patch("foundry_sandbox.commands.new_sbx.create_worktree")
    @patch("foundry_sandbox.commands.new_sbx.ensure_bare_repo")
    @patch("foundry_sandbox.commands.new_sbx.sbx_check_available")
    @patch("foundry_sandbox.commands.new_sbx.git_safety_server_is_running", return_value=False)
    @patch("foundry_sandbox.commands.new_sbx.git_safety_server_start")
    def test_fails_when_server_unhealthy_after_start(
        self, mock_gs_start, mock_gs_running, mock_check, mock_bare, mock_worktree, mock_create, tmp_path,
    ):
        from foundry_sandbox.commands.new_sbx import SetupError
        # Server starts without error but is_running still returns False
        mock_gs_start.return_value = MagicMock(returncode=0)
        with pytest.raises(SetupError, match="did not become healthy"):
            new_sbx_setup(**self._base_kwargs(tmp_path))
    @patch("foundry_sandbox.commands.new_sbx.shutil.rmtree")
    @patch("foundry_sandbox.commands.new_sbx.sbx_rm")
    def test_rollback(self, mock_rm, mock_rmtree):
        mock_worktree = MagicMock()
        mock_worktree.is_dir.return_value = True
        mock_config = MagicMock()
        mock_config.is_dir.return_value = True

        rollback_new_sbx(mock_worktree, mock_config, "test-sandbox")

        mock_rm.assert_called_once_with("test-sandbox")


class TestNewCommand:
    @patch("foundry_sandbox.commands.new.new_sbx_setup")
    @patch("foundry_sandbox.commands.new.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.new._validate_preconditions")
    @patch("foundry_sandbox.commands.new._resolve_repo_input")
    @patch("foundry_sandbox.commands.new.validate_sandbox_name")
    @patch("foundry_sandbox.commands.new.repo_url_to_bare_path")
    def test_basic_new(
        self, mock_bare, mock_validate_name, mock_resolve, mock_precond,
        mock_paths, mock_setup,
    ):
        mock_bare.return_value = "/tmp/repos/org-repo"
        mock_validate_name.return_value = (True, "")
        mock_resolve.return_value = ("https://github.com/org/repo", None, "org/repo", "main")
        mock_precond.return_value = None
        mock_path = MagicMock()
        mock_path.worktree_path = MagicMock()
        mock_path.claude_config_path = MagicMock()
        mock_path.claude_config_path.__truediv__ = MagicMock()
        mock_paths.return_value = mock_path

        runner = CliRunner()
        with patch("foundry_sandbox.commands.new.os.makedirs"):
            runner.invoke(new, ["org/repo", "feature-x"])


import pytest
