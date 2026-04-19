"""Tests for the rewritten cast destroy command (sbx backend)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.destroy import destroy, destroy_impl


class TestDestroyImpl:
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.unregister_sandbox_from_git_safety")
    @patch("foundry_sandbox.commands.destroy.sbx_rm")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_full_destroy(
        self, mock_validate, mock_paths, mock_rm, mock_unregister,
        mock_metadata, mock_worktree, mock_branch,
    ):
        mock_validate.return_value = (True, "")
        mock_path = MagicMock()
        mock_path.worktree_path = MagicMock()
        mock_path.worktree_path.is_dir.return_value = True
        mock_path.claude_config_path = MagicMock()
        mock_path.claude_config_path.is_dir.return_value = True
        mock_paths.return_value = mock_path
        mock_metadata.return_value = {"branch": "feature-x", "repo_url": "https://github.com/org/repo"}

        destroy_impl("test-sandbox")

        mock_rm.assert_called_once_with("test-sandbox")
        mock_unregister.assert_called_once_with("test-sandbox")
        mock_worktree.assert_called_once()
        mock_branch.assert_called_once()

    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.unregister_sandbox_from_git_safety")
    @patch("foundry_sandbox.commands.destroy.sbx_rm")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_sbx_rm_failure_best_effort(
        self, mock_validate, mock_paths, mock_rm, mock_unregister, mock_metadata,
    ):
        mock_validate.return_value = (True, "")
        mock_path = MagicMock()
        mock_path.worktree_path = MagicMock()
        mock_path.worktree_path.is_dir.return_value = False
        mock_path.claude_config_path = MagicMock()
        mock_path.claude_config_path.is_dir.return_value = False
        mock_paths.return_value = mock_path
        mock_rm.side_effect = Exception("sbx rm failed")
        mock_metadata.return_value = None

        # Should not raise in best_effort mode
        destroy_impl("test-sandbox")

    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.unregister_sandbox_from_git_safety")
    @patch("foundry_sandbox.commands.destroy.sbx_rm")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_invalid_name_raises(
        self, mock_validate, mock_paths, mock_rm, mock_unregister, mock_metadata,
    ):
        mock_validate.return_value = (False, "Invalid")
        try:
            destroy_impl("bad/name")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Invalid" in str(e)

    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.unregister_sandbox_from_git_safety")
    @patch("foundry_sandbox.commands.destroy.sbx_rm")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_keep_worktree(
        self, mock_validate, mock_paths, mock_rm, mock_unregister,
        mock_metadata, mock_worktree, mock_branch,
    ):
        mock_validate.return_value = (True, "")
        mock_path = MagicMock()
        mock_path.worktree_path = MagicMock()
        mock_path.worktree_path.is_dir.return_value = True
        mock_path.claude_config_path = MagicMock()
        mock_path.claude_config_path.is_dir.return_value = True
        mock_paths.return_value = mock_path
        mock_metadata.return_value = None

        destroy_impl("test-sandbox", keep_worktree=True)

        # Should NOT remove worktree or config
        mock_worktree.assert_not_called()


class TestDestroyCommand:
    @patch("foundry_sandbox.commands.destroy.destroy_impl")
    @patch("foundry_sandbox.commands.destroy.sbx_check_available")
    def test_force_skips_confirmation(self, mock_check, mock_impl):
        runner = CliRunner()
        result = runner.invoke(destroy, ["my-sandbox", "--force"])
        assert result.exit_code == 0
        assert "destroyed" in result.output
        mock_impl.assert_called_once()

    @patch("foundry_sandbox.commands.destroy.destroy_impl")
    @patch("foundry_sandbox.commands.destroy.sbx_check_available")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_confirmation_yes(self, mock_validate, mock_paths, mock_check, mock_impl):
        mock_validate.return_value = (True, "")
        mock_path = MagicMock()
        mock_path.worktree_path = MagicMock()
        mock_path.claude_config_path = MagicMock()
        mock_paths.return_value = mock_path

        runner = CliRunner()
        result = runner.invoke(destroy, ["my-sandbox"], input="y\n")
        assert result.exit_code == 0

    @patch("foundry_sandbox.commands.destroy.sbx_check_available")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.validate_existing_sandbox_name")
    def test_confirmation_no_aborts(self, mock_validate, mock_paths, mock_check):
        mock_validate.return_value = (True, "")
        mock_path = MagicMock()
        mock_path.worktree_path = MagicMock()
        mock_path.claude_config_path = MagicMock()
        mock_paths.return_value = mock_path

        runner = CliRunner()
        result = runner.invoke(destroy, ["my-sandbox"], input="n\n")
        assert result.exit_code == 0
        assert "Aborted" in result.output

    @patch("foundry_sandbox.commands.destroy.sbx_check_available")
    def test_invalid_name(self, mock_check):
        runner = CliRunner()
        result = runner.invoke(destroy, [""])
        assert result.exit_code == 1
