"""Unit tests for foundry_sandbox.commands.destroy.destroy_impl.

Tests the destroy_impl() implementation function for:
  - skip_tmux flag prevents tmux kill
  - skip_branch_cleanup flag prevents branch cleanup
  - best_effort=True catches and logs errors
  - best_effort=False raises on first error
  - logging output verification
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from foundry_sandbox.commands.destroy import destroy_impl


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_paths_fixture(tmp_path):
    """Mock paths object returned by derive_sandbox_paths."""
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    config = tmp_path / "claude_config"
    config.mkdir()

    paths = MagicMock()
    paths.worktree_path = worktree
    paths.container_name = "sandbox-test"
    paths.claude_config_path = config
    paths.override_file = Path("override.yml")
    return paths


@pytest.fixture
def standard_mocks():
    """Provide standard mocks for all external dependencies."""
    return {
        "derive_sandbox_paths": MagicMock(),
        "_tmux_session_name": MagicMock(return_value="session-test"),
        "_proxy_cleanup": MagicMock(),
        "compose_down": MagicMock(),
        "remove_stubs_volume": MagicMock(),
        "remove_hmac_volume": MagicMock(),
        "remove_sandbox_networks": MagicMock(),
        "load_sandbox_metadata": MagicMock(return_value={
            "branch": "sandbox/test",
            "repo_url": "/path/to/repo"
        }),
        "remove_worktree": MagicMock(),
        "cleanup_sandbox_branch": MagicMock(),
        "_repo_url_to_bare_path": MagicMock(return_value="/path/to/bare"),
        "log_info": MagicMock(),
        "log_warn": MagicMock(),
        "subprocess.run": MagicMock(),
        "shutil.rmtree": MagicMock(),
    }


# ---------------------------------------------------------------------------
# TestSkipTmuxFlag
# ---------------------------------------------------------------------------


class TestSkipTmuxFlag:
    """Test that skip_tmux=True prevents tmux kill."""

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_skip_tmux_true_does_not_kill_session(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When skip_tmux=True, subprocess.run with tmux args should NOT be called."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        destroy_impl("test-sandbox", skip_tmux=True)

        # subprocess.run should NOT be called with tmux args
        # Check all calls to subprocess.run
        for call_obj in mock_subprocess.call_args_list:
            args = call_obj[0][0] if call_obj[0] else []
            assert args != ["tmux", "kill-session", "-t", "session-test"]

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_skip_tmux_false_kills_session(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When skip_tmux=False (default), subprocess.run with tmux args SHOULD be called."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        destroy_impl("test-sandbox", skip_tmux=False)

        # subprocess.run should be called with tmux args
        called_with_tmux = False
        for call_obj in mock_subprocess.call_args_list:
            args = call_obj[0][0] if call_obj[0] else []
            if args == ["tmux", "kill-session", "-t", "session-test"]:
                called_with_tmux = True
                break
        assert called_with_tmux, "tmux kill-session was not called"


# ---------------------------------------------------------------------------
# TestSkipBranchCleanupFlag
# ---------------------------------------------------------------------------


class TestSkipBranchCleanupFlag:
    """Test that skip_branch_cleanup=True prevents branch cleanup."""

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_skip_branch_cleanup_true_does_not_cleanup(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When skip_branch_cleanup=True, cleanup_sandbox_branch should NOT be called."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = {
            "branch": "sandbox/test",
            "repo_url": "/path/to/repo"
        }

        destroy_impl("test-sandbox", skip_branch_cleanup=True)

        # cleanup_sandbox_branch should NOT be called
        mock_branch.assert_not_called()

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy._repo_url_to_bare_path")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_skip_branch_cleanup_false_cleans_branch(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_url_to_path,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When skip_branch_cleanup=False (default), cleanup_sandbox_branch SHOULD be called."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = {
            "branch": "sandbox/test",
            "repo_url": "/path/to/repo"
        }
        mock_url_to_path.return_value = "/path/to/bare"

        destroy_impl("test-sandbox", skip_branch_cleanup=False)

        # cleanup_sandbox_branch SHOULD be called
        mock_branch.assert_called_once_with("sandbox/test", "/path/to/bare")


# ---------------------------------------------------------------------------
# TestBestEffortMode
# ---------------------------------------------------------------------------


class TestBestEffortTrue:
    """Test that best_effort=True catches errors and logs them."""

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down", side_effect=OSError("docker failed"))
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_best_effort_true_catches_proxy_cleanup_error(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """best_effort=True catches OSError from compose_down and continues."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        # Should not raise, should complete
        destroy_impl("test-sandbox", best_effort=True)

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down", side_effect=OSError("docker failed"))
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_best_effort_true_logs_missing_resources(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """best_effort=True logs errors without raising."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        # Should not raise
        destroy_impl("test-sandbox", best_effort=True)

        # compose_down was called and failed
        mock_compose.assert_called_once()


class TestBestEffortFalse:
    """Test that best_effort=False raises on first error."""

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down", side_effect=OSError("docker failed"))
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_best_effort_false_raises_on_compose_down_error(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """best_effort=False raises on OSError from compose_down."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        with pytest.raises(OSError, match="docker failed"):
            destroy_impl("test-sandbox", best_effort=False)

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run", side_effect=OSError("tmux not found"))
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_best_effort_false_raises_on_tmux_error(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """best_effort=False raises on OSError from tmux kill."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        with pytest.raises(OSError, match="tmux not found"):
            destroy_impl("test-sandbox", best_effort=False)


# ---------------------------------------------------------------------------
# TestLoggingOutput
# ---------------------------------------------------------------------------


class TestLoggingOutput:
    """Test that log_info and log_warn are called appropriately."""

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_log_info_called_for_config_removal(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """log_info should be called when removing Claude config."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        destroy_impl("test-sandbox")

        # Verify log_info was called with "Removing Claude config..."
        log_info_calls = [
            str(call_obj[0][0]) if call_obj[0] else ""
            for call_obj in mock_log_info.call_args_list
        ]
        assert any("Removing Claude config" in s for s in log_info_calls), \
            f"Expected 'Removing Claude config' in log_info calls: {log_info_calls}"

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_log_info_called_for_worktree_removal(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """log_info should be called when removing worktree."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        destroy_impl("test-sandbox")

        # Verify log_info was called with "Removing worktree..."
        log_info_calls = [
            str(call_obj[0][0]) if call_obj[0] else ""
            for call_obj in mock_log_info.call_args_list
        ]
        assert any("Removing worktree" in s for s in log_info_calls), \
            f"Expected 'Removing worktree' in log_info calls: {log_info_calls}"

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree", side_effect=Exception("worktree busy"))
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_log_warn_called_on_worktree_removal_error(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """log_warn should be called when worktree removal fails with best_effort=True."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        destroy_impl("test-sandbox", best_effort=True)

        # Verify log_warn was called with error message
        log_warn_calls = [
            str(call_obj[0][0]) if call_obj[0] else ""
            for call_obj in mock_log_warn.call_args_list
        ]
        assert any("Could not remove worktree" in s for s in log_warn_calls), \
            f"Expected 'Could not remove worktree' in log_warn calls: {log_warn_calls}"

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run", side_effect=OSError("sudo not available"))
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("foundry_sandbox.commands.destroy.shutil.rmtree", side_effect=OSError("permission denied"))
    def test_log_warn_called_on_config_removal_error(
        self,
        mock_shutil_rmtree,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """log_warn should be called when config removal sudo fails with best_effort=True."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        destroy_impl("test-sandbox", best_effort=True)

        # Verify log_warn was called with error message about config
        log_warn_calls = [
            str(call_obj[0][0]) if call_obj[0] else ""
            for call_obj in mock_log_warn.call_args_list
        ]
        assert any("Could not remove config directory" in s for s in log_warn_calls), \
            f"Expected 'Could not remove config directory' in log_warn calls: {log_warn_calls}"


# ---------------------------------------------------------------------------
# TestKeepWorktreeFlag
# ---------------------------------------------------------------------------


class TestKeepWorktreeFlag:
    """Test that keep_worktree=True prevents deletion of worktree and config."""

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_keep_worktree_true_skips_worktree_removal(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When keep_worktree=True, remove_worktree should NOT be called."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        destroy_impl("test-sandbox", keep_worktree=True)

        # remove_worktree should NOT be called
        mock_rm_wt.assert_not_called()

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("shutil.rmtree")
    def test_keep_worktree_true_skips_config_removal(
        self,
        mock_shutil_rmtree,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When keep_worktree=True, config dir should NOT be removed."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        destroy_impl("test-sandbox", keep_worktree=True)

        # shutil.rmtree should NOT be called for config
        mock_shutil_rmtree.assert_not_called()


# ---------------------------------------------------------------------------
# TestCleanupSequence
# ---------------------------------------------------------------------------


class TestCleanupSequence:
    """Test that all cleanup steps are called in correct order."""

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy._repo_url_to_bare_path")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("shutil.rmtree")
    def test_all_cleanup_steps_called(
        self,
        mock_shutil_rmtree,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_url_to_path,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """All cleanup functions should be called during destroy."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = {
            "branch": "sandbox/test",
            "repo_url": "/path/to/repo"
        }
        mock_url_to_path.return_value = "/path/to/bare"

        destroy_impl("test-sandbox")

        # Verify all cleanup functions were called
        mock_proxy.assert_called_once()
        mock_compose.assert_called_once()
        mock_stubs.assert_called_once()
        mock_hmac.assert_called_once()
        mock_networks.assert_called_once()
        mock_metadata.assert_called_once()
        mock_rm_wt.assert_called_once()
        mock_branch.assert_called_once()


# ---------------------------------------------------------------------------
# TestMetadataHandling
# ---------------------------------------------------------------------------


class TestMetadataHandling:
    """Test metadata loading and branch cleanup conditions."""

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_no_branch_cleanup_when_metadata_missing(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When metadata is None, branch cleanup should NOT be called."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        destroy_impl("test-sandbox")

        # cleanup_sandbox_branch should NOT be called
        mock_branch.assert_not_called()

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_no_branch_cleanup_when_empty_metadata(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When metadata is empty dict, branch cleanup should NOT be called."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = {}

        destroy_impl("test-sandbox")

        # cleanup_sandbox_branch should NOT be called (no branch/repo_url)
        mock_branch.assert_not_called()

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_no_branch_cleanup_when_branch_missing(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When branch is missing, cleanup should NOT be called."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        # Only repo_url, no branch
        mock_metadata.return_value = {"repo_url": "/path/to/repo"}

        destroy_impl("test-sandbox")

        # cleanup_sandbox_branch should NOT be called
        mock_branch.assert_not_called()

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy._repo_url_to_bare_path")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_metadata_error_caught_in_best_effort(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_url_to_path,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When metadata loading fails with best_effort=True, should continue."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.side_effect = OSError("metadata file missing")

        # Should not raise
        destroy_impl("test-sandbox", best_effort=True)

        # Should have been called
        mock_metadata.assert_called_once()

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    def test_metadata_error_raised_in_strict_mode(
        self,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When metadata loading fails with best_effort=False, should raise."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.side_effect = ValueError("invalid metadata")

        with pytest.raises(ValueError, match="invalid metadata"):
            destroy_impl("test-sandbox", best_effort=False)


# ---------------------------------------------------------------------------
# TestSubprocessRunEdgeCases
# ---------------------------------------------------------------------------


class TestSubprocessRunEdgeCases:
    """Test subprocess.run behavior for tmux kill and sudo rm fallback."""

    @patch("foundry_sandbox.commands.destroy.log_warn")
    @patch("foundry_sandbox.commands.destroy.log_info")
    @patch("foundry_sandbox.commands.destroy.cleanup_sandbox_branch")
    @patch("foundry_sandbox.commands.destroy.remove_worktree")
    @patch("foundry_sandbox.commands.destroy.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.destroy.remove_sandbox_networks")
    @patch("foundry_sandbox.commands.destroy.remove_hmac_volume")
    @patch("foundry_sandbox.commands.destroy.remove_stubs_volume")
    @patch("foundry_sandbox.commands.destroy.compose_down")
    @patch("foundry_sandbox.commands.destroy._proxy_cleanup")
    @patch("subprocess.run")
    @patch("foundry_sandbox.commands.destroy._tmux_session_name")
    @patch("foundry_sandbox.commands.destroy.derive_sandbox_paths")
    @patch("shutil.rmtree", side_effect=OSError("permission denied"))
    def test_sudo_rm_fallback_called_on_shutil_error(
        self,
        mock_shutil_rmtree,
        mock_paths,
        mock_tmux_name,
        mock_subprocess,
        mock_proxy,
        mock_compose,
        mock_stubs,
        mock_hmac,
        mock_networks,
        mock_metadata,
        mock_rm_wt,
        mock_branch,
        mock_log_info,
        mock_log_warn,
        mock_paths_fixture,
    ):
        """When shutil.rmtree fails, sudo rm should be tried."""
        mock_paths.return_value = mock_paths_fixture
        mock_tmux_name.return_value = "session-test"
        mock_metadata.return_value = None

        destroy_impl("test-sandbox", best_effort=True)

        # subprocess.run should have been called for sudo rm
        called_with_sudo = False
        for call_obj in mock_subprocess.call_args_list:
            args = call_obj[0][0] if call_obj[0] else []
            if args and args[0] == "sudo":
                called_with_sudo = True
                break
        assert called_with_sudo, "sudo rm was not called after shutil.rmtree failed"


class TestDestroyImplNameValidation:
    """Test that destroy_impl validates sandbox names."""

    def test_empty_name_raises_value_error(self):
        """Empty sandbox name should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid sandbox name"):
            destroy_impl("")

    def test_path_traversal_name_raises_value_error(self):
        """Name containing path separators should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid sandbox name"):
            destroy_impl("../evil")

    def test_dot_name_raises_value_error(self):
        """Name '.' or '..' should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid sandbox name"):
            destroy_impl("..")

    def test_control_char_name_raises_value_error(self):
        """Name with control characters should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid sandbox name"):
            destroy_impl("sandbox\x00name")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
