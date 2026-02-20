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
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.commands.destroy import destroy_impl


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_DESTROY = "foundry_sandbox.commands.destroy"


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
def destroy_mocks(mock_paths_fixture):
    """Provide all standard mocks for destroy_impl tests.

    Patches every external dependency of destroy_impl and returns a dict
    of mock objects keyed by short name.  Tests that need to override
    specific behaviour (e.g. side_effect) do so on the fixture-provided
    mock before calling destroy_impl.
    """
    with (
        patch(f"{_DESTROY}.derive_sandbox_paths") as m_paths,
        patch(f"{_DESTROY}._tmux_session_name") as m_tmux,
        patch("subprocess.run") as m_subprocess,
        patch(f"{_DESTROY}._proxy_cleanup") as m_proxy,
        patch(f"{_DESTROY}.compose_down") as m_compose,
        patch(f"{_DESTROY}.remove_stubs_volume") as m_stubs,
        patch(f"{_DESTROY}.remove_hmac_volume") as m_hmac,
        patch(f"{_DESTROY}.remove_sandbox_networks") as m_networks,
        patch(f"{_DESTROY}.load_sandbox_metadata") as m_metadata,
        patch(f"{_DESTROY}.remove_worktree") as m_rm_wt,
        patch(f"{_DESTROY}.cleanup_sandbox_branch") as m_branch,
        patch(f"{_DESTROY}._repo_url_to_bare_path") as m_url_to_path,
        patch(f"{_DESTROY}.log_info") as m_log_info,
        patch(f"{_DESTROY}.log_warn") as m_log_warn,
        patch(f"{_DESTROY}.shutil.rmtree") as m_shutil_rmtree,
    ):
        m_paths.return_value = mock_paths_fixture
        m_tmux.return_value = "session-test"
        m_url_to_path.return_value = "/path/to/bare"
        yield {
            "paths": m_paths,
            "tmux_name": m_tmux,
            "subprocess": m_subprocess,
            "proxy_cleanup": m_proxy,
            "compose_down": m_compose,
            "stubs": m_stubs,
            "hmac": m_hmac,
            "networks": m_networks,
            "metadata": m_metadata,
            "remove_worktree": m_rm_wt,
            "branch": m_branch,
            "url_to_path": m_url_to_path,
            "log_info": m_log_info,
            "log_warn": m_log_warn,
            "shutil_rmtree": m_shutil_rmtree,
        }


# ---------------------------------------------------------------------------
# TestSkipTmuxFlag
# ---------------------------------------------------------------------------


class TestSkipTmuxFlag:
    """Test that skip_tmux=True prevents tmux kill."""

    def test_skip_tmux_true_does_not_kill_session(self, destroy_mocks):
        """When skip_tmux=True, subprocess.run with tmux args should NOT be called."""
        destroy_mocks["metadata"].return_value = None

        destroy_impl("test-sandbox", skip_tmux=True)

        for call_obj in destroy_mocks["subprocess"].call_args_list:
            args = call_obj[0][0] if call_obj[0] else []
            assert args != ["tmux", "kill-session", "-t", "session-test"]

    def test_skip_tmux_false_kills_session(self, destroy_mocks):
        """When skip_tmux=False (default), subprocess.run with tmux args SHOULD be called."""
        destroy_mocks["metadata"].return_value = None

        destroy_impl("test-sandbox", skip_tmux=False)

        called_with_tmux = False
        for call_obj in destroy_mocks["subprocess"].call_args_list:
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

    def test_skip_branch_cleanup_true_does_not_cleanup(self, destroy_mocks):
        """When skip_branch_cleanup=True, cleanup_sandbox_branch should NOT be called."""
        destroy_mocks["metadata"].return_value = {
            "branch": "sandbox/test",
            "repo_url": "/path/to/repo",
        }

        destroy_impl("test-sandbox", skip_branch_cleanup=True)

        destroy_mocks["branch"].assert_not_called()

    def test_skip_branch_cleanup_false_cleans_branch(self, destroy_mocks):
        """When skip_branch_cleanup=False (default), cleanup_sandbox_branch SHOULD be called."""
        destroy_mocks["metadata"].return_value = {
            "branch": "sandbox/test",
            "repo_url": "/path/to/repo",
        }

        destroy_impl("test-sandbox", skip_branch_cleanup=False)

        destroy_mocks["branch"].assert_called_once_with("sandbox/test", "/path/to/bare")


# ---------------------------------------------------------------------------
# TestBestEffortMode
# ---------------------------------------------------------------------------


class TestBestEffortTrue:
    """Test that best_effort=True catches errors and logs them."""

    def test_best_effort_true_catches_proxy_cleanup_error(self, destroy_mocks):
        """best_effort=True catches OSError from compose_down and continues."""
        destroy_mocks["metadata"].return_value = None
        destroy_mocks["compose_down"].side_effect = OSError("docker failed")

        # Should not raise, should complete
        destroy_impl("test-sandbox", best_effort=True)

    def test_best_effort_true_logs_missing_resources(self, destroy_mocks):
        """best_effort=True logs errors without raising."""
        destroy_mocks["metadata"].return_value = None
        destroy_mocks["compose_down"].side_effect = OSError("docker failed")

        # Should not raise
        destroy_impl("test-sandbox", best_effort=True)

        # compose_down was called and failed
        destroy_mocks["compose_down"].assert_called_once()


class TestBestEffortFalse:
    """Test that best_effort=False raises on first error."""

    def test_best_effort_false_raises_on_compose_down_error(self, destroy_mocks):
        """best_effort=False raises on OSError from compose_down."""
        destroy_mocks["metadata"].return_value = None
        destroy_mocks["compose_down"].side_effect = OSError("docker failed")

        with pytest.raises(OSError, match="docker failed"):
            destroy_impl("test-sandbox", best_effort=False)

    def test_best_effort_false_raises_on_tmux_error(self, destroy_mocks):
        """best_effort=False raises on OSError from tmux kill."""
        destroy_mocks["metadata"].return_value = None
        destroy_mocks["subprocess"].side_effect = OSError("tmux not found")

        with pytest.raises(OSError, match="tmux not found"):
            destroy_impl("test-sandbox", best_effort=False)


# ---------------------------------------------------------------------------
# TestLoggingOutput
# ---------------------------------------------------------------------------


class TestLoggingOutput:
    """Test that log_info and log_warn are called appropriately."""

    def test_log_info_called_for_config_removal(self, destroy_mocks):
        """log_info should be called when removing Claude config."""
        destroy_mocks["metadata"].return_value = None

        destroy_impl("test-sandbox")

        log_info_calls = [
            str(call_obj[0][0]) if call_obj[0] else ""
            for call_obj in destroy_mocks["log_info"].call_args_list
        ]
        assert any("Removing Claude config" in s for s in log_info_calls), \
            f"Expected 'Removing Claude config' in log_info calls: {log_info_calls}"

    def test_log_info_called_for_worktree_removal(self, destroy_mocks):
        """log_info should be called when removing worktree."""
        destroy_mocks["metadata"].return_value = None

        destroy_impl("test-sandbox")

        log_info_calls = [
            str(call_obj[0][0]) if call_obj[0] else ""
            for call_obj in destroy_mocks["log_info"].call_args_list
        ]
        assert any("Removing worktree" in s for s in log_info_calls), \
            f"Expected 'Removing worktree' in log_info calls: {log_info_calls}"

    def test_log_warn_called_on_worktree_removal_error(self, destroy_mocks):
        """log_warn should be called when worktree removal fails with best_effort=True."""
        destroy_mocks["metadata"].return_value = None
        destroy_mocks["remove_worktree"].side_effect = Exception("worktree busy")

        destroy_impl("test-sandbox", best_effort=True)

        log_warn_calls = [
            str(call_obj[0][0]) if call_obj[0] else ""
            for call_obj in destroy_mocks["log_warn"].call_args_list
        ]
        assert any("Could not remove worktree" in s for s in log_warn_calls), \
            f"Expected 'Could not remove worktree' in log_warn calls: {log_warn_calls}"

    def test_log_warn_called_on_config_removal_error(self, destroy_mocks):
        """log_warn should be called when config removal sudo fails with best_effort=True."""
        destroy_mocks["metadata"].return_value = None
        destroy_mocks["shutil_rmtree"].side_effect = OSError("permission denied")
        destroy_mocks["subprocess"].side_effect = OSError("sudo not available")

        destroy_impl("test-sandbox", best_effort=True)

        log_warn_calls = [
            str(call_obj[0][0]) if call_obj[0] else ""
            for call_obj in destroy_mocks["log_warn"].call_args_list
        ]
        assert any("Could not remove config directory" in s for s in log_warn_calls), \
            f"Expected 'Could not remove config directory' in log_warn calls: {log_warn_calls}"


# ---------------------------------------------------------------------------
# TestKeepWorktreeFlag
# ---------------------------------------------------------------------------


class TestKeepWorktreeFlag:
    """Test that keep_worktree=True prevents deletion of worktree and config."""

    def test_keep_worktree_true_skips_worktree_removal(self, destroy_mocks):
        """When keep_worktree=True, remove_worktree should NOT be called."""
        destroy_mocks["metadata"].return_value = None

        destroy_impl("test-sandbox", keep_worktree=True)

        destroy_mocks["remove_worktree"].assert_not_called()

    def test_keep_worktree_true_skips_config_removal(self, destroy_mocks):
        """When keep_worktree=True, config dir should NOT be removed."""
        destroy_mocks["metadata"].return_value = None

        destroy_impl("test-sandbox", keep_worktree=True)

        destroy_mocks["shutil_rmtree"].assert_not_called()


# ---------------------------------------------------------------------------
# TestCleanupSequence
# ---------------------------------------------------------------------------


class TestCleanupSequence:
    """Test that all cleanup steps are called in correct order."""

    def test_all_cleanup_steps_called(self, destroy_mocks):
        """All cleanup functions should be called during destroy."""
        destroy_mocks["metadata"].return_value = {
            "branch": "sandbox/test",
            "repo_url": "/path/to/repo",
        }

        destroy_impl("test-sandbox")

        destroy_mocks["proxy_cleanup"].assert_called_once()
        destroy_mocks["compose_down"].assert_called_once()
        destroy_mocks["stubs"].assert_called_once()
        destroy_mocks["hmac"].assert_called_once()
        destroy_mocks["networks"].assert_called_once()
        destroy_mocks["metadata"].assert_called_once()
        destroy_mocks["remove_worktree"].assert_called_once()
        destroy_mocks["branch"].assert_called_once()


# ---------------------------------------------------------------------------
# TestMetadataHandling
# ---------------------------------------------------------------------------


class TestMetadataHandling:
    """Test metadata loading and branch cleanup conditions."""

    def test_no_branch_cleanup_when_metadata_missing(self, destroy_mocks):
        """When metadata is None, branch cleanup should NOT be called."""
        destroy_mocks["metadata"].return_value = None

        destroy_impl("test-sandbox")

        destroy_mocks["branch"].assert_not_called()

    def test_no_branch_cleanup_when_empty_metadata(self, destroy_mocks):
        """When metadata is empty dict, branch cleanup should NOT be called."""
        destroy_mocks["metadata"].return_value = {}

        destroy_impl("test-sandbox")

        destroy_mocks["branch"].assert_not_called()

    def test_no_branch_cleanup_when_branch_missing(self, destroy_mocks):
        """When branch is missing, cleanup should NOT be called."""
        destroy_mocks["metadata"].return_value = {"repo_url": "/path/to/repo"}

        destroy_impl("test-sandbox")

        destroy_mocks["branch"].assert_not_called()

    def test_metadata_error_caught_in_best_effort(self, destroy_mocks):
        """When metadata loading fails with best_effort=True, should continue."""
        destroy_mocks["metadata"].side_effect = OSError("metadata file missing")

        # Should not raise
        destroy_impl("test-sandbox", best_effort=True)

        destroy_mocks["metadata"].assert_called_once()

    def test_metadata_error_raised_in_strict_mode(self, destroy_mocks):
        """When metadata loading fails with best_effort=False, should raise."""
        destroy_mocks["metadata"].side_effect = ValueError("invalid metadata")

        with pytest.raises(ValueError, match="invalid metadata"):
            destroy_impl("test-sandbox", best_effort=False)


# ---------------------------------------------------------------------------
# TestSubprocessRunEdgeCases
# ---------------------------------------------------------------------------


class TestSubprocessRunEdgeCases:
    """Test subprocess.run behavior for tmux kill and sudo rm fallback."""

    def test_sudo_rm_fallback_called_on_shutil_error(self, destroy_mocks):
        """When shutil.rmtree fails, sudo rm should be tried."""
        destroy_mocks["metadata"].return_value = None
        destroy_mocks["shutil_rmtree"].side_effect = OSError("permission denied")

        destroy_impl("test-sandbox", best_effort=True)

        called_with_sudo = False
        for call_obj in destroy_mocks["subprocess"].call_args_list:
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
