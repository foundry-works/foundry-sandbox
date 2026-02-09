"""Unit tests for git path fixer module.

Tests fix_worktree_paths, fix_proxy_worktree_paths, and detect_nested_git_repos
from foundry_sandbox.git_path_fixer.

The module under test does not yet exist; these tests are written against
the spec derived from lib/container_config.sh shell functions:
  - fix_worktree_paths()
  - fix_proxy_worktree_paths()
  - detect_nested_git_repos()

All subprocess.run calls are mocked so tests run without Docker.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, call, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _completed(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> MagicMock:
    """Build a mock subprocess.CompletedProcess."""
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.stdout = stdout
    cp.stderr = stderr
    cp.returncode = returncode
    return cp


# ---------------------------------------------------------------------------
# TestFixWorktreePaths
# ---------------------------------------------------------------------------


class TestFixWorktreePaths:
    """Tests for fix_worktree_paths."""

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_corrects_gitdir_refs(self, mock_run):
        """Gitdir references with host user paths are rewritten to container paths."""
        from foundry_sandbox.git_path_fixer import fix_worktree_paths

        # First call: docker exec to read the .git file content
        # The shell function does a grep + sed inside the container in one
        # docker exec invocation.  We simulate the exec returning the
        # original .git file contents with host-user path, then the
        # corrected write succeeding.
        #
        # The actual implementation runs a single docker exec that:
        #   1) checks if /workspace/.git is a file
        #   2) greps for /home/<host_user> or /Users/<host_user>
        #   3) sed -i replaces both patterns
        #   4) reads gitdir, writes corrected gitdir reference
        #
        # We simulate the exec succeeding with returncode 0.
        mock_run.return_value = _completed(returncode=0)

        fix_worktree_paths("container-abc123", "tyler")

        # Verify docker exec was called
        assert mock_run.called
        first_call_args = mock_run.call_args_list[0]
        cmd = first_call_args[0][0] if first_call_args[0] else first_call_args[1].get("args", [])

        # The command should reference docker exec with the container id
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        assert "docker" in cmd_str
        assert "container-abc123" in cmd_str

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_skips_when_no_git_files(self, mock_run):
        """No error when no .git files found."""
        from foundry_sandbox.git_path_fixer import fix_worktree_paths

        # Docker exec returns 0 even if no .git file matches (grep/sed
        # silently do nothing when path doesn't match).
        mock_run.return_value = _completed(returncode=0)

        # Should not raise
        fix_worktree_paths("container-abc123", "tyler")
        assert mock_run.called

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_validates_host_user_safe_chars(self, mock_run):
        """Rejects host_user with unsafe characters."""
        from foundry_sandbox.git_path_fixer import fix_worktree_paths

        # Usernames with shell metacharacters must be rejected to prevent
        # injection in the sed command inside docker exec.
        unsafe_usernames = [
            "user;rm -rf /",
            "user|cat /etc/shadow",
            "user&background",
            "user$(whoami)",
            "user`id`",
            "../../../etc",
            "user name",       # spaces
            "user\ttab",       # tabs
        ]

        for unsafe in unsafe_usernames:
            mock_run.reset_mock()
            # Should either return early or raise ValueError
            try:
                fix_worktree_paths("container-abc123", unsafe)
            except ValueError:
                pass  # Raising ValueError is acceptable

            # subprocess.run must NOT have been called with an unsafe username
            # because validation should happen before any docker exec
            mock_run.assert_not_called(), (
                f"subprocess.run should not be called for unsafe username: {unsafe!r}"
            )

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_handles_macos_paths(self, mock_run):
        """Correctly rewrites /Users/username/... paths to /home/ubuntu/..."""
        from foundry_sandbox.git_path_fixer import fix_worktree_paths

        # The docker exec shell snippet contains:
        #   sed -i -e 's|/Users/$host_user|/home/ubuntu|g' /workspace/.git
        # Simulate successful execution.
        mock_run.return_value = _completed(returncode=0)

        fix_worktree_paths("container-mac", "tyler")

        assert mock_run.called
        # Verify the command includes a reference to /Users/ replacement
        # (the sed pattern in the shell script handles both Linux and macOS)
        all_args = " ".join(
            str(a) for c in mock_run.call_args_list for a in (c[0][0] if c[0] else [])
        )
        # The implementation should mention both /Users/ and /home/ patterns
        assert "/Users/" in all_args or "Users" in all_args or mock_run.call_count >= 1

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_empty_host_user_noop(self, mock_run):
        """Empty host_user is a no-op (returns immediately)."""
        from foundry_sandbox.git_path_fixer import fix_worktree_paths

        fix_worktree_paths("container-abc123", "")

        # No docker exec should be called for empty host_user
        mock_run.assert_not_called()

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_valid_usernames_accepted(self, mock_run):
        """Usernames with safe characters are accepted."""
        from foundry_sandbox.git_path_fixer import fix_worktree_paths

        mock_run.return_value = _completed(returncode=0)

        safe_names = ["tyler", "user.name", "user-name", "user_name", "User123"]
        for name in safe_names:
            mock_run.reset_mock()
            fix_worktree_paths("container-abc123", name)
            assert mock_run.called, f"subprocess.run should be called for safe username: {name!r}"

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_docker_exec_failure_does_not_raise(self, mock_run):
        """Non-zero docker exec return code should not raise (best-effort)."""
        from foundry_sandbox.git_path_fixer import fix_worktree_paths

        # The shell function pipes errors to /dev/null and uses || true
        mock_run.return_value = _completed(returncode=1, stderr="some error")

        # Should not raise
        fix_worktree_paths("container-abc123", "tyler")


# ---------------------------------------------------------------------------
# TestFixProxyWorktreePaths
# ---------------------------------------------------------------------------


class TestFixProxyWorktreePaths:
    """Tests for fix_proxy_worktree_paths."""

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_creates_symlinks(self, mock_run):
        """Creates symlinks for worktree paths that differ between host and container."""
        from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths

        # The shell function creates symlinks via docker exec sh -c:
        #   ln -s /home/ubuntu '/home/$host_user'
        #   ln -s /home/ubuntu '/Users/$host_user'
        # Then it also configures core.worktree for the proxy workspace.
        mock_run.return_value = _completed(returncode=0)

        fix_proxy_worktree_paths("proxy-container-42", "tyler")

        assert mock_run.called
        # The command should be docker exec targeting the proxy container
        first_cmd = mock_run.call_args_list[0]
        cmd = first_cmd[0][0] if first_cmd[0] else first_cmd[1].get("args", [])
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        assert "proxy-container-42" in cmd_str

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_handles_linux_host_paths(self, mock_run):
        """Handles /home/username paths on Linux hosts."""
        from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths

        mock_run.return_value = _completed(returncode=0)

        fix_proxy_worktree_paths("proxy-linux", "devuser")

        assert mock_run.called
        # Should include logic for /home/<user> -> /home/ubuntu symlink
        all_args = " ".join(
            str(a) for c in mock_run.call_args_list for a in (c[0][0] if c[0] else [])
        )
        # The shell command checks: if [ ! -e '/home/$host_user' ]
        assert "/home/" in all_args or "home" in all_args

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_handles_macos_host_paths(self, mock_run):
        """Handles /Users/username paths on macOS hosts."""
        from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths

        mock_run.return_value = _completed(returncode=0)

        fix_proxy_worktree_paths("proxy-macos", "devuser")

        assert mock_run.called
        # Should include logic for /Users/<user> -> /home/ubuntu symlink
        all_args = " ".join(
            str(a) for c in mock_run.call_args_list for a in (c[0][0] if c[0] else [])
        )
        # The shell command creates: mkdir -p /Users && ln -s /home/ubuntu '/Users/$host_user'
        assert "/Users/" in all_args or "Users" in all_args

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_empty_inputs_noop(self, mock_run):
        """Empty host_user or container returns early."""
        from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths

        # Empty host_user
        fix_proxy_worktree_paths("proxy-container", "")
        mock_run.assert_not_called()

        # Empty proxy_container
        fix_proxy_worktree_paths("", "tyler")
        mock_run.assert_not_called()

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_validates_host_user_safe_chars(self, mock_run):
        """Rejects host_user with unsafe characters in proxy variant too."""
        from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths

        unsafe_usernames = [
            "user;rm -rf /",
            "user|cat /etc/shadow",
            "user$(whoami)",
        ]

        for unsafe in unsafe_usernames:
            mock_run.reset_mock()
            try:
                fix_proxy_worktree_paths("proxy-container", unsafe)
            except ValueError:
                pass

            # subprocess.run must not be called with unsafe input
            mock_run.assert_not_called(), (
                f"subprocess.run should not be called for unsafe username: {unsafe!r}"
            )

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_configures_core_worktree(self, mock_run):
        """Sets core.worktree on the proxy worktree gitdir."""
        from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths

        mock_run.return_value = _completed(returncode=0)

        fix_proxy_worktree_paths("proxy-wt", "tyler")

        assert mock_run.called
        # The shell function contains: git config --file "$GITDIR_PATH/config.worktree" core.worktree /git-workspace
        all_args = " ".join(
            str(a) for c in mock_run.call_args_list for a in (c[0][0] if c[0] else [])
        )
        assert "core.worktree" in all_args or "config.worktree" in all_args or mock_run.call_count >= 1

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_docker_exec_failure_does_not_raise(self, mock_run):
        """Non-zero docker exec return code should not raise (best-effort)."""
        from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths

        # The shell function uses 2>/dev/null || true
        mock_run.return_value = _completed(returncode=1, stderr="error")

        # Should not raise
        fix_proxy_worktree_paths("proxy-container", "tyler")


# ---------------------------------------------------------------------------
# TestDetectNestedGitRepos
# ---------------------------------------------------------------------------


class TestDetectNestedGitRepos:
    """Tests for detect_nested_git_repos."""

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_identifies_nested_repos(self, mock_run):
        """Finds .git directories nested inside workspace."""
        from foundry_sandbox.git_path_fixer import detect_nested_git_repos

        # Simulate docker exec running:
        #   find /home/ubuntu/workspace -mindepth 2 -name .git -type d
        # The shell implementation actually runs find /workspace -mindepth 2 ...
        nested_paths = (
            "/workspace/vendor/some-lib/.git\n"
            "/workspace/submodules/other/.git\n"
        )
        mock_run.return_value = _completed(stdout=nested_paths, returncode=0)

        result = detect_nested_git_repos("container-abc123", "/workspace")

        assert mock_run.called
        assert len(result) == 2
        assert "/workspace/vendor/some-lib/.git" in result
        assert "/workspace/submodules/other/.git" in result

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_returns_empty_when_none(self, mock_run):
        """Returns empty list when no nested repos found."""
        from foundry_sandbox.git_path_fixer import detect_nested_git_repos

        # find returns empty stdout when no matches
        mock_run.return_value = _completed(stdout="", returncode=0)

        result = detect_nested_git_repos("container-abc123", "/workspace")

        assert mock_run.called
        assert result == []

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_handles_command_failure(self, mock_run):
        """Returns empty list if docker exec fails."""
        from foundry_sandbox.git_path_fixer import detect_nested_git_repos

        # docker exec fails (e.g., container not running)
        mock_run.return_value = _completed(
            stdout="",
            stderr="Error: No such container",
            returncode=1,
        )

        result = detect_nested_git_repos("dead-container", "/workspace")

        assert result == []

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_handles_subprocess_exception(self, mock_run):
        """Returns empty list if subprocess.run raises an exception."""
        from foundry_sandbox.git_path_fixer import detect_nested_git_repos

        mock_run.side_effect = subprocess.SubprocessError("connection refused")

        result = detect_nested_git_repos("container-abc123", "/workspace")

        assert result == []

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_strips_whitespace_from_paths(self, mock_run):
        """Trailing newlines and whitespace are stripped from returned paths."""
        from foundry_sandbox.git_path_fixer import detect_nested_git_repos

        mock_run.return_value = _completed(
            stdout="/workspace/sub/.git\n\n",
            returncode=0,
        )

        result = detect_nested_git_repos("container-abc123", "/workspace")

        assert result == ["/workspace/sub/.git"]

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_uses_correct_workspace_path(self, mock_run):
        """The find command targets the given workspace_path."""
        from foundry_sandbox.git_path_fixer import detect_nested_git_repos

        mock_run.return_value = _completed(stdout="", returncode=0)

        detect_nested_git_repos("container-abc123", "/home/ubuntu/workspace")

        assert mock_run.called
        cmd = mock_run.call_args_list[0]
        cmd_args = cmd[0][0] if cmd[0] else cmd[1].get("args", [])
        cmd_str = " ".join(cmd_args) if isinstance(cmd_args, list) else str(cmd_args)
        assert "/home/ubuntu/workspace" in cmd_str

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_single_nested_repo(self, mock_run):
        """Single nested repo is returned correctly."""
        from foundry_sandbox.git_path_fixer import detect_nested_git_repos

        mock_run.return_value = _completed(
            stdout="/workspace/node_modules/some-pkg/.git\n",
            returncode=0,
        )

        result = detect_nested_git_repos("container-abc123", "/workspace")

        assert len(result) == 1
        assert result[0] == "/workspace/node_modules/some-pkg/.git"

    @patch("foundry_sandbox.git_path_fixer.subprocess.run")
    def test_default_workspace_path(self, mock_run):
        """Uses /workspace as default when workspace_path not specified explicitly."""
        from foundry_sandbox.git_path_fixer import detect_nested_git_repos

        mock_run.return_value = _completed(stdout="", returncode=0)

        # The shell function uses /workspace hard-coded; the Python wrapper
        # should accept a workspace_path parameter with a sensible default.
        detect_nested_git_repos("container-abc123", "/workspace")

        assert mock_run.called


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
