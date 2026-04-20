"""Tests for foundry_sandbox.git_safety module."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.git_safety import (
    generate_hmac_secret,
    git_safety_server_is_running,
    git_safety_server_start,
    git_safety_server_stop,
    inject_git_wrapper,
    register_sandbox_with_git_safety,
    unregister_sandbox_from_git_safety,
    verify_git_wrapper,
    write_hmac_secret_for_server,
    write_hmac_secret_to_worktree,
)


def _mock_completed(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> MagicMock:
    mock = MagicMock(spec=subprocess.CompletedProcess)
    mock.stdout = stdout
    mock.stderr = stderr
    mock.returncode = returncode
    return mock


# ============================================================================
# Server Lifecycle
# ============================================================================


class TestGitSafetyServerStart:
    @patch("foundry_sandbox.git_safety.subprocess.run")
    def test_default(self, mock_run):
        mock_run.return_value = _mock_completed("Started")
        result = git_safety_server_start()
        assert result.returncode == 0
        cmd = mock_run.call_args[0][0]
        assert cmd == ["foundry-git-safety", "start"]

    @patch("foundry_sandbox.git_safety.subprocess.run")
    def test_with_port(self, mock_run):
        mock_run.return_value = _mock_completed()
        git_safety_server_start(port=9999)
        cmd = mock_run.call_args[0][0]
        assert "--port" in cmd
        assert "9999" in cmd

    @patch("foundry_sandbox.git_safety.subprocess.run")
    def test_foreground(self, mock_run):
        mock_run.return_value = _mock_completed()
        git_safety_server_start(foreground=True)
        cmd = mock_run.call_args[0][0]
        assert "--foreground" in cmd


class TestGitSafetyServerStop:
    @patch("foundry_sandbox.git_safety.subprocess.run")
    def test_stop(self, mock_run):
        mock_run.return_value = _mock_completed("Stopped")
        result = git_safety_server_stop()
        assert result.returncode == 0
        cmd = mock_run.call_args[0][0]
        assert cmd == ["foundry-git-safety", "stop"]


class TestGitSafetyServerIsRunning:
    @patch("foundry_sandbox.git_safety.subprocess.run")
    def test_running(self, mock_run):
        mock_run.return_value = _mock_completed("Server running")
        assert git_safety_server_is_running() is True

    @patch("foundry_sandbox.git_safety.subprocess.run")
    def test_not_running(self, mock_run):
        mock_run.return_value = _mock_completed(returncode=1)
        assert git_safety_server_is_running() is False

    @patch("foundry_sandbox.git_safety.subprocess.run", side_effect=OSError)
    def test_os_error(self, mock_run):
        assert git_safety_server_is_running() is False


# ============================================================================
# HMAC Secret Management
# ============================================================================


class TestGenerateHmacSecret:
    def test_length(self):
        secret = generate_hmac_secret()
        assert len(secret) == 64  # 32 bytes = 64 hex chars

    def test_hex(self):
        secret = generate_hmac_secret()
        int(secret, 16)  # should not raise

    def test_unique(self):
        a = generate_hmac_secret()
        b = generate_hmac_secret()
        assert a != b


class TestWriteHmacSecretToWorktree:
    def test_creates_file(self, tmp_path):
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        secret_path = write_hmac_secret_to_worktree(worktree, "my-secret")
        assert secret_path.exists()
        assert secret_path.read_text() == "my-secret"
        assert secret_path.name == "hmac-secret"
        assert str(secret_path.parent).endswith("/.foundry")

    def test_creates_foundry_dir(self, tmp_path):
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        write_hmac_secret_to_worktree(worktree, "secret")
        assert (worktree / ".foundry").is_dir()

    def test_permissions(self, tmp_path):
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        secret_path = write_hmac_secret_to_worktree(worktree, "secret")
        mode = secret_path.stat().st_mode & 0o777
        assert mode == 0o600


class TestWriteHmacSecretForServer:
    def test_creates_file(self, tmp_path):
        secrets_dir = tmp_path / "secrets"
        path = write_hmac_secret_for_server("sbx-1", "my-secret", secrets_dir=str(secrets_dir))
        assert path.exists()
        assert path.read_text() == "my-secret"
        assert path.name == "sbx-1"

    def test_creates_dir(self, tmp_path):
        secrets_dir = tmp_path / "new" / "secrets"
        write_hmac_secret_for_server("sbx-1", "secret", secrets_dir=str(secrets_dir))
        assert secrets_dir.is_dir()


# ============================================================================
# Sandbox Registration
# ============================================================================


class TestRegisterSandboxWithGitSafety:
    def test_creates_metadata(self, tmp_path):
        data_dir = tmp_path / "data"
        path = register_sandbox_with_git_safety(
            "sbx-1",
            branch="feature-x",
            repo_spec="org/repo",
            from_branch="main",
            allow_pr=True,
            data_dir=str(data_dir),
        )
        assert path.exists()
        metadata = json.loads(path.read_text())
        assert metadata["sandbox_branch"] == "feature-x"
        assert metadata["from_branch"] == "main"
        assert metadata["repos"] == ["org/repo"]
        assert metadata["allow_pr"] is True

    def test_minimal(self, tmp_path):
        data_dir = tmp_path / "data"
        path = register_sandbox_with_git_safety(
            "sbx-2",
            branch="dev",
            repo_spec="org/repo",
            data_dir=str(data_dir),
        )
        metadata = json.loads(path.read_text())
        assert metadata["from_branch"] == ""
        assert metadata["allow_pr"] is False

    def test_creates_sandboxes_dir(self, tmp_path):
        data_dir = tmp_path / "data"
        register_sandbox_with_git_safety(
            "sbx-1", branch="main", repo_spec="org/repo", data_dir=str(data_dir),
        )
        assert (data_dir / "sandboxes").is_dir()


class TestUnregisterSandboxFromGitSafety:
    def test_removes_files(self, tmp_path):
        data_dir = tmp_path / "data"
        secrets_dir = tmp_path / "secrets"
        register_sandbox_with_git_safety(
            "sbx-1", branch="main", repo_spec="org/repo", data_dir=str(data_dir),
        )
        write_hmac_secret_for_server("sbx-1", "secret", secrets_dir=str(secrets_dir))
        unregister_sandbox_from_git_safety(
            "sbx-1",
            data_dir=str(data_dir),
            secrets_dir=str(secrets_dir),
        )
        assert not (data_dir / "sandboxes" / "sbx-1.json").exists()
        assert not (secrets_dir / "sbx-1").exists()

    def test_idempotent(self, tmp_path):
        # Should not raise even if files don't exist
        unregister_sandbox_from_git_safety(
            "nonexistent",
            data_dir=str(tmp_path / "data"),
            secrets_dir=str(tmp_path / "secrets"),
        )


# ============================================================================
# Git Wrapper Injection
# ============================================================================


class TestInjectGitWrapper:
    @patch("foundry_sandbox.sbx.sbx_exec")
    @patch("foundry_sandbox.git_safety._WRAPPER_SCRIPT")
    def test_injects_wrapper(self, mock_wrapper_path, mock_exec):
        mock_wrapper_path.exists.return_value = True
        mock_wrapper_path.read_text.return_value = "#!/bin/bash\nwrapper"
        mock_exec.return_value = _mock_completed()

        inject_git_wrapper(
            "test-sandbox",
            sandbox_id="sbx-1",
            workspace_dir="/workspace",
        )

        # Should call sbx_exec 4 times: tee git, chmod git, tee env, chmod env
        assert mock_exec.call_count == 4

    @patch("foundry_sandbox.sbx.sbx_exec")
    @patch("foundry_sandbox.git_safety._WRAPPER_SCRIPT")
    def test_wrapper_not_found(self, mock_wrapper_path, mock_exec):
        mock_wrapper_path.exists.return_value = False
        with pytest.raises(FileNotFoundError):
            inject_git_wrapper("test", sandbox_id="sbx-1", workspace_dir="/workspace")

    @patch("foundry_sandbox.sbx.sbx_exec")
    @patch("foundry_sandbox.git_safety._WRAPPER_SCRIPT")
    def test_env_script_uses_workspace_dir(self, mock_wrapper_path, mock_exec):
        mock_wrapper_path.exists.return_value = True
        mock_wrapper_path.read_text.return_value = "#!/bin/bash\nwrapper"
        mock_exec.return_value = _mock_completed()

        inject_git_wrapper(
            "test-sandbox",
            sandbox_id="sbx-1",
            workspace_dir="/custom/path",
        )

        # Find the sbx_exec call that writes the env script
        env_call = mock_exec.call_args_list[2]  # third call is tee env script
        env_call_input = env_call[1]["input"]
        assert "WORKSPACE_DIR=/custom/path" in env_call_input
        assert 'GIT_HMAC_SECRET_FILE="/custom/path/.foundry/hmac-secret"' in env_call_input


class TestVerifyGitWrapper:
    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_installed(self, mock_exec):
        mock_exec.return_value = _mock_completed(stdout="/usr/local/bin/git\n")
        assert verify_git_wrapper("test") is True

    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_not_installed(self, mock_exec):
        mock_exec.return_value = _mock_completed(stdout="/usr/bin/git\n")
        assert verify_git_wrapper("test") is False

    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_failure(self, mock_exec):
        mock_exec.return_value = _mock_completed(returncode=1)
        assert verify_git_wrapper("test") is False

    @patch("foundry_sandbox.sbx.sbx_exec", side_effect=Exception("fail"))
    def test_exception(self, mock_exec):
        assert verify_git_wrapper("test") is False
