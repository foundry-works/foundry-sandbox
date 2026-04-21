"""Tests for foundry_sandbox.git_safety module."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.git_safety import (
    compute_wrapper_checksum,
    generate_hmac_secret,
    git_safety_server_is_running,
    git_safety_server_start,
    git_safety_server_stop,
    inject_git_wrapper,
    read_wrapper_checksum_from_sandbox,
    register_sandbox_with_git_safety,
    unregister_sandbox_from_git_safety,
    verify_git_wrapper,
    verify_wrapper_integrity,
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

    def test_persists_repo_root(self, tmp_path):
        data_dir = tmp_path / "data"
        path = register_sandbox_with_git_safety(
            "sbx-3",
            branch="feature-y",
            repo_spec="org/repo",
            repo_root="/home/user/.sandboxes/worktrees/sbx-3",
            data_dir=str(data_dir),
        )
        metadata = json.loads(path.read_text())
        assert metadata["repo_root"] == "/home/user/.sandboxes/worktrees/sbx-3"

    def test_no_repo_root_when_not_provided(self, tmp_path):
        data_dir = tmp_path / "data"
        path = register_sandbox_with_git_safety(
            "sbx-4",
            branch="main",
            repo_spec="org/repo",
            data_dir=str(data_dir),
        )
        metadata = json.loads(path.read_text())
        assert "repo_root" not in metadata


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


# ============================================================================
# Checksum Functions
# ============================================================================


class TestComputeWrapperChecksum:
    def test_computes_sha256(self, tmp_path, monkeypatch):
        script = tmp_path / "git-wrapper-sbx.sh"
        script.write_text("#!/bin/bash\necho hello\n")
        monkeypatch.setattr("foundry_sandbox.git_safety._WRAPPER_SCRIPT", script)
        checksum = compute_wrapper_checksum()
        assert len(checksum) == 64
        assert all(c in "0123456789abcdef" for c in checksum)

    def test_deterministic(self, tmp_path, monkeypatch):
        script = tmp_path / "git-wrapper-sbx.sh"
        script.write_text("#!/bin/bash\necho hello\n")
        monkeypatch.setattr("foundry_sandbox.git_safety._WRAPPER_SCRIPT", script)
        assert compute_wrapper_checksum() == compute_wrapper_checksum()

    def test_raises_file_not_found(self, tmp_path, monkeypatch):
        missing = tmp_path / "nonexistent.sh"
        monkeypatch.setattr("foundry_sandbox.git_safety._WRAPPER_SCRIPT", missing)
        with pytest.raises(FileNotFoundError):
            compute_wrapper_checksum()


class TestReadWrapperChecksumFromSandbox:
    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_parses_sha256sum_output(self, mock_exec):
        mock_exec.return_value = _mock_completed(
            stdout="abcdef1234567890" * 4 + "  /usr/local/bin/git\n",
        )
        result = read_wrapper_checksum_from_sandbox("test")
        assert result == "abcdef1234567890" * 4

    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_returns_none_on_failure(self, mock_exec):
        mock_exec.return_value = _mock_completed(returncode=1)
        assert read_wrapper_checksum_from_sandbox("test") is None

    @patch("foundry_sandbox.sbx.sbx_exec", side_effect=Exception("fail"))
    def test_returns_none_on_exception(self, mock_exec):
        assert read_wrapper_checksum_from_sandbox("test") is None


class TestVerifyWrapperIntegrity:
    @patch("foundry_sandbox.git_safety.read_wrapper_checksum_from_sandbox")
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum")
    def test_match(self, mock_compute, mock_read):
        mock_compute.return_value = "abc123"
        mock_read.return_value = "abc123"
        ok, actual = verify_wrapper_integrity("test")
        assert ok is True
        assert actual == "abc123"

    @patch("foundry_sandbox.git_safety.read_wrapper_checksum_from_sandbox")
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum")
    def test_mismatch(self, mock_compute, mock_read):
        mock_compute.return_value = "abc123"
        mock_read.return_value = "def456"
        ok, actual = verify_wrapper_integrity("test")
        assert ok is False
        assert actual == "def456"

    @patch("foundry_sandbox.git_safety.read_wrapper_checksum_from_sandbox")
    def test_with_explicit_expected(self, mock_read):
        mock_read.return_value = "explicit_checksum"
        ok, actual = verify_wrapper_integrity(
            "test", expected_checksum="explicit_checksum",
        )
        assert ok is True
        assert actual == "explicit_checksum"

    @patch("foundry_sandbox.git_safety.read_wrapper_checksum_from_sandbox")
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum")
    def test_missing_in_sandbox(self, mock_compute, mock_read):
        mock_compute.return_value = "abc"
        mock_read.return_value = None
        ok, actual = verify_wrapper_integrity("test")
        assert ok is False
        assert actual == ""


class TestRepoRootResolution:
    """Verify server-side repo_root resolution from metadata."""

    def test_repo_root_returned_when_present_in_metadata(self, tmp_path):
        from foundry_git_safety.auth import NonceStore, RateLimiter, SecretStore
        from foundry_git_safety.server import create_git_api

        data_dir = str(tmp_path / "data")
        secrets_dir = str(tmp_path / "secrets")
        os.makedirs(os.path.join(data_dir, "sandboxes"), exist_ok=True)
        os.makedirs(secrets_dir, exist_ok=True)

        sandbox_id = "test-sbx"
        secret = "a" * 64
        Path(secrets_dir, sandbox_id).write_text(secret)

        metadata = {
            "sandbox_branch": "feature",
            "from_branch": "main",
            "repos": [],
            "repo_root": str(tmp_path / "worktree"),
        }
        Path(data_dir, "sandboxes", f"{sandbox_id}.json").write_text(
            json.dumps(metadata)
        )

        app = create_git_api(
            secret_store=SecretStore(secrets_path=secrets_dir),
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
            data_dir=data_dir,
        )
        # The app should be created without error
        assert app is not None

    def test_missing_repo_root_returns_400(self, tmp_path):
        from foundry_git_safety.auth import NonceStore, RateLimiter, SecretStore
        from foundry_git_safety.server import create_git_api

        data_dir = str(tmp_path / "data")
        secrets_dir = str(tmp_path / "secrets")
        os.makedirs(os.path.join(data_dir, "sandboxes"), exist_ok=True)
        os.makedirs(secrets_dir, exist_ok=True)

        sandbox_id = "test-sbx-no-root"
        secret = "b" * 64
        Path(secrets_dir, sandbox_id).write_text(secret)

        # Metadata without repo_root
        metadata = {
            "sandbox_branch": "feature",
            "from_branch": "main",
            "repos": [],
        }
        Path(data_dir, "sandboxes", f"{sandbox_id}.json").write_text(
            json.dumps(metadata)
        )

        app = create_git_api(
            secret_store=SecretStore(secrets_path=secrets_dir),
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
            data_dir=data_dir,
        )
        client = app.test_client()

        # Build a valid HMAC-authenticated request (but we just need to get past
        # the initial checks — the repo_root check happens before git execution)
        import time
        import hashlib
        import hmac

        timestamp = str(time.time())
        nonce = "test-nonce-123"
        body = '{"args": ["git", "status"]}'
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        canonical = f"POST\n/git/exec\n{body_hash}\n{timestamp}\n{nonce}"
        sig = hmac.new(
            secret.encode(), canonical.encode(), hashlib.sha256
        ).hexdigest()

        resp = client.post(
            "/git/exec",
            data=body,
            content_type="application/json",
            headers={
                "X-Sandbox-Id": sandbox_id,
                "X-Request-Signature": sig,
                "X-Request-Timestamp": timestamp,
                "X-Request-Nonce": nonce,
            },
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert "repo_root" in data["error"]
