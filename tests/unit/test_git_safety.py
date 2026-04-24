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
    write_hmac_secret_to_sandbox,
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


class TestWriteHmacSecretToSandbox:
    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_creates_dir_and_writes_secret(self, mock_exec):
        mock_exec.return_value = _mock_completed()
        secret_path = write_hmac_secret_to_sandbox("test-sandbox", "my-secret")
        assert str(secret_path) == "/run/foundry/hmac-secret"
        assert mock_exec.call_count == 1
        # Combined mkdir + write in a single exec call
        call_args = mock_exec.call_args_list[0]
        cmd = str(call_args)
        assert "mkdir" in cmd
        assert "hmac-secret" in cmd

    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_writes_to_both_tmpfs_and_persistent(self, mock_exec):
        mock_exec.return_value = _mock_completed()
        write_hmac_secret_to_sandbox("test-sandbox", "my-secret")
        call_args = mock_exec.call_args_list[0]
        cmd = str(call_args)
        # Both locations must be written in a single exec
        assert "/run/foundry/hmac-secret" in cmd
        assert "/var/lib/foundry/hmac-secret" in cmd


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

    def test_rejects_auth_incompatible_sandbox_id(self, tmp_path):
        secrets_dir = tmp_path / "secrets"
        with pytest.raises(ValueError, match="Invalid git-safety sandbox id"):
            write_hmac_secret_for_server(
                "x" * 65,
                "secret",
                secrets_dir=str(secrets_dir),
            )


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

    def test_rejects_auth_incompatible_sandbox_id(self, tmp_path):
        data_dir = tmp_path / "data"
        with pytest.raises(ValueError, match="Invalid git-safety sandbox id"):
            register_sandbox_with_git_safety(
                "bad sandbox",
                branch="feature-x",
                repo_spec="org/repo",
                data_dir=str(data_dir),
            )

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
    @patch("foundry_sandbox.git_safety._proxy_sign_script_path")
    @patch("foundry_sandbox.git_safety._wrapper_script_path")
    def test_injects_wrapper(self, mock_wrapper_fn, mock_proxy_sign_fn, mock_exec):
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "#!/bin/bash\nwrapper"
        mock_wrapper_fn.return_value = mock_path
        mock_proxy_sign_fn.return_value = mock_path
        mock_exec.return_value = _mock_completed()

        inject_git_wrapper(
            "test-sandbox",
            sandbox_id="sbx-1",
            workspace_dir="/workspace",
        )

        # 6 calls: base64 git, base64 proxy-sign, base64 profile.d env,
        # bashrc append, base64 persistent env, git hardening
        assert mock_exec.call_count == 6

    @patch("foundry_sandbox.sbx.sbx_exec")
    @patch("foundry_sandbox.git_safety._wrapper_script_path")
    def test_wrapper_not_found(self, mock_wrapper_fn, mock_exec):
        mock_wrapper_fn.side_effect = FileNotFoundError("not found")
        with pytest.raises(FileNotFoundError):
            inject_git_wrapper("test", sandbox_id="sbx-1", workspace_dir="/workspace")

    @patch("foundry_sandbox.sbx.sbx_exec")
    @patch("foundry_sandbox.git_safety._proxy_sign_script_path")
    @patch("foundry_sandbox.git_safety._wrapper_script_path")
    def test_env_script_uses_workspace_dir(self, mock_wrapper_fn, mock_proxy_sign_fn, mock_exec):
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "#!/bin/bash\nwrapper"
        mock_wrapper_fn.return_value = mock_path
        mock_proxy_sign_fn.return_value = mock_path
        mock_exec.return_value = _mock_completed()

        inject_git_wrapper(
            "test-sandbox",
            sandbox_id="sbx-1",
            workspace_dir="/custom/path",
        )

        # The profile.d env script is the 3rd call (index 2), base64-encoded
        env_call = mock_exec.call_args_list[2]
        env_cmd = str(env_call)
        assert "foundry-git-safety.sh" in env_cmd
        # Decode the base64 to check content
        import base64
        cmd_str = env_call[0][1][2]  # ["sh", "-c", "..."]
        b64_part = cmd_str.split("echo '")[1].split("' | base64")[0]
        env_content = base64.b64decode(b64_part).decode()
        assert "export WORKSPACE_DIR=/custom/path" in env_content
        assert "export GIT_HMAC_SECRET_FILE=/run/foundry/hmac-secret" in env_content

        # The persistent env file is the 5th call (index 4)
        persistent_call = mock_exec.call_args_list[4]
        persistent_cmd = str(persistent_call)
        assert "git-safety.env" in persistent_cmd
        cmd_str_p = persistent_call[0][1][2]
        b64_part_p = cmd_str_p.split("echo '")[1].split("' | base64")[0]
        persistent_content = base64.b64decode(b64_part_p).decode()
        assert "export WORKSPACE_DIR=/custom/path" in persistent_content
        assert "export SANDBOX_ID=sbx-1" in persistent_content

    @patch("foundry_sandbox.sbx.sbx_exec")
    @patch("foundry_sandbox.git_safety._proxy_sign_script_path")
    @patch("foundry_sandbox.git_safety._wrapper_script_path")
    def test_env_scripts_quote_shell_sensitive_values(
        self, mock_wrapper_fn, mock_proxy_sign_fn, mock_exec,
    ):
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = "#!/bin/bash\nwrapper"
        mock_wrapper_fn.return_value = mock_path
        mock_proxy_sign_fn.return_value = mock_path
        mock_exec.return_value = _mock_completed()

        inject_git_wrapper(
            "test-sandbox",
            sandbox_id="sbx-1",
            workspace_dir="/tmp/repo with spaces/$(nope)",
        )

        import base64

        env_cmd = mock_exec.call_args_list[2][0][1][2]
        env_b64 = env_cmd.split("echo '")[1].split("' | base64")[0]
        env_content = base64.b64decode(env_b64).decode()
        assert "export WORKSPACE_DIR='/tmp/repo with spaces/$(nope)'" in env_content

        persistent_cmd = mock_exec.call_args_list[4][0][1][2]
        persistent_b64 = persistent_cmd.split("echo '")[1].split("' | base64")[0]
        persistent_content = base64.b64decode(persistent_b64).decode()
        assert "export WORKSPACE_DIR='/tmp/repo with spaces/$(nope)'" in persistent_content


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
    @patch("foundry_sandbox.git_safety._wrapper_script_path")
    def test_computes_sha256(self, mock_wrapper_fn, tmp_path):
        script = tmp_path / "git-wrapper.sh"
        script.write_text("#!/bin/bash\necho hello\n")
        mock_wrapper_fn.return_value = script
        checksum = compute_wrapper_checksum()
        assert len(checksum) == 64
        assert all(c in "0123456789abcdef" for c in checksum)

    @patch("foundry_sandbox.git_safety._wrapper_script_path")
    def test_deterministic(self, mock_wrapper_fn, tmp_path):
        script = tmp_path / "git-wrapper.sh"
        script.write_text("#!/bin/bash\necho hello\n")
        mock_wrapper_fn.return_value = script
        assert compute_wrapper_checksum() == compute_wrapper_checksum()

    @patch("foundry_sandbox.git_safety._wrapper_script_path")
    def test_raises_file_not_found(self, mock_wrapper_fn):
        mock_wrapper_fn.side_effect = FileNotFoundError("not found")
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


class TestWrapperScriptResolution:
    """Verify the wrapper script is resolvable from package resources."""

    def test_wrapper_script_resolves_from_package(self):
        from foundry_sandbox.git_safety import _wrapper_script_path

        path = _wrapper_script_path()
        assert path.exists()
        assert path.name == "git-wrapper.sh"

    def test_wrapper_script_is_readable(self):
        from foundry_sandbox.git_safety import _wrapper_script_path

        path = _wrapper_script_path()
        content = path.read_text()
        assert content.startswith("#!/bin/bash")
        assert "WORKSPACE_DIR" in content

    def test_wrapper_script_is_nonempty(self):
        from foundry_sandbox.git_safety import _wrapper_script_path

        path = _wrapper_script_path()
        assert path.stat().st_size > 100


# ============================================================================
# Shared Provisioning Helpers
# ============================================================================


class TestProvisionGitSafety:
    """Tests for the centralized provision_git_safety helper."""

    @patch("foundry_sandbox.git_safety._verify_sandbox_connectivity")
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="sha256abc")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.register_sandbox_with_git_safety")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_sandbox")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="a" * 64)
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    def test_full_provisioning_success(
        self, mock_patch, mock_hmac, mock_write_guest, mock_write_host,
        mock_register, mock_inject, mock_checksum, mock_connectivity,
    ):
        from foundry_sandbox.git_safety import provision_git_safety

        result = provision_git_safety(
            "test-sandbox",
            sandbox_id="test-sandbox",
            workspace_dir="/workspace",
            branch="feature-x",
            repo_spec="org/repo",
            from_branch="main",
            allow_pr=False,
            repo_root="/path/to/worktree",
        )

        assert result.success is True
        assert result.wrapper_checksum == "sha256abc"
        assert result.error == ""
        mock_hmac.assert_called_once()
        mock_write_guest.assert_called_once_with("test-sandbox", "a" * 64)
        mock_write_host.assert_called_once_with("test-sandbox", "a" * 64)
        mock_register.assert_called_once()
        mock_inject.assert_called_once()
        # The helper writes git_safety_enabled=True
        mock_patch.assert_called_once()
        patch_kwargs = mock_patch.call_args[1]
        assert patch_kwargs["git_safety_enabled"] is True
        assert patch_kwargs["wrapper_checksum"] == "sha256abc"

    @patch("foundry_sandbox.git_safety.generate_hmac_secret", side_effect=OSError("rng failed"))
    def test_hmac_failure_returns_error(self, mock_hmac):
        from foundry_sandbox.git_safety import provision_git_safety

        result = provision_git_safety("test-sandbox", branch="main", repo_spec="org/repo")
        assert result.success is False
        assert "HMAC generation failed" in result.error

    def test_invalid_auth_id_fails_before_provisioning(self):
        from foundry_sandbox.git_safety import provision_git_safety

        result = provision_git_safety("x" * 65, branch="main", repo_spec="org/repo")
        assert result.success is False
        assert "Invalid git-safety sandbox id" in result.error

    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_sandbox", side_effect=OSError("sandbox not running"))
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="a" * 64)
    def test_guest_write_failure_returns_error(self, mock_hmac, mock_write):
        from foundry_sandbox.git_safety import provision_git_safety

        result = provision_git_safety("test-sandbox", branch="main", repo_spec="org/repo")
        assert result.success is False
        assert "Guest HMAC write failed" in result.error

    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server", side_effect=OSError("disk full"))
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_sandbox")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="a" * 64)
    def test_server_write_failure_returns_error(self, mock_hmac, mock_guest, mock_host):
        from foundry_sandbox.git_safety import provision_git_safety

        result = provision_git_safety("test-sandbox", branch="main", repo_spec="org/repo")
        assert result.success is False
        assert "Server HMAC write failed" in result.error

    @patch("foundry_sandbox.git_safety.register_sandbox_with_git_safety", side_effect=OSError("data dir missing"))
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_sandbox")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="a" * 64)
    def test_registration_failure_returns_error(self, mock_hmac, mock_guest, mock_host, mock_register):
        from foundry_sandbox.git_safety import provision_git_safety

        result = provision_git_safety("test-sandbox", branch="main", repo_spec="org/repo")
        assert result.success is False
        assert "registration failed" in result.error

    @patch("foundry_sandbox.git_safety.inject_git_wrapper", side_effect=OSError("inject failed"))
    @patch("foundry_sandbox.git_safety.register_sandbox_with_git_safety")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_sandbox")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="a" * 64)
    def test_injection_failure_returns_error(self, mock_hmac, mock_guest, mock_host, mock_register, mock_inject):
        from foundry_sandbox.git_safety import provision_git_safety

        result = provision_git_safety("test-sandbox", branch="main", repo_spec="org/repo")
        assert result.success is False
        assert "Wrapper injection failed" in result.error

    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", side_effect=FileNotFoundError("missing"))
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.register_sandbox_with_git_safety")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_sandbox")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="a" * 64)
    def test_checksum_failure_returns_error(self, mock_hmac, mock_guest, mock_host, mock_register, mock_inject, mock_checksum):
        from foundry_sandbox.git_safety import provision_git_safety

        result = provision_git_safety("test-sandbox", branch="main", repo_spec="org/repo")
        assert result.success is False
        assert "Checksum computation failed" in result.error

    @patch("foundry_sandbox.git_safety._verify_sandbox_connectivity")
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="sha256abc")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_sandbox")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="a" * 64)
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    def test_skips_registration_when_no_branch(
        self, mock_patch, mock_hmac, mock_guest, mock_host, mock_inject,
        mock_checksum, mock_connectivity,
    ):
        from foundry_sandbox.git_safety import provision_git_safety

        result = provision_git_safety(
            "test-sandbox",
            branch="",  # no branch → skip registration
            repo_spec="org/repo",
        )
        assert result.success is True

    @patch("foundry_sandbox.git_safety._verify_sandbox_connectivity")
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="sha256abc")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.register_sandbox_with_git_safety")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_sandbox")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="a" * 64)
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    def test_uses_sandbox_id_default(
        self, mock_patch, mock_hmac, mock_guest, mock_host, mock_register, mock_inject,
        mock_checksum, mock_connectivity,
    ):
        from foundry_sandbox.git_safety import provision_git_safety

        # sandbox_id defaults to sandbox_name
        result = provision_git_safety("my-sandbox", branch="main", repo_spec="org/repo")
        assert result.success is True
        mock_host.assert_called_once_with("my-sandbox", "a" * 64)

    @patch("foundry_sandbox.git_safety._verify_sandbox_connectivity", side_effect=RuntimeError("curl exited 7"))
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="sha256abc")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.register_sandbox_with_git_safety")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_sandbox")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="a" * 64)
    def test_connectivity_failure_returns_error(
        self, mock_hmac, mock_guest, mock_host, mock_register,
        mock_inject, mock_checksum, mock_connectivity,
    ):
        from foundry_sandbox.git_safety import provision_git_safety

        result = provision_git_safety(
            "test-sandbox", branch="main", repo_spec="org/repo",
        )
        assert result.success is False
        assert "connectivity" in result.error


class TestVerifySandboxConnectivity:
    """Tests for the _verify_sandbox_connectivity helper."""

    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_success_on_200(self, mock_exec):
        from foundry_sandbox.git_safety import _verify_sandbox_connectivity

        mock_exec.return_value = _mock_completed(stdout="200")
        # Should not raise
        _verify_sandbox_connectivity("test-sandbox")

    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_success_on_2xx(self, mock_exec):
        from foundry_sandbox.git_safety import _verify_sandbox_connectivity

        mock_exec.return_value = _mock_completed(stdout="204")
        _verify_sandbox_connectivity("test-sandbox")

    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_raises_on_curl_failure(self, mock_exec):
        from foundry_sandbox.git_safety import _verify_sandbox_connectivity

        mock_exec.return_value = _mock_completed(returncode=7)
        with pytest.raises(RuntimeError, match="curl exited 7"):
            _verify_sandbox_connectivity("test-sandbox")

    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_raises_on_non_2xx(self, mock_exec):
        from foundry_sandbox.git_safety import _verify_sandbox_connectivity

        mock_exec.return_value = _mock_completed(stdout="503")
        with pytest.raises(RuntimeError, match="HTTP 503"):
            _verify_sandbox_connectivity("test-sandbox")

    @patch("foundry_sandbox.sbx.sbx_exec")
    def test_uses_proxy_and_api_url(self, mock_exec):
        from foundry_sandbox.git_safety import _verify_sandbox_connectivity

        mock_exec.return_value = _mock_completed(stdout="200")
        _verify_sandbox_connectivity(
            "test-sandbox",
            api_host="myhost",
            api_port=9999,
            proxy="http://myproxy:1234",
        )
        cmd = mock_exec.call_args[0][1]
        assert "--proxy" in cmd
        assert "http://myproxy:1234" in cmd
        assert "http://myhost:9999/health" in cmd


class TestRepairGitSafety:
    """Tests for the repair_git_safety helper."""

    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="sha256new")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    def test_basic_repair_success(self, mock_inject, mock_checksum, mock_patch):
        from foundry_sandbox.git_safety import repair_git_safety

        result = repair_git_safety("test-sandbox", sandbox_id="test-sandbox")
        assert result.success is True
        assert result.wrapper_checksum == "sha256new"
        mock_inject.assert_called_once()
        # Repair does NOT set git_safety_enabled
        patch_kwargs = mock_patch.call_args[1]
        assert "git_safety_enabled" not in patch_kwargs

    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper", side_effect=OSError("inject failed"))
    def test_repair_failure_returns_error(self, mock_inject, mock_patch):
        from foundry_sandbox.git_safety import repair_git_safety

        result = repair_git_safety("test-sandbox")
        assert result.success is False
        assert "re-injection failed" in result.error

    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_sandbox")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="new_secret")
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="sha256new")
    def test_repair_with_hmac_rotation(self, mock_checksum, mock_hmac, mock_guest, mock_host, mock_inject, mock_patch):
        from foundry_sandbox.git_safety import repair_git_safety

        result = repair_git_safety(
            "test-sandbox",
            sandbox_id="test-sandbox",
            rotate_hmac=True,
        )
        assert result.success is True
        mock_hmac.assert_called_once()
        mock_guest.assert_called_once()
        mock_host.assert_called_once()

    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_sandbox", side_effect=OSError("sandbox not running"))
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="new_secret")
    def test_repair_rotation_failure_returns_error(self, mock_hmac, mock_guest):
        from foundry_sandbox.git_safety import repair_git_safety

        result = repair_git_safety("test-sandbox", rotate_hmac=True)
        assert result.success is False
        assert "HMAC rotation failed" in result.error

    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", side_effect=FileNotFoundError("missing"))
    def test_repair_uses_expected_checksum_on_compute_failure(self, mock_checksum, mock_inject, mock_patch):
        from foundry_sandbox.git_safety import repair_git_safety

        result = repair_git_safety(
            "test-sandbox",
            expected_checksum="provided_checksum",
        )
        assert result.success is True
        assert result.wrapper_checksum == "provided_checksum"

    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="computed_checksum")
    def test_repair_uses_computed_checksum_when_no_expected(self, mock_checksum, mock_inject, mock_patch):
        from foundry_sandbox.git_safety import repair_git_safety

        result = repair_git_safety("test-sandbox")
        assert result.success is True
        assert result.wrapper_checksum == "computed_checksum"


class TestTemplateStaleness:
    """Tests for template digest staleness detection."""

    def test_stale_when_version_differs(self, tmp_path):
        from foundry_sandbox.git_safety import is_template_stale

        digest_file = tmp_path / ".foundry" / "template-image-digest"
        digest_file.parent.mkdir(parents=True)
        digest_file.write_text("0.5.0")

        with patch("foundry_sandbox.git_safety.Path.home", return_value=tmp_path):
            with patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.6.0"):
                assert is_template_stale() is True

    def test_not_stale_when_version_matches(self, tmp_path):
        from foundry_sandbox.git_safety import is_template_stale

        digest_file = tmp_path / ".foundry" / "template-image-digest"
        digest_file.parent.mkdir(parents=True)
        digest_file.write_text("0.6.0")

        with patch("foundry_sandbox.git_safety.Path.home", return_value=tmp_path):
            with patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.6.0"):
                assert is_template_stale() is False

    def test_not_stale_when_no_digest_file(self, tmp_path):
        from foundry_sandbox.git_safety import is_template_stale

        with patch("foundry_sandbox.git_safety.Path.home", return_value=tmp_path):
            with patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.6.0"):
                assert is_template_stale() is False


class TestEmitWrapperTamperEvent:
    """Tests for metric-only tamper event delivery."""

    @patch("urllib.request.urlopen")
    def test_posts_to_server_endpoint(self, mock_urlopen):
        import foundry_sandbox.git_safety as gs
        from foundry_sandbox.git_safety import emit_wrapper_tamper_event

        # Reset fallback counter
        gs._tamper_event_fallback_count = 0

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        emit_wrapper_tamper_event(
            sandbox="sbx-1",
            expected_sha256="abc123",
            actual_sha256="def456",
            action="reinjected",
        )

        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.full_url == "http://127.0.0.1:8083/tamper-event"
        assert req.method == "POST"
        assert gs._tamper_event_fallback_count == 0

    @patch("foundry_sandbox.git_safety.log_warn")
    @patch("foundry_git_safety.decision_log.write_decision")
    @patch("urllib.request.urlopen", side_effect=OSError("Connection refused"))
    def test_fallback_on_server_unreachable(self, mock_urlopen, mock_write, mock_warn):
        import foundry_sandbox.git_safety as gs
        from foundry_sandbox.git_safety import emit_wrapper_tamper_event

        gs._tamper_event_fallback_count = 0

        emit_wrapper_tamper_event(
            sandbox="sbx-1",
            expected_sha256="abc",
            actual_sha256="def",
            action="reinjected",
        )

        assert gs._tamper_event_fallback_count == 1
        mock_write.assert_called_once()
        # Should log warning about server unreachable
        assert any("unreachable" in str(c) for c in mock_warn.call_args_list)

    @patch("foundry_sandbox.git_safety.log_warn")
    @patch("foundry_git_safety.decision_log.write_decision", side_effect=OSError("log dir missing"))
    @patch("urllib.request.urlopen", side_effect=OSError("Connection refused"))
    def test_both_channels_fail_still_increments_counter(self, mock_urlopen, mock_write, mock_warn):
        import foundry_sandbox.git_safety as gs
        from foundry_sandbox.git_safety import emit_wrapper_tamper_event

        gs._tamper_event_fallback_count = 0

        # Should not raise despite both channels failing
        emit_wrapper_tamper_event(
            sandbox="sbx-1",
            expected_sha256="abc",
            actual_sha256="def",
            action="reinject_failed",
        )

        assert gs._tamper_event_fallback_count == 1
        # Should log about both failures
        warn_msgs = [str(c) for c in mock_warn.call_args_list]
        assert any("unreachable" in m for m in warn_msgs)
        assert any("fallback also failed" in m for m in warn_msgs)

    def test_get_tamper_event_fallback_count(self):
        import foundry_sandbox.git_safety as gs
        from foundry_sandbox.git_safety import get_tamper_event_fallback_count

        gs._tamper_event_fallback_count = 0
        assert get_tamper_event_fallback_count() == 0
        gs._tamper_event_fallback_count = 5
        assert get_tamper_event_fallback_count() == 5
        gs._tamper_event_fallback_count = 0
