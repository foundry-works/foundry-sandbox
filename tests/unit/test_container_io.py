"""Unit tests for foundry_sandbox.container_io.

Tests blocked-path validation, tar feature detection, file/directory copy
command construction, retry logic, chmod mode handling, and docker exec helpers.

All subprocess calls are mocked so tests run without Docker.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from foundry_sandbox.container_io import (
    _CONTAINER_BLOCKED_PREFIXES,
    _build_tar_base_args,
    _tar_env,
    _validate_container_dst,
    copy_dir_to_container,
    copy_file_to_container,
    copy_file_to_container_quiet,
    copy_dir_to_container_quiet,
    docker_exec_json,
    docker_exec_text,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _completed(stdout="", stderr="", returncode=0):
    """Build a mock subprocess.CompletedProcess."""
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.stdout = stdout
    cp.stderr = stderr
    cp.returncode = returncode
    return cp


# ---------------------------------------------------------------------------
# TestValidateContainerDst
# ---------------------------------------------------------------------------


class TestValidateContainerDst:
    """_validate_container_dst must reject blocked system paths."""

    @pytest.mark.parametrize("blocked_path", [
        "/etc/passwd",
        "/etc/",
        "/proc/1/status",
        "/sys/class/net",
        "/dev/null",
        "/var/run/docker.sock",
        "/run/secrets",
        "/sbin/init",
        "/bin/sh",
        "/usr/sbin/nologin",
        "/usr/bin/env",
    ])
    def test_rejects_blocked_paths(self, blocked_path):
        with pytest.raises(ValueError, match="Refusing to copy to container system path"):
            _validate_container_dst(blocked_path)

    @pytest.mark.parametrize("allowed_path", [
        "/home/ubuntu/.config",
        "/workspace/project",
        "/tmp/scratch",
        "/opt/tools",
        "/home/ubuntu/.ssh/config",
    ])
    def test_allows_safe_paths(self, allowed_path):
        # Should not raise
        _validate_container_dst(allowed_path)

    def test_rejects_exact_prefix_without_trailing_slash(self):
        """e.g., '/etc' without trailing slash must still be blocked."""
        with pytest.raises(ValueError):
            _validate_container_dst("/etc")

    def test_all_prefixes_covered(self):
        """Every prefix in _CONTAINER_BLOCKED_PREFIXES must trigger rejection."""
        for prefix in _CONTAINER_BLOCKED_PREFIXES:
            with pytest.raises(ValueError):
                _validate_container_dst(prefix + "test")


# ---------------------------------------------------------------------------
# TestTarFeatureDetection
# ---------------------------------------------------------------------------


class TestTarFeatureDetection:
    """Tar feature detection functions."""

    def test_tar_supports_no_xattrs_true(self):
        from foundry_sandbox.container_io import _tar_supports_no_xattrs
        _tar_supports_no_xattrs.cache_clear()

        with patch("foundry_sandbox.container_io.subprocess.run",
                    return_value=_completed(returncode=0)):
            assert _tar_supports_no_xattrs() is True

        _tar_supports_no_xattrs.cache_clear()

    def test_tar_supports_no_xattrs_false(self):
        from foundry_sandbox.container_io import _tar_supports_no_xattrs
        _tar_supports_no_xattrs.cache_clear()

        with patch("foundry_sandbox.container_io.subprocess.run",
                    return_value=_completed(returncode=1)):
            assert _tar_supports_no_xattrs() is False

        _tar_supports_no_xattrs.cache_clear()

    def test_tar_supports_no_xattrs_oserror(self):
        from foundry_sandbox.container_io import _tar_supports_no_xattrs
        _tar_supports_no_xattrs.cache_clear()

        with patch("foundry_sandbox.container_io.subprocess.run",
                    side_effect=OSError("tar not found")):
            assert _tar_supports_no_xattrs() is False

        _tar_supports_no_xattrs.cache_clear()

    def test_tar_supports_transform_true(self):
        from foundry_sandbox.container_io import _tar_supports_transform
        _tar_supports_transform.cache_clear()

        with patch("foundry_sandbox.container_io.subprocess.run",
                    return_value=_completed(stdout="--transform supported")):
            assert _tar_supports_transform() is True

        _tar_supports_transform.cache_clear()

    def test_tar_supports_transform_false(self):
        from foundry_sandbox.container_io import _tar_supports_transform
        _tar_supports_transform.cache_clear()

        with patch("foundry_sandbox.container_io.subprocess.run",
                    return_value=_completed(stdout="no such option")):
            assert _tar_supports_transform() is False

        _tar_supports_transform.cache_clear()

    def test_tar_supports_transform_in_stderr(self):
        from foundry_sandbox.container_io import _tar_supports_transform
        _tar_supports_transform.cache_clear()

        with patch("foundry_sandbox.container_io.subprocess.run",
                    return_value=_completed(stdout="", stderr="--transform")):
            # stderr contains the flag info
            result = _tar_supports_transform()

        _tar_supports_transform.cache_clear()
        assert result is True


# ---------------------------------------------------------------------------
# TestBuildTarBaseArgs
# ---------------------------------------------------------------------------


class TestBuildTarBaseArgs:
    """_build_tar_base_args returns correct flags."""

    def test_includes_no_xattrs_when_supported(self):
        with patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=True):
            assert "--no-xattrs" in _build_tar_base_args()

    def test_empty_when_not_supported(self):
        with patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=False):
            assert _build_tar_base_args() == []


# ---------------------------------------------------------------------------
# TestTarEnv
# ---------------------------------------------------------------------------


class TestTarEnv:
    """_tar_env sets COPYFILE_DISABLE for macOS metadata suppression."""

    def test_sets_copyfile_disable(self):
        env = _tar_env()
        assert env["COPYFILE_DISABLE"] == "1"

    def test_preserves_existing_env(self, monkeypatch):
        monkeypatch.setenv("MY_VAR", "test_value")
        env = _tar_env()
        assert env["MY_VAR"] == "test_value"


# ---------------------------------------------------------------------------
# TestCopyFileToContainer
# ---------------------------------------------------------------------------


class TestCopyFileToContainer:
    """copy_file_to_container command construction and retry logic."""

    @patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=False)
    @patch("foundry_sandbox.container_io._tar_supports_transform", return_value=False)
    @patch("foundry_sandbox.container_io._pipe_tar_to_docker", return_value=0)
    @patch("foundry_sandbox.container_io.subprocess.run", return_value=_completed())
    def test_simple_copy_same_basename(self, mock_run, mock_pipe, _t, _x):
        """When src and dst basenames match, no rename needed."""
        result = copy_file_to_container(
            "container-1", "/host/file.txt", "/home/ubuntu/file.txt",
        )
        assert result is True
        mock_pipe.assert_called_once()

    @patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=False)
    @patch("foundry_sandbox.container_io._tar_supports_transform", return_value=True)
    @patch("foundry_sandbox.container_io._pipe_tar_to_docker", return_value=0)
    @patch("foundry_sandbox.container_io.subprocess.run", return_value=_completed())
    def test_rename_via_transform(self, mock_run, mock_pipe, _t, _x):
        """When basenames differ and --transform supported, uses transform."""
        result = copy_file_to_container(
            "container-1", "/host/src.txt", "/home/ubuntu/dst.txt",
        )
        assert result is True
        # Check that the tar command included --transform
        tar_cmd = mock_pipe.call_args[0][0]
        assert any("--transform" in arg for arg in tar_cmd)

    @patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=False)
    @patch("foundry_sandbox.container_io._tar_supports_transform", return_value=False)
    @patch("foundry_sandbox.container_io._pipe_tar_to_docker", return_value=0)
    @patch("foundry_sandbox.container_io.subprocess.run", return_value=_completed())
    def test_rename_fallback_mv(self, mock_run, mock_pipe, _t, _x):
        """When basenames differ and no --transform, uses tar + mv fallback."""
        result = copy_file_to_container(
            "container-1", "/host/src.txt", "/home/ubuntu/dst.txt",
        )
        assert result is True
        # Should have run mv command
        mv_calls = [
            c for c in mock_run.call_args_list
            if any("mv" in str(arg) for arg in (c[0][0] if c[0] else []))
        ]
        assert len(mv_calls) >= 1

    @patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=False)
    @patch("foundry_sandbox.container_io._tar_supports_transform", return_value=False)
    @patch("foundry_sandbox.container_io._pipe_tar_to_docker", return_value=1)
    @patch("foundry_sandbox.container_io.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.container_io.time.sleep")
    def test_retries_on_failure(self, mock_sleep, mock_run, mock_pipe, _t, _x):
        """Retries up to CONTAINER_READY_ATTEMPTS times on pipe failure."""
        result = copy_file_to_container(
            "container-1", "/host/file.txt", "/home/ubuntu/file.txt",
        )
        assert result is False
        # Should have retried (5 attempts = 4 sleeps)
        assert mock_sleep.call_count == 4
        assert mock_pipe.call_count == 5

    def test_rejects_blocked_dst(self):
        """Must raise ValueError for blocked destinations."""
        with pytest.raises(ValueError, match="Refusing to copy"):
            copy_file_to_container("container-1", "/host/file", "/etc/passwd")

    @patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=False)
    @patch("foundry_sandbox.container_io._tar_supports_transform", return_value=False)
    @patch("foundry_sandbox.container_io._pipe_tar_to_docker", return_value=0)
    @patch("foundry_sandbox.container_io.subprocess.run", return_value=_completed())
    def test_chmod_applied_after_copy(self, mock_run, mock_pipe, _t, _x):
        """When mode is set, chmod is applied immediately after copy."""
        result = copy_file_to_container(
            "container-1", "/host/key", "/home/ubuntu/.ssh/id_rsa",
            mode="0600",
        )
        assert result is True
        # Find the chmod call
        chmod_calls = [
            c for c in mock_run.call_args_list
            if any("chmod" in str(arg) for arg in (c[0][0] if c[0] else []))
        ]
        assert len(chmod_calls) >= 1
        chmod_cmd = chmod_calls[0][0][0]
        assert "0600" in chmod_cmd

    @patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=False)
    @patch("foundry_sandbox.container_io._tar_supports_transform", return_value=False)
    @patch("foundry_sandbox.container_io._pipe_tar_to_docker", return_value=0)
    @patch("foundry_sandbox.container_io.subprocess.run", return_value=_completed())
    def test_invalid_chmod_mode_raises(self, mock_run, mock_pipe, _t, _x):
        """Invalid chmod mode must raise ValueError."""
        with pytest.raises(ValueError, match="invalid chmod mode"):
            copy_file_to_container(
                "container-1", "/host/file", "/home/ubuntu/file",
                mode="abc",
            )

    @patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=False)
    @patch("foundry_sandbox.container_io._tar_supports_transform", return_value=False)
    @patch("foundry_sandbox.container_io._pipe_tar_to_docker", return_value=0)
    @patch("foundry_sandbox.container_io.subprocess.run", return_value=_completed())
    def test_mkdir_creates_parent_dir(self, mock_run, mock_pipe, _t, _x):
        """mkdir -p is called for the parent directory."""
        copy_file_to_container(
            "container-1", "/host/file.txt", "/home/ubuntu/deep/nested/file.txt",
        )
        mkdir_calls = [
            c for c in mock_run.call_args_list
            if "mkdir" in (c[0][0] if c[0] else [])
        ]
        assert len(mkdir_calls) >= 1


# ---------------------------------------------------------------------------
# TestCopyFileToContainerQuiet
# ---------------------------------------------------------------------------


class TestCopyFileToContainerQuiet:
    """Quiet variant delegates to copy_file_to_container with quiet=True."""

    @patch("foundry_sandbox.container_io.copy_file_to_container", return_value=True)
    def test_delegates_with_quiet(self, mock_copy):
        result = copy_file_to_container_quiet("c1", "/src", "/dst")
        assert result is True
        mock_copy.assert_called_once_with("c1", "/src", "/dst", quiet=True)


# ---------------------------------------------------------------------------
# TestCopyDirToContainer
# ---------------------------------------------------------------------------


class TestCopyDirToContainer:
    """copy_dir_to_container command construction."""

    @patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=False)
    @patch("foundry_sandbox.container_io._pipe_tar_to_docker", return_value=0)
    @patch("foundry_sandbox.container_io.subprocess.run", return_value=_completed())
    def test_simple_dir_copy(self, mock_run, mock_pipe, _x):
        result = copy_dir_to_container("c1", "/host/dir", "/home/ubuntu/dir")
        assert result is True
        mock_pipe.assert_called_once()

    @patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=False)
    @patch("foundry_sandbox.container_io._pipe_tar_to_docker", return_value=0)
    @patch("foundry_sandbox.container_io.subprocess.run", return_value=_completed())
    def test_excludes_passed_to_tar(self, mock_run, mock_pipe, _x):
        """Exclude patterns are passed as --exclude=<pattern> to tar."""
        copy_dir_to_container(
            "c1", "/host/dir", "/home/ubuntu/dir",
            excludes=["node_modules", ".git"],
        )
        tar_cmd = mock_pipe.call_args[0][0]
        assert "--exclude=node_modules" in tar_cmd
        assert "--exclude=.git" in tar_cmd

    @patch("foundry_sandbox.container_io._tar_supports_no_xattrs", return_value=False)
    @patch("foundry_sandbox.container_io._pipe_tar_to_docker", return_value=1)
    @patch("foundry_sandbox.container_io.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.container_io.time.sleep")
    def test_retries_on_failure(self, mock_sleep, mock_run, mock_pipe, _x):
        result = copy_dir_to_container("c1", "/host/dir", "/home/ubuntu/dir")
        assert result is False
        assert mock_pipe.call_count == 5

    def test_rejects_blocked_dst(self):
        with pytest.raises(ValueError, match="Refusing to copy"):
            copy_dir_to_container("c1", "/host/dir", "/etc/cron.d")


class TestCopyDirToContainerQuiet:
    """Quiet variant delegates with quiet=True."""

    @patch("foundry_sandbox.container_io.copy_dir_to_container", return_value=True)
    def test_delegates_with_quiet(self, mock_copy):
        result = copy_dir_to_container_quiet("c1", "/src", "/dst", ["*.pyc"])
        assert result is True
        mock_copy.assert_called_once_with("c1", "/src", "/dst", excludes=["*.pyc"], quiet=True)


# ---------------------------------------------------------------------------
# TestDockerExecJson
# ---------------------------------------------------------------------------


class TestDockerExecJson:
    """docker_exec_json parses JSON stdout from docker exec."""

    @patch("foundry_sandbox.container_io.subprocess.run")
    def test_parses_valid_json(self, mock_run):
        mock_run.return_value = _completed(stdout='{"key": "value"}')
        result = docker_exec_json("c1", "cat", "/file.json")
        assert result == {"key": "value"}

    @patch("foundry_sandbox.container_io.subprocess.run")
    def test_raises_on_invalid_json(self, mock_run):
        mock_run.return_value = _completed(stdout="not json")
        with pytest.raises(ValueError, match="not valid JSON"):
            docker_exec_json("c1", "cat", "/file.json")

    @patch("foundry_sandbox.container_io.subprocess.run")
    def test_passes_user_to_docker_exec(self, mock_run):
        mock_run.return_value = _completed(stdout='[]')
        docker_exec_json("c1", "ls", user="root")
        cmd = mock_run.call_args[0][0]
        assert cmd[2] == "-u"
        assert cmd[3] == "root"

    @patch("foundry_sandbox.container_io.subprocess.run")
    def test_raises_on_subprocess_failure(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, ["docker"])
        with pytest.raises(subprocess.CalledProcessError):
            docker_exec_json("c1", "false")


# ---------------------------------------------------------------------------
# TestDockerExecText
# ---------------------------------------------------------------------------


class TestDockerExecText:
    """docker_exec_text returns stripped stdout from docker exec."""

    @patch("foundry_sandbox.container_io.subprocess.run")
    def test_returns_stripped_output(self, mock_run):
        mock_run.return_value = _completed(stdout="  hello world  \n")
        result = docker_exec_text("c1", "echo", "hello world")
        assert result == "hello world"

    @patch("foundry_sandbox.container_io.subprocess.run")
    def test_passes_user_to_docker_exec(self, mock_run):
        mock_run.return_value = _completed(stdout="ok")
        docker_exec_text("c1", "whoami", user="root")
        cmd = mock_run.call_args[0][0]
        assert "-u" in cmd
        idx = cmd.index("-u")
        assert cmd[idx + 1] == "root"

    @patch("foundry_sandbox.container_io.subprocess.run")
    def test_raises_on_subprocess_failure(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, ["docker"])
        with pytest.raises(subprocess.CalledProcessError):
            docker_exec_text("c1", "false")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
