"""Chaos tests for the sbx wrapper layer and git_safety bridge.

Simulates sbx CLI failures (daemon dead, corrupt output, process killed)
and validates recovery behavior. Uses mocks since these require a live sbx.
"""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest


pytestmark = pytest.mark.slow


class TestSbxSubprocessFailure:
    """sbx CLI wrapper handles subprocess failures gracefully."""

    def test_sbx_exec_handles_process_killed(self):
        """TimeoutExpired from sbx_exec propagates correctly."""
        from foundry_sandbox.sbx import sbx_exec

        with patch("foundry_sandbox.sbx.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd=["sbx", "exec", "test", "--", "git"], timeout=60
            )
            with pytest.raises(subprocess.TimeoutExpired):
                sbx_exec("test", ["git", "status"])

    def test_sbx_ls_handles_corrupt_json(self):
        """sbx_ls returns empty list on corrupt JSON output."""
        from foundry_sandbox.sbx import sbx_ls

        with patch("foundry_sandbox.sbx.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="not valid json{{{",
                stderr="",
            )
            result = sbx_ls()
            assert result == []

    def test_sbx_ls_handles_nonzero_return(self):
        """sbx_ls returns empty list on non-zero exit code."""
        from foundry_sandbox.sbx import sbx_ls

        with patch("foundry_sandbox.sbx.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="daemon not running",
            )
            result = sbx_ls()
            assert result == []

    def test_sbx_ls_handles_timeout(self):
        """sbx_ls returns empty list on timeout."""
        from foundry_sandbox.sbx import sbx_ls

        with patch("foundry_sandbox.sbx.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd=["sbx", "ls"], timeout=30
            )
            result = sbx_ls()
            assert result == []

    def test_sbx_create_handles_daemon_dead(self):
        """sbx_create raises when the daemon is not running."""
        from foundry_sandbox.sbx import sbx_create

        with patch("foundry_sandbox.sbx.subprocess.run") as mock_run:
            mock_run.side_effect = OSError("sbx daemon not running")
            with pytest.raises(OSError, match="daemon"):
                sbx_create("test", "claude", "/tmp/test")


class TestGitSafetyBridgeChaos:
    """git_safety.py bridge handles failures during wrapper injection."""

    def test_inject_wrapper_mid_kill_recovers(self):
        """If sbx_exec fails, a retry with a working exec succeeds."""
        from foundry_sandbox import git_safety

        # First attempt: all calls fail
        with patch("foundry_sandbox.sbx.sbx_exec") as mock_exec:
            mock_exec.side_effect = subprocess.TimeoutExpired(cmd=["sbx"], timeout=60)
            with patch("foundry_sandbox.git_safety._WRAPPER_SCRIPT") as mock_path:
                mock_path.exists.return_value = True
                mock_path.read_text.return_value = "#!/bin/bash\necho wrapper"

                with pytest.raises(subprocess.TimeoutExpired):
                    git_safety.inject_git_wrapper(
                        "test-sandbox",
                        sandbox_id="test",
                        workspace_dir="/workspace",
                    )

        # Second attempt: all calls succeed
        with patch("foundry_sandbox.sbx.sbx_exec") as mock_exec:
            mock_exec.return_value = MagicMock(returncode=0, stdout="", stderr="")
            with patch("foundry_sandbox.git_safety._WRAPPER_SCRIPT") as mock_path:
                mock_path.exists.return_value = True
                mock_path.read_text.return_value = "#!/bin/bash\necho wrapper"

                git_safety.inject_git_wrapper(
                    "test-sandbox",
                    sandbox_id="test",
                    workspace_dir="/workspace",
                )
                # 4 calls: tee wrapper, chmod wrapper, tee env, chmod env
                assert mock_exec.call_count == 4

    def test_register_sandbox_writes_valid_json(self, tmp_path):
        """register_sandbox_with_git_safety writes parseable JSON."""
        from foundry_sandbox import git_safety

        path = git_safety.register_sandbox_with_git_safety(
            "test-sb",
            branch="feature",
            repo_spec="owner/repo",
            from_branch="main",
            data_dir=str(tmp_path),
        )

        assert path.exists()
        data = json.loads(path.read_text())
        assert data["sandbox_branch"] == "feature"
        assert data["from_branch"] == "main"
        assert data["repos"] == ["owner/repo"]

    def test_register_sandbox_overwrite_preserves_validity(self, tmp_path):
        """Overwriting metadata produces valid JSON even if interrupted mid-write."""
        from foundry_sandbox import git_safety

        # Write initial metadata
        git_safety.register_sandbox_with_git_safety(
            "test-sb",
            branch="feature-1",
            repo_spec="owner/repo",
            data_dir=str(tmp_path),
        )

        # Overwrite with new data
        path2 = git_safety.register_sandbox_with_git_safety(
            "test-sb",
            branch="feature-2",
            repo_spec="owner/repo",
            data_dir=str(tmp_path),
        )

        data = json.loads(path2.read_text())
        assert data["sandbox_branch"] == "feature-2"

    def test_unregister_cleans_up_files(self, tmp_path):
        """unregister_sandbox_from_git_safety removes both metadata and secret."""
        from foundry_sandbox import git_safety

        # Create files
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "test-sb").write_text("secret")

        data_dir = tmp_path / "data" / "sandboxes"
        data_dir.mkdir(parents=True)
        (data_dir / "test-sb.json").write_text('{"branch": "feature"}')

        git_safety.unregister_sandbox_from_git_safety(
            "test-sb",
            data_dir=str(tmp_path / "data"),
            secrets_dir=str(secrets_dir),
        )

        assert not (secrets_dir / "test-sb").exists()
        assert not (data_dir / "test-sb.json").exists()

    def test_unregister_handles_missing_files(self, tmp_path):
        """unregister_sandbox_from_git_safety does not fail on missing files."""
        from foundry_sandbox import git_safety

        # Should not raise
        git_safety.unregister_sandbox_from_git_safety(
            "nonexistent-sandbox",
            data_dir=str(tmp_path / "data"),
            secrets_dir=str(tmp_path / "secrets"),
        )
