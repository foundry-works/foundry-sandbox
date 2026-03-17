"""Unit tests for foundry_sandbox.stub_manager.

Tests workspace stub installation.

All subprocess and file I/O calls are mocked so tests run without Docker.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.stub_manager import install_workspace_stubs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _completed(stdout="", stderr="", returncode=0):
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.stdout = stdout
    cp.stderr = stderr
    cp.returncode = returncode
    return cp


# ---------------------------------------------------------------------------
# TestInstallWorkspaceStubs
# ---------------------------------------------------------------------------


class TestInstallWorkspaceStubs:
    """install_workspace_stubs appends stubs to container workspace."""

    @patch("foundry_sandbox.stub_manager.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.stub_manager.get_sandbox_home")
    def test_skips_when_no_stub_files(self, mock_home, mock_run, tmp_path):
        """When no stub files are specified, nothing happens."""
        mock_home.return_value = tmp_path

        install_workspace_stubs("c1")

        mock_run.assert_not_called()

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    @patch("foundry_sandbox.stub_manager.get_sandbox_home")
    def test_installs_existing_stub_files(self, mock_home, mock_run, tmp_path):
        """Existing stub files are grep-checked, touched, and appended."""
        mock_home.return_value = tmp_path
        stubs_dir = tmp_path / "stubs"
        stubs_dir.mkdir()
        (stubs_dir / "CLAUDE.md").write_text("# Test stub")

        # grep returns 1 (marker not found) so installation proceeds
        mock_run.return_value = _completed(returncode=1)

        install_workspace_stubs("c1", ["CLAUDE.md"])

        # grep (idempotency check) + touch + cat >> = 3 calls
        assert mock_run.call_count == 3

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    @patch("foundry_sandbox.stub_manager.get_sandbox_home")
    def test_skips_already_installed_stub(self, mock_home, mock_run, tmp_path):
        """Stubs with existing markers are skipped (idempotency)."""
        mock_home.return_value = tmp_path
        stubs_dir = tmp_path / "stubs"
        stubs_dir.mkdir()
        (stubs_dir / "CLAUDE.md").write_text("# Test stub")

        # grep returns 0 (marker found) so installation is skipped
        mock_run.return_value = _completed(returncode=0)

        install_workspace_stubs("c1", ["CLAUDE.md"])

        # Only the grep check, no touch or append
        assert mock_run.call_count == 1

    @patch("foundry_sandbox.stub_manager.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.stub_manager.get_sandbox_home")
    def test_skips_empty_stub_files(self, mock_home, mock_run, tmp_path):
        """Empty stub files are skipped."""
        mock_home.return_value = tmp_path
        stubs_dir = tmp_path / "stubs"
        stubs_dir.mkdir()
        (stubs_dir / "EMPTY.md").write_text("   \n  ")

        install_workspace_stubs("c1", ["EMPTY.md"])

        mock_run.assert_not_called()

    @patch("foundry_sandbox.stub_manager.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.stub_manager.get_sandbox_home")
    def test_skips_missing_stub_files(self, mock_home, mock_run, tmp_path):
        """Missing stub files are silently skipped."""
        mock_home.return_value = tmp_path
        stubs_dir = tmp_path / "stubs"
        stubs_dir.mkdir()
        # Don't create the stub file

        install_workspace_stubs("c1", ["MISSING.md"])

        mock_run.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
