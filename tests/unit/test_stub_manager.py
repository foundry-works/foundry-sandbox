"""Unit tests for foundry_sandbox.stub_manager.

Tests workspace docs installation and marker idempotency checks.

All subprocess and file I/O calls are mocked so tests run without Docker.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.stub_manager import (
    install_foundry_workspace_docs,
)


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
# TestInstallFoundryWorkspaceDocs
# ---------------------------------------------------------------------------


class TestInstallFoundryWorkspaceDocs:
    """install_foundry_workspace_docs appends stubs to container workspace."""

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    @patch("foundry_sandbox.stub_manager.os.path.isfile")
    @patch("foundry_sandbox.stub_manager.get_sandbox_home")
    def test_skips_when_marker_already_present(self, mock_home, mock_isfile, mock_run, tmp_path):
        """When foundry-instructions marker exists, no append happens."""
        mock_home.return_value = tmp_path
        stubs_dir = tmp_path / "stubs"
        stubs_dir.mkdir()
        (stubs_dir / "CLAUDE.md").write_text("# Stub content")
        (stubs_dir / "AGENTS.md").write_text("# Agents content")

        mock_isfile.return_value = True
        # grep returns 0 = marker found for both files
        mock_run.return_value = _completed(returncode=0)

        install_foundry_workspace_docs("c1")

        # Only the grep checks should run (one per stub file), no touch/append
        assert mock_run.call_count == 2
        for c in mock_run.call_args_list:
            cmd = c[0][0]
            assert "grep" in cmd

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    @patch("foundry_sandbox.stub_manager.os.path.isfile")
    @patch("foundry_sandbox.stub_manager.get_sandbox_home")
    def test_appends_when_marker_not_present(self, mock_home, mock_isfile, mock_run, tmp_path):
        """When no marker, touch + append should happen for each stub file."""
        mock_home.return_value = tmp_path
        stubs_dir = tmp_path / "stubs"
        stubs_dir.mkdir()
        (stubs_dir / "CLAUDE.md").write_text("# Stub content\n<foundry-instructions>")
        (stubs_dir / "AGENTS.md").write_text("# Agents content\n<foundry-instructions>")

        mock_isfile.return_value = True
        # Both files: grep not found, touch, append
        mock_run.side_effect = [
            _completed(returncode=1),  # grep CLAUDE.md - not found
            _completed(returncode=0),  # touch CLAUDE.md
            _completed(returncode=0),  # cat >> CLAUDE.md (append)
            _completed(returncode=1),  # grep AGENTS.md - not found
            _completed(returncode=0),  # touch AGENTS.md
            _completed(returncode=0),  # cat >> AGENTS.md (append)
        ]

        install_foundry_workspace_docs("c1")

        # Should have: (grep, touch, append) x 2
        assert mock_run.call_count == 6

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    @patch("foundry_sandbox.stub_manager.os.path.isfile")
    @patch("foundry_sandbox.stub_manager.get_sandbox_home")
    def test_skips_missing_stub_files(self, mock_home, mock_isfile, mock_run, tmp_path):
        """When stub file doesn't exist on host, skip it."""
        mock_home.return_value = tmp_path
        stubs_dir = tmp_path / "stubs"
        stubs_dir.mkdir()
        # Don't create CLAUDE.md or AGENTS.md

        mock_isfile.return_value = False

        install_foundry_workspace_docs("c1")

        # No subprocess calls should happen
        mock_run.assert_not_called()

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    @patch("foundry_sandbox.stub_manager.os.path.isfile")
    @patch("foundry_sandbox.stub_manager.get_sandbox_home")
    def test_processes_both_stub_files(self, mock_home, mock_isfile, mock_run, tmp_path):
        """Both CLAUDE.md and AGENTS.md are processed."""
        mock_home.return_value = tmp_path
        stubs_dir = tmp_path / "stubs"
        stubs_dir.mkdir()
        (stubs_dir / "CLAUDE.md").write_text("# Claude")
        (stubs_dir / "AGENTS.md").write_text("# Agents")

        mock_isfile.return_value = True
        # Both greps say marker not found
        mock_run.side_effect = [
            _completed(returncode=1),  # grep CLAUDE.md
            _completed(returncode=0),  # touch CLAUDE.md
            _completed(returncode=0),  # append CLAUDE.md
            _completed(returncode=1),  # grep AGENTS.md
            _completed(returncode=0),  # touch AGENTS.md
            _completed(returncode=0),  # append AGENTS.md
        ]

        install_foundry_workspace_docs("c1")

        assert mock_run.call_count == 6


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
