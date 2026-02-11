"""Unit tests for foundry_sandbox.stub_manager.

Tests workspace docs installation, branch context injection, repo URL
cleaning, and marker idempotency checks.

All subprocess and file I/O calls are mocked so tests run without Docker.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.stub_manager import (
    inject_sandbox_branch_context,
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


# ---------------------------------------------------------------------------
# TestInjectSandboxBranchContext
# ---------------------------------------------------------------------------


class TestInjectSandboxBranchContext:
    """inject_sandbox_branch_context appends branch info to CLAUDE.md."""

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    def test_skips_when_no_branch(self, mock_run):
        """Must skip if branch is empty."""
        inject_sandbox_branch_context("c1", repo_url="org/repo", branch="", from_branch="main")
        mock_run.assert_not_called()

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    def test_skips_when_no_from_branch(self, mock_run):
        """Must skip if from_branch is empty."""
        inject_sandbox_branch_context("c1", repo_url="org/repo", branch="feat", from_branch="")
        mock_run.assert_not_called()

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    def test_skips_when_marker_present(self, mock_run):
        """When sandbox-context marker exists, no append."""
        mock_run.return_value = _completed(returncode=0)  # grep found marker

        inject_sandbox_branch_context("c1", branch="feat", from_branch="main")

        # Only grep should be called
        assert mock_run.call_count == 1

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    def test_appends_context_block(self, mock_run):
        """When no marker, touch + append context block."""
        mock_run.side_effect = [
            _completed(returncode=1),  # grep - not found
            _completed(returncode=0),  # touch
            _completed(returncode=0),  # append
        ]

        inject_sandbox_branch_context(
            "c1", repo_url="https://github.com/org/repo.git",
            branch="feat/thing", from_branch="main",
        )

        assert mock_run.call_count == 3

        # Check that the appended content contains branch info
        append_call = mock_run.call_args_list[2]
        input_text = append_call[1].get("input", "")
        assert "feat/thing" in input_text
        assert "main" in input_text
        assert "<sandbox-context>" in input_text

    @pytest.mark.parametrize("url,expected", [
        ("https://github.com/org/repo.git", "org/repo"),
        ("http://github.com/org/repo", "org/repo"),
        ("git@github.com:org/repo.git", "org/repo"),
        ("https://github.com/org/repo", "org/repo"),
    ])
    @patch("foundry_sandbox.stub_manager.subprocess.run")
    def test_cleans_repo_url(self, mock_run, url, expected):
        """Various repo URL formats are cleaned to owner/repo."""
        mock_run.side_effect = [
            _completed(returncode=1),  # grep
            _completed(returncode=0),  # touch
            _completed(returncode=0),  # append
        ]

        inject_sandbox_branch_context(
            "c1", repo_url=url, branch="feat", from_branch="main",
        )

        append_call = mock_run.call_args_list[2]
        input_text = append_call[1].get("input", "")
        assert expected in input_text

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    def test_no_repo_url_omits_repository_line(self, mock_run):
        """When repo_url is empty, Repository line is omitted."""
        mock_run.side_effect = [
            _completed(returncode=1),
            _completed(returncode=0),
            _completed(returncode=0),
        ]

        inject_sandbox_branch_context("c1", branch="feat", from_branch="main")

        append_call = mock_run.call_args_list[2]
        input_text = append_call[1].get("input", "")
        assert "Repository" not in input_text
        assert "feat" in input_text

    @patch("foundry_sandbox.stub_manager.subprocess.run")
    def test_includes_base_branch_in_pr_guidance(self, mock_run):
        """PR guidance references the from_branch."""
        mock_run.side_effect = [
            _completed(returncode=1),
            _completed(returncode=0),
            _completed(returncode=0),
        ]

        inject_sandbox_branch_context(
            "c1", branch="feat", from_branch="develop",
        )

        append_call = mock_run.call_args_list[2]
        input_text = append_call[1].get("input", "")
        assert "target `develop` as the base branch" in input_text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
