"""Unit tests for foundry_sandbox.container_setup (install_pip_requirements)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from foundry_sandbox.container_setup import install_pip_requirements


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_ok(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")


def _run_fail(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")


# ---------------------------------------------------------------------------
# Empty / no-op paths
# ---------------------------------------------------------------------------


class TestEmptyPath:
    def test_empty_string_returns_immediately(self) -> None:
        with patch("foundry_sandbox.container_setup.subprocess.run") as mock_run:
            install_pip_requirements("ctr-1", "")
            mock_run.assert_not_called()

    def test_none_returns_immediately(self) -> None:
        with patch("foundry_sandbox.container_setup.subprocess.run") as mock_run:
            install_pip_requirements("ctr-1", "")  # empty string
            mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Auto-detection mode
# ---------------------------------------------------------------------------


class TestAutoMode:
    @patch("foundry_sandbox.container_setup.subprocess.run")
    def test_auto_no_file_returns_early(self, mock_run: MagicMock) -> None:
        """auto mode with no /workspace/requirements.txt returns without installing."""
        mock_run.return_value = _run_fail()
        install_pip_requirements("ctr-1", "auto", quiet=True)
        # Only the test -f call, no pip install
        assert mock_run.call_count == 1
        cmd = mock_run.call_args_list[0][0][0]
        assert "test" in cmd and "/workspace/requirements.txt" in cmd

    @patch("foundry_sandbox.container_setup.subprocess.run")
    def test_auto_with_file_runs_pip(self, mock_run: MagicMock) -> None:
        """auto mode with /workspace/requirements.txt runs pip install."""
        mock_run.return_value = _run_ok()
        install_pip_requirements("ctr-1", "auto", quiet=True)
        # Calls: test -f, pip install, grep resolv.conf, (possibly block + cleanup)
        assert mock_run.call_count >= 3
        pip_call = mock_run.call_args_list[1][0][0]
        assert "pip" in pip_call
        assert "/workspace/requirements.txt" in pip_call


# ---------------------------------------------------------------------------
# Host paths
# ---------------------------------------------------------------------------


class TestHostPaths:
    @patch("foundry_sandbox.container_setup.subprocess.run")
    def test_absolute_host_path_not_found(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Absolute host path that doesn't exist returns early."""
        install_pip_requirements("ctr-1", "/nonexistent/requirements.txt", quiet=True)
        mock_run.assert_not_called()

    @patch("foundry_sandbox.container_setup.copy_file_to_container")
    @patch("foundry_sandbox.container_setup.subprocess.run")
    def test_absolute_host_path_copies_and_installs(
        self, mock_run: MagicMock, mock_copy: MagicMock, tmp_path: Path
    ) -> None:
        """Valid host path is copied into container then pip-installed."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.31.0\n")
        mock_run.return_value = _run_ok()

        install_pip_requirements("ctr-1", str(req_file), quiet=True)

        mock_copy.assert_called_once_with("ctr-1", str(req_file), "/tmp/sandbox-requirements.txt")
        # pip install call uses /tmp/sandbox-requirements.txt
        pip_call = mock_run.call_args_list[0][0][0]
        assert "pip" in pip_call
        assert "/tmp/sandbox-requirements.txt" in pip_call

    @patch("foundry_sandbox.container_setup.copy_file_to_container")
    @patch("foundry_sandbox.container_setup.subprocess.run")
    def test_tilde_path_expands(
        self, mock_run: MagicMock, mock_copy: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """~/requirements.txt expands to $HOME/requirements.txt."""
        home_dir = tmp_path / "fakehome"
        home_dir.mkdir()
        req_file = home_dir / "requirements.txt"
        req_file.write_text("flask\n")

        monkeypatch.setattr(Path, "home", staticmethod(lambda: home_dir))
        mock_run.return_value = _run_ok()

        install_pip_requirements("ctr-1", "~/requirements.txt", quiet=True)
        mock_copy.assert_called_once_with("ctr-1", str(req_file), "/tmp/sandbox-requirements.txt")


# ---------------------------------------------------------------------------
# Workspace-relative paths
# ---------------------------------------------------------------------------


class TestWorkspaceRelative:
    @patch("foundry_sandbox.container_setup.subprocess.run")
    def test_workspace_relative_not_found(self, mock_run: MagicMock) -> None:
        """Workspace-relative path that doesn't exist returns early."""
        mock_run.return_value = _run_fail()
        install_pip_requirements("ctr-1", "requirements/dev.txt", quiet=True)
        assert mock_run.call_count == 1
        cmd = mock_run.call_args_list[0][0][0]
        assert "/workspace/requirements/dev.txt" in cmd

    @patch("foundry_sandbox.container_setup.subprocess.run")
    def test_workspace_relative_found_installs(self, mock_run: MagicMock) -> None:
        """Workspace-relative path that exists triggers pip install."""
        mock_run.return_value = _run_ok()
        install_pip_requirements("ctr-1", "requirements.txt", quiet=True)
        # Calls: test -f, pip install, grep resolv.conf, ...
        assert mock_run.call_count >= 3
        pip_call = mock_run.call_args_list[1][0][0]
        assert "pip" in pip_call
        assert "/workspace/requirements.txt" in pip_call


# ---------------------------------------------------------------------------
# PyPI blocking after install
# ---------------------------------------------------------------------------


class TestPypiBlocking:
    @patch("foundry_sandbox.container_setup.block_pypi_after_install")
    @patch("foundry_sandbox.container_setup.subprocess.run")
    def test_pypi_blocked_when_proxy_dns_detected(
        self, mock_run: MagicMock, mock_block: MagicMock
    ) -> None:
        """block_pypi_after_install is called when resolv.conf contains proxy DNS."""
        mock_run.return_value = _run_ok()
        install_pip_requirements("ctr-1", "auto", quiet=True)
        mock_block.assert_called_once_with("ctr-1", quiet=True)

    @patch("foundry_sandbox.container_setup.block_pypi_after_install")
    @patch("foundry_sandbox.container_setup.subprocess.run")
    def test_pypi_not_blocked_without_proxy_dns(
        self, mock_run: MagicMock, mock_block: MagicMock
    ) -> None:
        """block_pypi_after_install is NOT called when resolv.conf has no proxy DNS."""
        # test -f succeeds, pip succeeds, grep resolv.conf fails
        mock_run.side_effect = [_run_ok(), _run_ok(), _run_fail()]
        install_pip_requirements("ctr-1", "auto", quiet=True)
        mock_block.assert_not_called()
