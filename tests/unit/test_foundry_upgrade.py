"""Unit tests for foundry_sandbox.foundry_upgrade."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import click
import pytest

from foundry_sandbox.foundry_upgrade import (
    _get_installed_version,
    upgrade_foundry_mcp_prerelease,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_ok(stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr=stderr)


def _run_fail(stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=stderr)


PIP_SHOW_OUTPUT = """\
Name: foundry-mcp
Version: 1.2.0a3
Summary: Foundry MCP plugin
"""

_MOD = "foundry_sandbox.foundry_upgrade"


# ---------------------------------------------------------------------------
# _get_installed_version
# ---------------------------------------------------------------------------


class TestGetInstalledVersion:
    @patch(f"{_MOD}.subprocess.run", return_value=_run_ok(stdout=PIP_SHOW_OUTPUT))
    def test_parses_version(self, mock_run: MagicMock) -> None:
        assert _get_installed_version("ctr-1") == "1.2.0a3"

    @patch(f"{_MOD}.subprocess.run", return_value=_run_fail())
    def test_returns_empty_on_failure(self, mock_run: MagicMock) -> None:
        assert _get_installed_version("ctr-1") == ""

    @patch(f"{_MOD}.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=30))
    def test_returns_empty_on_timeout(self, mock_run: MagicMock) -> None:
        assert _get_installed_version("ctr-1") == ""

    @patch(f"{_MOD}.subprocess.run", return_value=_run_ok(stdout="Name: foundry-mcp\nSummary: no version line\n"))
    def test_returns_empty_when_no_version_line(self, mock_run: MagicMock) -> None:
        assert _get_installed_version("ctr-1") == ""


# ---------------------------------------------------------------------------
# upgrade_foundry_mcp_prerelease — successful paths
# ---------------------------------------------------------------------------


class TestUpgradeSuccess:
    @patch(f"{_MOD}._get_installed_version", return_value="1.2.0a3")
    @patch(f"{_MOD}.subprocess.run", return_value=_run_ok())
    def test_latest_prerelease(self, mock_run: MagicMock, mock_ver: MagicMock) -> None:
        result = upgrade_foundry_mcp_prerelease("ctr-1")
        assert result == "1.2.0a3"
        # First subprocess.run call is the pip install; subsequent calls are
        # from _enable_user_site_packages patching MCP config.
        cmd = mock_run.call_args_list[0][0][0]
        assert "foundry-mcp" in cmd
        assert not any("==" in arg for arg in cmd)

    @patch(f"{_MOD}._get_installed_version", return_value="1.2.0a3")
    @patch(f"{_MOD}.subprocess.run", return_value=_run_ok())
    def test_pinned_version(self, mock_run: MagicMock, mock_ver: MagicMock) -> None:
        result = upgrade_foundry_mcp_prerelease("ctr-1", pin_version="1.2.0a3")
        assert result == "1.2.0a3"
        cmd = mock_run.call_args_list[0][0][0]
        assert "foundry-mcp==1.2.0a3" in cmd


# ---------------------------------------------------------------------------
# upgrade_foundry_mcp_prerelease — failure paths (required=False)
# ---------------------------------------------------------------------------


class TestUpgradeSoftFailure:
    @patch(f"{_MOD}.subprocess.run", return_value=_run_fail(stderr="pip error"))
    def test_pip_failure_returns_empty(self, mock_run: MagicMock) -> None:
        result = upgrade_foundry_mcp_prerelease("ctr-1", required=False)
        assert result == ""

    @patch(f"{_MOD}.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=300))
    def test_timeout_returns_empty(self, mock_run: MagicMock) -> None:
        result = upgrade_foundry_mcp_prerelease("ctr-1", required=False)
        assert result == ""


# ---------------------------------------------------------------------------
# upgrade_foundry_mcp_prerelease — failure paths (required=True)
# ---------------------------------------------------------------------------


class TestUpgradeRequiredFailure:
    @patch(f"{_MOD}.subprocess.run", return_value=_run_fail(stderr="no matching distribution"))
    def test_pip_failure_raises(self, mock_run: MagicMock) -> None:
        with pytest.raises(click.ClickException, match="no matching distribution"):
            upgrade_foundry_mcp_prerelease("ctr-1", required=True)

    @patch(f"{_MOD}.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=300))
    def test_timeout_raises(self, mock_run: MagicMock) -> None:
        with pytest.raises(click.ClickException, match="timed out"):
            upgrade_foundry_mcp_prerelease("ctr-1", required=True)

    @patch(f"{_MOD}.subprocess.run", return_value=_run_fail(stderr=""))
    def test_empty_stderr_shows_unknown(self, mock_run: MagicMock) -> None:
        with pytest.raises(click.ClickException, match="unknown error"):
            upgrade_foundry_mcp_prerelease("ctr-1", required=True)
