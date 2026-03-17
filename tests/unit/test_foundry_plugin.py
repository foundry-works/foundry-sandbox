"""Unit tests for foundry_sandbox.foundry_plugin.

Tests container-side MCP configuration, marketplace manifest synthesis,
and backward-compatible wrapper functions.

All subprocess, file I/O, and git calls are mocked so tests run without Docker.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.foundry_plugin import (
    ensure_claude_foundry_mcp,
    ensure_foundry_mcp_config,
    sync_marketplace_manifests,
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
# TestEnsureClaudeFoundryMcp
# ---------------------------------------------------------------------------


class TestEnsureClaudeFoundryMcp:
    """ensure_claude_foundry_mcp runs Python script in container."""

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_runs_docker_exec_python(self, mock_run):
        ensure_claude_foundry_mcp("c1")

        # First call should be the main settings script
        cmd = mock_run.call_args_list[0][0][0]
        assert "docker" in cmd
        assert "exec" in cmd
        assert "python3" in cmd
        assert "-c" in cmd

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_quiet_mode_skips_pyright(self, mock_run):
        ensure_claude_foundry_mcp("c1", quiet=True)

        # Only one docker exec call (no pyright pre-bake)
        assert mock_run.call_count == 1

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_non_quiet_prebakes_pyright(self, mock_run):
        ensure_claude_foundry_mcp("c1", quiet=False)

        # Two docker exec calls: main settings + pyright
        assert mock_run.call_count == 2


# ---------------------------------------------------------------------------
# TestEnsureFoundryMcpConfig
# ---------------------------------------------------------------------------


class TestEnsureFoundryMcpConfig:
    """ensure_foundry_mcp_config registers MCP server in container."""

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_runs_python_in_container(self, mock_run):
        ensure_foundry_mcp_config("c1")
        cmd = mock_run.call_args[0][0]
        assert "python3" in cmd
        assert "-c" in cmd


# ---------------------------------------------------------------------------
# TestSyncMarketplaceManifests
# ---------------------------------------------------------------------------


class TestSyncMarketplaceManifests:
    """sync_marketplace_manifests runs Python + git in container."""

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_runs_python_and_git(self, mock_run):
        sync_marketplace_manifests("c1", "/home/ubuntu/.claude/plugins")

        # Two calls: python script + git commit
        assert mock_run.call_count == 2

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_quiet_suppresses_stderr(self, mock_run):
        sync_marketplace_manifests("c1", "/home/ubuntu/.claude/plugins", quiet=True)

        python_call = mock_run.call_args_list[0]
        assert python_call[1].get("stderr") == subprocess.DEVNULL


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
