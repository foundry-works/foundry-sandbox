"""Unit tests for foundry_sandbox.foundry_plugin.

Tests host-side prepopulation, container-side MCP configuration,
workspace directory creation, marketplace manifest synthesis, and
research provider configuration.

All subprocess, file I/O, and git calls are mocked so tests run without Docker.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.foundry_plugin import (
    DEFAULT_HOOKS,
    configure_foundry_research_providers,
    ensure_claude_foundry_mcp,
    ensure_foundry_mcp_config,
    ensure_foundry_mcp_workspace_dirs,
    prepopulate_foundry_global,
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
# TestDefaultHooks
# ---------------------------------------------------------------------------


class TestDefaultHooks:
    """DEFAULT_HOOKS must include security hooks."""

    def test_has_pre_tool_use(self):
        assert "PreToolUse" in DEFAULT_HOOKS

    def test_has_post_tool_use(self):
        assert "PostToolUse" in DEFAULT_HOOKS

    def test_pre_tool_use_has_read_blocker(self):
        matchers = [h["matcher"] for h in DEFAULT_HOOKS["PreToolUse"]]
        assert "Read" in matchers

    def test_pre_tool_use_has_bash_blocker(self):
        matchers = [h["matcher"] for h in DEFAULT_HOOKS["PreToolUse"]]
        assert "Bash" in matchers


# ---------------------------------------------------------------------------
# TestPrepopulateFoundryGlobal
# ---------------------------------------------------------------------------


class TestPrepopulateFoundryGlobal:
    """prepopulate_foundry_global clones/updates plugin repo and installs."""

    @patch("foundry_sandbox.foundry_plugin.write_json")
    @patch("foundry_sandbox.foundry_plugin.load_json", return_value={})
    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_clones_repo_when_cache_missing(self, mock_run, mock_load, mock_write, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_PLUGINS_CACHE", str(tmp_path / "cache"))

        claude_home = tmp_path / "claude"
        claude_home.mkdir()

        result = prepopulate_foundry_global(str(claude_home))

        # Should have called git clone
        clone_calls = [
            c for c in mock_run.call_args_list
            if "clone" in (c[0][0] if c[0] else [])
        ]
        assert len(clone_calls) >= 1
        assert result is True

    @patch("foundry_sandbox.foundry_plugin.write_json")
    @patch("foundry_sandbox.foundry_plugin.load_json", return_value={})
    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_pulls_when_cache_exists(self, mock_run, mock_load, mock_write, tmp_path, monkeypatch):
        cache_dir = tmp_path / "cache"
        foundry_cache = cache_dir / "claude-foundry"
        (foundry_cache / ".git").mkdir(parents=True)

        monkeypatch.setenv("CLAUDE_PLUGINS_CACHE", str(cache_dir))

        claude_home = tmp_path / "claude"
        claude_home.mkdir()

        prepopulate_foundry_global(str(claude_home))

        pull_calls = [
            c for c in mock_run.call_args_list
            if "pull" in (c[0][0] if c[0] else [])
        ]
        assert len(pull_calls) >= 1

    @patch("foundry_sandbox.foundry_plugin.write_json")
    @patch("foundry_sandbox.foundry_plugin.load_json", return_value={})
    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_skip_if_populated(self, mock_run, mock_load, mock_write, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_PLUGINS_CACHE", str(tmp_path / "cache"))

        claude_home = tmp_path / "claude"
        (claude_home / "skills" / "foundry-spec").mkdir(parents=True)

        result = prepopulate_foundry_global(str(claude_home), skip_if_populated=True)

        assert result is True
        mock_run.assert_not_called()

    @patch("foundry_sandbox.foundry_plugin.write_json")
    @patch("foundry_sandbox.foundry_plugin.load_json", return_value={})
    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_sets_model_defaults(self, mock_run, mock_load, mock_write, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_PLUGINS_CACHE", str(tmp_path / "cache"))

        claude_home = tmp_path / "claude"
        claude_home.mkdir()

        prepopulate_foundry_global(str(claude_home))

        # Check write_json was called with model defaults
        write_call = mock_write.call_args
        data = write_call[0][1]
        assert data["model"] == "opus"
        assert data["subagentModel"] == "haiku"
        assert data["alwaysThinkingEnabled"] is True

    @patch("foundry_sandbox.foundry_plugin.write_json")
    @patch("foundry_sandbox.foundry_plugin.load_json", return_value={})
    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_configures_hooks(self, mock_run, mock_load, mock_write, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_PLUGINS_CACHE", str(tmp_path / "cache"))

        claude_home = tmp_path / "claude"
        claude_home.mkdir()

        prepopulate_foundry_global(str(claude_home))

        write_call = mock_write.call_args
        data = write_call[0][1]
        assert data["hooks"] == DEFAULT_HOOKS

    @patch("foundry_sandbox.foundry_plugin.write_json")
    @patch("foundry_sandbox.foundry_plugin.load_json", return_value={})
    @patch("foundry_sandbox.foundry_plugin.subprocess.run")
    def test_returns_false_on_clone_failure(self, mock_run, mock_load, mock_write, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_PLUGINS_CACHE", str(tmp_path / "cache"))

        claude_home = tmp_path / "claude"
        claude_home.mkdir()

        mock_run.return_value = _completed(returncode=1)

        result = prepopulate_foundry_global(str(claude_home))
        assert result is False


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

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_passes_tavily_env_when_set(self, mock_run, monkeypatch):
        monkeypatch.setenv("SANDBOX_ENABLE_TAVILY", "1")
        ensure_foundry_mcp_config("c1")
        cmd = mock_run.call_args[0][0]
        assert "SANDBOX_ENABLE_TAVILY=1" in " ".join(cmd)


# ---------------------------------------------------------------------------
# TestEnsureFoundryMcpWorkspaceDirs
# ---------------------------------------------------------------------------


class TestEnsureFoundryMcpWorkspaceDirs:
    """ensure_foundry_mcp_workspace_dirs creates specs directories."""

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_creates_specs_dirs(self, mock_run):
        ensure_foundry_mcp_workspace_dirs("c1")

        # Should have mkdir, home dirs, and chown calls
        assert mock_run.call_count >= 3

        # Check that specs directories are created
        mkdir_call = mock_run.call_args_list[0]
        cmd = mkdir_call[0][0]
        assert "mkdir" in cmd
        dirs = [arg for arg in cmd if "specs" in arg]
        assert len(dirs) > 0

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_working_dir_prefix(self, mock_run):
        ensure_foundry_mcp_workspace_dirs("c1", working_dir="apps/api")

        mkdir_call = mock_run.call_args_list[0]
        cmd = mkdir_call[0][0]
        dirs = [arg for arg in cmd if "specs" in arg]
        # All dirs should be under /workspace/apps/api/specs/
        for d in dirs:
            assert d.startswith("/workspace/apps/api/specs/")

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_creates_home_foundry_dirs(self, mock_run):
        ensure_foundry_mcp_workspace_dirs("c1")

        home_dirs_call = mock_run.call_args_list[1]
        cmd = home_dirs_call[0][0]
        home_dirs = [arg for arg in cmd if ".foundry-mcp" in arg]
        assert len(home_dirs) > 0


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


# ---------------------------------------------------------------------------
# TestConfigureFoundryResearchProviders
# ---------------------------------------------------------------------------


class TestConfigureFoundryResearchProviders:
    """configure_foundry_research_providers updates TOML config."""

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_runs_python_in_container(self, mock_run):
        configure_foundry_research_providers("c1")
        cmd = mock_run.call_args[0][0]
        assert "python3" in cmd
        assert "-c" in cmd

    @patch("foundry_sandbox.foundry_plugin.subprocess.run", return_value=_completed())
    def test_suppresses_stderr(self, mock_run):
        configure_foundry_research_providers("c1")
        assert mock_run.call_args[1].get("stderr") == subprocess.DEVNULL


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
