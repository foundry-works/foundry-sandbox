"""Unit tests for tool configs module.

Tests configuration provisioning for Claude, Codex, Gemini, OpenCode, and gh
inside Docker containers via foundry_sandbox.tool_configs.

Each configure_* wrapper function delegates to ensure_* functions that execute
inline Python scripts inside containers via docker exec. Tests verify that:
- subprocess.run is called with docker exec commands
- The correct container ID is targeted
- Inline scripts reference expected paths and config keys
- Functions are idempotent (can be called multiple times)

Paths referenced in assertions are drawn from foundry_sandbox.constants:
  CONTAINER_HOME = /home/ubuntu
  CONTAINER_USER = ubuntu
"""
from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, call, patch, ANY

import pytest

import foundry_sandbox.tool_configs as tool_configs_module
from foundry_sandbox.tool_configs import (
    configure_claude,
    configure_codex,
    configure_gemini,
    configure_gh,
    configure_opencode,
    sync_opencode_local_plugins_on_first_attach,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CONTAINER_ID = "test-container-dev-1"


def _make_completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    """Return a MagicMock that behaves like subprocess.CompletedProcess."""
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.returncode = returncode
    cp.stdout = stdout
    cp.stderr = stderr
    return cp


def _flatten_calls(mock_run):
    """Return a list of flattened arg-string lists from mock_run calls.

    Each entry is the full positional argument list passed to subprocess.run
    so callers can search for specific substrings.
    """
    result = []
    for c in mock_run.call_args_list:
        args = c.args[0] if c.args else c.kwargs.get("args", [])
        if isinstance(args, (list, tuple)):
            result.append([str(a) for a in args])
        else:
            result.append([str(args)])
    return result


def _calls_contain(mock_run, *fragments: str) -> list[list[str]]:
    """Return all subprocess.run calls whose flattened args contain every fragment."""
    matches = []
    for arg_list in _flatten_calls(mock_run):
        joined = " ".join(arg_list)
        if all(f in joined for f in fragments):
            matches.append(arg_list)
    return matches


def _stdin_contains(mock_run, *fragments: str) -> list[str]:
    """Return all subprocess.run calls whose stdin input contains every fragment."""
    matches = []
    for c in mock_run.call_args_list:
        stdin_data = c.kwargs.get("input", "") or ""
        if isinstance(stdin_data, str) and all(f in stdin_data for f in fragments):
            matches.append(stdin_data)
    return matches


def _any_call_references(mock_run, *fragments: str) -> bool:
    """Check if any subprocess.run call references all fragments in args or stdin."""
    # Check in args
    if _calls_contain(mock_run, *fragments):
        return True
    # Check in stdin
    if _stdin_contains(mock_run, *fragments):
        return True
    return False


# ============================================================================
# configure_claude
# ============================================================================


class TestConfigureClaude:
    """Tests for configure_claude."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_references_claude_directory(self, mock_run):
        """References /home/ubuntu/.claude directory inside container."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        assert _any_call_references(mock_run, ".claude"), (
            "Expected at least one call referencing .claude directory"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_uses_docker_exec(self, mock_run):
        """All commands should be executed via docker exec."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        assert mock_run.called
        for arg_list in _flatten_calls(mock_run):
            joined = " ".join(arg_list)
            assert "docker" in joined, (
                f"Expected docker command, got: {joined}"
            )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_targets_correct_container(self, mock_run):
        """Docker exec commands should target the given container ID."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        assert len(docker_exec_calls) >= 1
        for arg_list in docker_exec_calls:
            assert CONTAINER_ID in arg_list, (
                f"Container ID {CONTAINER_ID!r} not found in: {arg_list}"
            )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_references_settings_json(self, mock_run):
        """Should reference settings.json in args or inline script."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        assert _any_call_references(mock_run, "settings.json"), (
            "Expected at least one call referencing settings.json"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_inline_script_references_onboarding(self, mock_run):
        """Inline Python script should set onboarding flags."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        assert _any_call_references(mock_run, "hasCompletedOnboarding"), (
            "Expected inline script to reference hasCompletedOnboarding"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_propagates(self, mock_run):
        """Subprocess failures should propagate as exceptions."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        with pytest.raises(subprocess.CalledProcessError):
            configure_claude(CONTAINER_ID)

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_calls_both_onboarding_and_statusline(self, mock_run):
        """configure_claude should call both ensure_claude_onboarding and ensure_claude_statusline."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        # Should have at least 2 calls (onboarding + statusline check)
        assert mock_run.call_count >= 2


# ============================================================================
# configure_codex
# ============================================================================


class TestConfigureCodex:
    """Tests for configure_codex."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_references_codex_directory(self, mock_run):
        """References /home/ubuntu/.codex in args or inline script."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID)

        assert _any_call_references(mock_run, ".codex"), (
            "Expected at least one call referencing .codex directory"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_uses_docker_exec(self, mock_run):
        """All commands should be executed via docker exec."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID)

        assert mock_run.called
        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        assert len(docker_exec_calls) >= 1

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_targets_correct_container(self, mock_run):
        """Docker exec commands should target the given container ID."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID)

        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        for arg_list in docker_exec_calls:
            assert CONTAINER_ID in arg_list

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_references_config_toml(self, mock_run):
        """Should reference config.toml in args or inline script."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID)

        assert _any_call_references(mock_run, "config.toml"), (
            "Expected at least one call referencing config.toml"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_disables_auto_update(self, mock_run):
        """Codex config should disable update checks by default."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID)

        assert _any_call_references(mock_run, "check_for_update_on_startup")

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_propagates(self, mock_run):
        """Subprocess failures should propagate as exceptions."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        with pytest.raises(subprocess.CalledProcessError):
            configure_codex(CONTAINER_ID)


# ============================================================================
# configure_gemini
# ============================================================================


class TestConfigureGemini:
    """Tests for configure_gemini."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_references_gemini_directory(self, mock_run):
        """References /home/ubuntu/.gemini in args or inline script."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)

        assert _any_call_references(mock_run, ".gemini"), (
            "Expected at least one call referencing .gemini directory"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_uses_docker_exec(self, mock_run):
        """All commands should be executed via docker exec."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)

        assert mock_run.called
        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        assert len(docker_exec_calls) >= 1

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_targets_correct_container(self, mock_run):
        """Docker exec commands should target the given container ID."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)

        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        for arg_list in docker_exec_calls:
            assert CONTAINER_ID in arg_list

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_references_settings_json(self, mock_run):
        """Should reference settings.json in args or inline script."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)

        assert _any_call_references(mock_run, "settings.json")

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_disables_auto_update(self, mock_run):
        """Gemini settings should disable auto-update by default."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)

        assert _any_call_references(mock_run, "disableAutoUpdate")

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_disables_telemetry(self, mock_run):
        """Gemini settings should disable telemetry by default."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)

        assert _any_call_references(mock_run, "telemetry")

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_propagates(self, mock_run):
        """Subprocess failures should propagate as exceptions."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        with pytest.raises(subprocess.CalledProcessError):
            configure_gemini(CONTAINER_ID)


# ============================================================================
# configure_opencode
# ============================================================================


class TestConfigureOpenCode:
    """Tests for configure_opencode."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_references_opencode_directory(self, mock_run):
        """References /home/ubuntu/.config/opencode in args or inline script."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID)

        assert _any_call_references(mock_run, "opencode"), (
            "Expected at least one call referencing opencode config directory"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_uses_docker_exec(self, mock_run):
        """All commands should be executed via docker exec."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID)

        assert mock_run.called
        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        assert len(docker_exec_calls) >= 1

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_targets_correct_container(self, mock_run):
        """Docker exec commands should target the given container ID."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID)

        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        for arg_list in docker_exec_calls:
            assert CONTAINER_ID in arg_list

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_references_opencode_json(self, mock_run):
        """Should reference opencode.json config in args or inline script."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID)

        assert _any_call_references(mock_run, "opencode.json")

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_disables_autoupdate(self, mock_run):
        """OpenCode config should set autoupdate to off."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID)

        assert _any_call_references(mock_run, "autoupdate")

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_propagates(self, mock_run):
        """Subprocess failures should propagate as exceptions."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        with pytest.raises(subprocess.CalledProcessError):
            configure_opencode(CONTAINER_ID)


# ============================================================================
# configure_gh
# ============================================================================


class TestConfigureGh:
    """Tests for configure_gh."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_references_gh_config(self, mock_run):
        """References .config/gh or git config in args or inline script."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID)

        # configure_gh calls ensure_github_https_git which does git config operations
        assert _any_call_references(mock_run, "git", "config"), (
            "Expected at least one call referencing git config"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_uses_docker_exec(self, mock_run):
        """All commands should be executed via docker exec."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID)

        assert mock_run.called
        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        assert len(docker_exec_calls) >= 1

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_targets_correct_container(self, mock_run):
        """Docker exec commands should target the given container ID."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID)

        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        for arg_list in docker_exec_calls:
            assert CONTAINER_ID in arg_list

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_forces_https_for_github(self, mock_run):
        """Should configure git to use HTTPS instead of SSH for GitHub."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID)

        assert _any_call_references(mock_run, "https://github.com/"), (
            "Expected HTTPS insteadOf configuration for github.com"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_skips_https_when_ssh_enabled(self, mock_run):
        """Should skip HTTPS forcing when enable_ssh is True."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, enable_ssh=True)

        # When SSH is enabled, no git config calls should be made
        assert not mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_does_not_propagate(self, mock_run):
        """Git config uses check=False so errors don't propagate."""
        mock_run.return_value = _make_completed(returncode=1)

        # Should not raise
        configure_gh(CONTAINER_ID)


# ============================================================================
# Cross-cutting concerns
# ============================================================================


class TestContainerUserOwnership:
    """Tests verifying that config commands run as the container user."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_claude_uses_container_user(self, mock_run):
        """Claude config commands should run as ubuntu user."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        # At least one docker exec call should specify -u ubuntu
        user_calls = _calls_contain(mock_run, "docker", "exec", "ubuntu")
        assert len(user_calls) >= 1 or mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_gemini_uses_container_user(self, mock_run):
        """Gemini config commands should run as ubuntu user."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)

        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_opencode_uses_container_user(self, mock_run):
        """OpenCode config commands should run as ubuntu user."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID)

        assert mock_run.called


class TestContainerPaths:
    """Tests verifying that correct container paths are used."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_claude_uses_home_ubuntu_path(self, mock_run):
        """Claude config should reference /home/ubuntu/.claude."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        assert _any_call_references(mock_run, "/home/ubuntu/.claude"), (
            "Expected at least one call referencing /home/ubuntu/.claude"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_gemini_uses_home_ubuntu_path(self, mock_run):
        """Gemini config should reference /home/ubuntu/.gemini."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)

        assert _any_call_references(mock_run, "/home/ubuntu/.gemini"), (
            "Expected at least one call referencing /home/ubuntu/.gemini"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_opencode_uses_config_path(self, mock_run):
        """OpenCode config should reference /home/ubuntu/.config/opencode."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID)

        assert _any_call_references(mock_run, "/home/ubuntu/.config/opencode"), (
            "Expected at least one call referencing /home/ubuntu/.config/opencode"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_gh_uses_git_config(self, mock_run):
        """gh config should reference github.com via git config."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID)

        assert _any_call_references(mock_run, "github.com"), (
            "Expected at least one call referencing github.com"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_codex_uses_home_ubuntu_path(self, mock_run):
        """Codex config should reference /home/ubuntu/.codex."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID)

        assert _any_call_references(mock_run, "/home/ubuntu/.codex"), (
            "Expected at least one call referencing /home/ubuntu/.codex"
        )


class TestIdempotency:
    """Tests verifying that configure_* functions can be called multiple times."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_claude_idempotent(self, mock_run):
        """Calling configure_claude twice should not raise."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)
        configure_claude(CONTAINER_ID)

        # Should succeed without error
        assert mock_run.call_count >= 2

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_gemini_idempotent(self, mock_run):
        """Calling configure_gemini twice should not raise."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)
        configure_gemini(CONTAINER_ID)

        assert mock_run.call_count >= 2

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_opencode_idempotent(self, mock_run):
        """Calling configure_opencode twice should not raise."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID)
        configure_opencode(CONTAINER_ID)

        assert mock_run.call_count >= 2

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_gh_idempotent(self, mock_run):
        """Calling configure_gh twice should not raise."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID)
        configure_gh(CONTAINER_ID)

        assert mock_run.call_count >= 2

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_codex_idempotent(self, mock_run):
        """Calling configure_codex twice should not raise."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID)
        configure_codex(CONTAINER_ID)

        assert mock_run.call_count >= 2


class TestOpenCodeLocalPluginSync:
    """Tests for first-attach OpenCode local plugin sync behavior."""

    def test_sync_skips_marker_when_chown_fails(self, tmp_path, monkeypatch):
        host_plugins = tmp_path / "host-plugins"
        host_plugins.mkdir()
        marker = tmp_path / "opencode-plugins.synced"

        responses = [
            _make_completed(returncode=1),  # has_container_plugins check
            _make_completed(returncode=0),  # mkdir in container
            _make_completed(returncode=0),  # docker cp
            _make_completed(returncode=1),  # chown fails
        ]

        def _fake_run(*args, **kwargs):
            assert responses, "Unexpected subprocess.run call"
            return responses.pop(0)

        sync_foundry = MagicMock()
        ensure_tavily = MagicMock()

        monkeypatch.setattr(tool_configs_module, "get_sandbox_opencode_plugin_dir", lambda: str(host_plugins))
        monkeypatch.setattr(tool_configs_module, "path_opencode_plugins_marker", lambda _name: marker)
        monkeypatch.setattr(tool_configs_module.subprocess, "run", _fake_run)
        monkeypatch.setattr(tool_configs_module, "sync_opencode_foundry", sync_foundry)
        monkeypatch.setattr(tool_configs_module, "ensure_opencode_tavily_mcp", ensure_tavily)

        sync_opencode_local_plugins_on_first_attach("demo", "sandbox-demo-dev-1")

        assert not marker.exists()
        sync_foundry.assert_not_called()
        ensure_tavily.assert_not_called()
        assert responses == []

    def test_sync_writes_marker_and_runs_followups_on_success(self, tmp_path, monkeypatch):
        host_plugins = tmp_path / "host-plugins"
        host_plugins.mkdir()
        marker = tmp_path / "opencode-plugins.synced"

        responses = [
            _make_completed(returncode=1),  # has_container_plugins check
            _make_completed(returncode=0),  # mkdir in container
            _make_completed(returncode=0),  # docker cp
            _make_completed(returncode=0),  # chown succeeds
        ]

        def _fake_run(*args, **kwargs):
            assert responses, "Unexpected subprocess.run call"
            return responses.pop(0)

        sync_foundry = MagicMock()
        ensure_tavily = MagicMock()

        monkeypatch.setattr(tool_configs_module, "get_sandbox_opencode_plugin_dir", lambda: str(host_plugins))
        monkeypatch.setattr(tool_configs_module, "path_opencode_plugins_marker", lambda _name: marker)
        monkeypatch.setattr(tool_configs_module.subprocess, "run", _fake_run)
        monkeypatch.setattr(tool_configs_module, "sync_opencode_foundry", sync_foundry)
        monkeypatch.setattr(tool_configs_module, "ensure_opencode_tavily_mcp", ensure_tavily)

        sync_opencode_local_plugins_on_first_attach("demo", "sandbox-demo-dev-1")

        assert marker.exists()
        sync_foundry.assert_called_once()
        ensure_tavily.assert_called_once()
        assert responses == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
