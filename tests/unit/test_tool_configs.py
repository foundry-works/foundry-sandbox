"""Unit tests for tool configs module.

Tests configuration provisioning for Claude, Codex, Gemini, OpenCode, and gh
inside Docker containers via foundry_sandbox.tool_configs.

Each configure_* wrapper function delegates to ensure_* functions that execute
Python scripts (from lib/python/) inside containers via docker exec. Tests verify:
- Commands are structured as docker exec with correct user and container
- Script content references expected config paths and keys
- Errors propagate correctly
- Functions are idempotent
- Extracted script files are valid Python
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import foundry_sandbox.tool_configs as tool_configs_module
from foundry_sandbox.tool_configs import (
    _SCRIPT_DIR,
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


def _get_calls(mock_run):
    """Return (cmd, stdin) pairs from mock_run call history.

    Extracts the command list (first positional arg) and stdin input string
    from each subprocess.run invocation for structured assertions.
    """
    result = []
    for c in mock_run.call_args_list:
        cmd = c.args[0] if c.args else c.kwargs.get("args", [])
        stdin = c.kwargs.get("input", "") or ""
        result.append((cmd, stdin))
    return result


# ============================================================================
# Script file validity
# ============================================================================


class TestExtractedScriptValidity:
    """Verify that extracted Python scripts in lib/python/ are valid syntax."""

    @pytest.mark.parametrize("script_name", [
        "ensure_claude_onboarding.py",
        "ensure_codex_config.py",
        "ensure_gemini_settings.py",
        "ensure_opencode_settings.py",
        "ensure_opencode_default_model.py",
        "ensure_opencode_tavily.py",
        "prefetch_opencode_plugins.py",
    ])
    def test_script_compiles(self, script_name):
        """Each extracted script should be valid Python syntax."""
        script_path = _SCRIPT_DIR / script_name
        assert script_path.exists(), f"Script not found: {script_path}"
        source = script_path.read_text()
        compile(source, str(script_path), "exec")

    def test_statusline_script_compiles_with_action(self):
        """Statusline script requires _ACTION variable; compiles with it prepended."""
        script_path = _SCRIPT_DIR / "ensure_claude_statusline.py"
        source = script_path.read_text()
        for action in ("set", "remove"):
            compile(f'_ACTION = "{action}"\n' + source, str(script_path), "exec")

    def test_onboarding_script_references_expected_keys(self):
        """Onboarding script should set known config keys."""
        source = (_SCRIPT_DIR / "ensure_claude_onboarding.py").read_text()
        for key in ("hasCompletedOnboarding", "autoUpdates", "autoCompactEnabled"):
            assert key in source, f"Expected key {key!r} in onboarding script"

    def test_codex_script_references_config_path(self):
        """Codex script should reference ~/.codex/config.toml."""
        source = (_SCRIPT_DIR / "ensure_codex_config.py").read_text()
        assert "config.toml" in source
        assert "check_for_update_on_startup" in source

    def test_gemini_script_references_expected_keys(self):
        """Gemini script should reference auto-update and telemetry settings."""
        source = (_SCRIPT_DIR / "ensure_gemini_settings.py").read_text()
        assert "disableAutoUpdate" in source
        assert "telemetry" in source

    def test_opencode_script_references_autoupdate(self):
        """OpenCode settings script should disable autoupdate."""
        source = (_SCRIPT_DIR / "ensure_opencode_settings.py").read_text()
        assert "autoupdate" in source

    def test_script_dir_exists(self):
        """The _SCRIPT_DIR should point to an existing directory."""
        assert _SCRIPT_DIR.is_dir(), f"Script dir not found: {_SCRIPT_DIR}"


# ============================================================================
# configure_claude
# ============================================================================


class TestConfigureClaude:
    """Tests for configure_claude."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_docker_exec_command_structure(self, mock_run):
        """Commands should be docker exec targeting the correct container as ubuntu."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        calls = _get_calls(mock_run)
        assert len(calls) >= 2, "Expected at least 2 calls (onboarding + statusline check)"
        for cmd, _stdin in calls:
            assert cmd[0:2] == ["docker", "exec"], f"Expected docker exec, got: {cmd[:2]}"
            assert CONTAINER_ID in cmd, f"Container ID not in command: {cmd}"

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_onboarding_script_sent_as_stdin(self, mock_run):
        """Onboarding script content should be passed via stdin."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        calls = _get_calls(mock_run)
        # First call is onboarding (docker exec python3 with stdin)
        cmd, stdin = calls[0]
        assert "python3" in cmd, f"Expected python3 in command: {cmd}"
        assert "hasCompletedOnboarding" in stdin
        assert "/home/ubuntu/.claude.json" in stdin

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_statusline_check_references_settings(self, mock_run):
        """Statusline detection should check for settings.json in container."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        calls = _get_calls(mock_run)
        # Second call is statusline binary check (sh -c)
        all_args = " ".join(str(a) for cmd, _ in calls for a in cmd)
        assert "settings.json" in all_args or any(
            "settings.json" in stdin for _, stdin in calls
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_runs_as_container_user(self, mock_run):
        """Docker exec should specify -u ubuntu."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        calls = _get_calls(mock_run)
        cmd, _ = calls[0]
        assert "-u" in cmd
        u_idx = cmd.index("-u")
        assert cmd[u_idx + 1] == "ubuntu"

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_propagates(self, mock_run):
        """Subprocess failures should propagate as exceptions."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        with pytest.raises(subprocess.CalledProcessError):
            configure_claude(CONTAINER_ID)

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_calls_both_onboarding_and_statusline(self, mock_run):
        """configure_claude delegates to both ensure_claude_onboarding and ensure_claude_statusline."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID)

        assert mock_run.call_count >= 2


# ============================================================================
# configure_codex
# ============================================================================


class TestConfigureCodex:
    """Tests for configure_codex."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_docker_exec_command_structure(self, mock_run):
        """Commands should be docker exec targeting the correct container."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID)

        calls = _get_calls(mock_run)
        assert len(calls) >= 1
        cmd, stdin = calls[0]
        assert cmd[0:2] == ["docker", "exec"]
        assert CONTAINER_ID in cmd
        assert "-u" in cmd

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_script_references_codex_config(self, mock_run):
        """Script sent to container should reference codex config path and settings."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID)

        calls = _get_calls(mock_run)
        cmd, stdin = calls[0]
        assert "python3" in cmd
        assert "/home/ubuntu/.codex" in stdin or "config.toml" in stdin
        assert "check_for_update_on_startup" in stdin

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_passes_tavily_env_var(self, mock_run):
        """Should pass SANDBOX_ENABLE_TAVILY environment variable."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID)

        calls = _get_calls(mock_run)
        cmd, _ = calls[0]
        assert any("SANDBOX_ENABLE_TAVILY" in str(a) for a in cmd)

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
    def test_docker_exec_command_structure(self, mock_run):
        """Commands should be docker exec targeting the correct container."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)

        calls = _get_calls(mock_run)
        assert len(calls) >= 1
        cmd, stdin = calls[0]
        assert cmd[0:2] == ["docker", "exec"]
        assert CONTAINER_ID in cmd

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_script_references_gemini_settings(self, mock_run):
        """Script should reference gemini settings path and expected keys."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)

        calls = _get_calls(mock_run)
        cmd, stdin = calls[0]
        assert "python3" in cmd
        assert "/home/ubuntu/.gemini" in stdin or "settings.json" in stdin
        assert "disableAutoUpdate" in stdin
        assert "telemetry" in stdin

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_passes_tavily_env_var(self, mock_run):
        """Should pass SANDBOX_ENABLE_TAVILY environment variable."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID)

        calls = _get_calls(mock_run)
        cmd, _ = calls[0]
        assert any("SANDBOX_ENABLE_TAVILY" in str(a) for a in cmd)

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
    def test_docker_exec_command_structure(self, mock_run):
        """Commands should be docker exec targeting the correct container."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID)

        calls = _get_calls(mock_run)
        assert len(calls) >= 1
        for cmd, _stdin in calls:
            assert cmd[0:2] == ["docker", "exec"]
            assert CONTAINER_ID in cmd

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_script_references_opencode_config(self, mock_run):
        """Script should reference opencode config path and autoupdate setting."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID)

        calls = _get_calls(mock_run)
        cmd, stdin = calls[0]
        assert "python3" in cmd
        assert "/home/ubuntu/.config/opencode" in stdin or "opencode.json" in stdin
        assert "autoupdate" in stdin

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
    def test_docker_exec_command_structure(self, mock_run):
        """Commands should be docker exec targeting the correct container."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID)

        calls = _get_calls(mock_run)
        assert len(calls) >= 1
        for cmd, _stdin in calls:
            assert cmd[0:2] == ["docker", "exec"]
            assert CONTAINER_ID in cmd

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_forces_https_for_github(self, mock_run):
        """Should configure git to use HTTPS instead of SSH for GitHub."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID)

        calls = _get_calls(mock_run)
        # First call is the git config shell command
        cmd, _ = calls[0]
        assert "sh" in cmd
        shell_cmd = cmd[-1]  # last arg is the shell command string
        assert "https://github.com/" in shell_cmd
        assert "git config" in shell_cmd

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_skips_https_when_ssh_enabled(self, mock_run):
        """Should skip HTTPS forcing when enable_ssh is True."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, enable_ssh=True)

        assert not mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_does_not_propagate(self, mock_run):
        """Git config uses check=False so errors don't propagate."""
        mock_run.return_value = _make_completed(returncode=1)

        # Should not raise
        configure_gh(CONTAINER_ID)


# ============================================================================
# Idempotency
# ============================================================================


class TestIdempotency:
    """Verify that configure_* functions can be called multiple times without error."""

    @pytest.mark.parametrize("configure_fn", [
        configure_claude,
        configure_codex,
        configure_gemini,
        configure_gh,
        configure_opencode,
    ])
    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_idempotent(self, mock_run, configure_fn):
        """Calling any configure_* function twice should not raise."""
        mock_run.return_value = _make_completed()

        configure_fn(CONTAINER_ID)
        configure_fn(CONTAINER_ID)

        assert mock_run.call_count >= 2


# ============================================================================
# OpenCode local plugin sync
# ============================================================================


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
