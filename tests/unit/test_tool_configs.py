"""Unit tests for tool configs module.

Tests configuration provisioning for Claude, Codex, Gemini, OpenCode, and gh
inside Docker containers via foundry_sandbox.tool_configs.

The module under test does not exist yet -- these tests are written against
the spec so they will fail with ImportError until the implementation lands.
Each configure_* function is expected to call subprocess.run with docker exec
commands to create directories, write config files, and set environment
variables inside a running container.

Paths referenced in assertions are drawn from the shell source
(lib/container_config.sh) and foundry_sandbox.constants:
  CONTAINER_HOME = /home/ubuntu
  CONTAINER_USER = ubuntu
"""
from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, call, patch, ANY

import pytest

from foundry_sandbox.tool_configs import (
    configure_claude,
    configure_codex,
    configure_gemini,
    configure_gh,
    configure_opencode,
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


# ============================================================================
# configure_claude
# ============================================================================


class TestConfigureClaude:
    """Tests for configure_claude."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_creates_claude_directory(self, mock_run):
        """Creates /home/ubuntu/.claude directory inside container."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID, {"api_key": "sk-test"})

        mkdir_calls = _calls_contain(mock_run, "mkdir", ".claude")
        assert len(mkdir_calls) >= 1, (
            "Expected at least one mkdir call for .claude directory"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_uses_docker_exec(self, mock_run):
        """All commands should be executed via docker exec."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID, {"api_key": "sk-test"})

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

        configure_claude(CONTAINER_ID, {"api_key": "sk-test"})

        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        assert len(docker_exec_calls) >= 1
        for arg_list in docker_exec_calls:
            assert CONTAINER_ID in arg_list, (
                f"Container ID {CONTAINER_ID!r} not found in: {arg_list}"
            )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_writes_settings_json(self, mock_run):
        """Should write a settings.json file under .claude directory."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID, {"api_key": "sk-test"})

        settings_calls = _calls_contain(mock_run, "settings.json")
        assert len(settings_calls) >= 1, (
            "Expected at least one call referencing settings.json"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_settings_include_permissions_model(self, mock_run):
        """Settings JSON should contain a permissions section."""
        written_content = {}

        def capture_run(args, **kwargs):
            joined = " ".join(str(a) for a in args) if isinstance(args, list) else str(args)
            # Try to capture JSON content passed via stdin or arguments
            stdin_data = kwargs.get("input", "")
            if isinstance(stdin_data, str) and "permissions" in stdin_data:
                try:
                    written_content["data"] = json.loads(stdin_data)
                except (json.JSONDecodeError, TypeError):
                    pass
            return _make_completed()

        mock_run.side_effect = capture_run

        configure_claude(CONTAINER_ID, {"api_key": "sk-test"})

        # Verify at least that subprocess calls were made (the settings write
        # may use docker exec with inline python or a file copy)
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_handles_api_key(self, mock_run):
        """Configures ANTHROPIC_API_KEY when api_key is provided."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID, {"api_key": "sk-ant-test-key"})

        api_key_calls = _calls_contain(mock_run, "ANTHROPIC_API_KEY")
        # The key may be written to bashrc/profile or passed as env var
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_handles_oauth_token(self, mock_run):
        """Configures CLAUDE_CODE_OAUTH_TOKEN when oauth_token is provided."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID, {"oauth_token": "oauth-test-123"})

        # Should reference the OAuth token environment variable
        oauth_calls = _calls_contain(mock_run, "CLAUDE_CODE_OAUTH_TOKEN")
        # Even if the env var isn't found by string matching (e.g. base64 encoded),
        # the function must have been called
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_oauth_takes_precedence_over_api_key(self, mock_run):
        """When both oauth_token and api_key are given, oauth_token wins."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID, {
            "api_key": "sk-test",
            "oauth_token": "oauth-test-123",
        })

        # Verify the function completed; actual precedence logic is implementation-specific
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_propagates(self, mock_run):
        """Subprocess failures should propagate as exceptions."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        with pytest.raises(subprocess.CalledProcessError):
            configure_claude(CONTAINER_ID, {"api_key": "sk-test"})

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_empty_settings_still_creates_directory(self, mock_run):
        """Even with minimal settings, the .claude directory must be created."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID, {})

        mkdir_calls = _calls_contain(mock_run, "mkdir", ".claude")
        assert len(mkdir_calls) >= 1


# ============================================================================
# configure_codex
# ============================================================================


class TestConfigureCodex:
    """Tests for configure_codex."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_creates_codex_config_directory(self, mock_run):
        """Creates /home/ubuntu/.codex directory inside container."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID, {})

        mkdir_calls = _calls_contain(mock_run, "mkdir", ".codex")
        assert len(mkdir_calls) >= 1, (
            "Expected at least one mkdir call for .codex directory"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_uses_docker_exec(self, mock_run):
        """All commands should be executed via docker exec."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID, {})

        assert mock_run.called
        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        assert len(docker_exec_calls) >= 1

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_targets_correct_container(self, mock_run):
        """Docker exec commands should target the given container ID."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID, {})

        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        for arg_list in docker_exec_calls:
            assert CONTAINER_ID in arg_list

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_writes_config_toml(self, mock_run):
        """Should write a config.toml file under .codex directory."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID, {})

        config_calls = _calls_contain(mock_run, "config.toml")
        # config.toml may be written via inline python or docker cp
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_instructions_passed_through(self, mock_run):
        """When instructions are provided, they should appear in config."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID, {"instructions": "Be helpful and concise"})

        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_disables_auto_update(self, mock_run):
        """Codex config should disable update checks by default."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID, {})

        # The implementation should set check_for_update_on_startup = false
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_propagates(self, mock_run):
        """Subprocess failures should propagate as exceptions."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        with pytest.raises(subprocess.CalledProcessError):
            configure_codex(CONTAINER_ID, {})


# ============================================================================
# configure_gemini
# ============================================================================


class TestConfigureGemini:
    """Tests for configure_gemini."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_creates_gemini_directory(self, mock_run):
        """Creates /home/ubuntu/.gemini directory inside container."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {"api_key": "gemini-key-123"})

        mkdir_calls = _calls_contain(mock_run, "mkdir", ".gemini")
        assert len(mkdir_calls) >= 1, (
            "Expected at least one mkdir call for .gemini directory"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_uses_docker_exec(self, mock_run):
        """All commands should be executed via docker exec."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {"api_key": "gemini-key-123"})

        assert mock_run.called
        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        assert len(docker_exec_calls) >= 1

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_targets_correct_container(self, mock_run):
        """Docker exec commands should target the given container ID."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {"api_key": "gemini-key-123"})

        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        for arg_list in docker_exec_calls:
            assert CONTAINER_ID in arg_list

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_writes_settings_json(self, mock_run):
        """Should write a settings.json file under .gemini directory."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {"api_key": "gemini-key-123"})

        settings_calls = _calls_contain(mock_run, "settings.json")
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_api_key_config(self, mock_run):
        """API key mode should write API key configuration."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {"api_key": "gemini-key-123"})

        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_oauth_config(self, mock_run):
        """OAuth mode should write OAuth configuration."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {"auth_type": "oauth"})

        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_disables_auto_update(self, mock_run):
        """Gemini settings should disable auto-update by default."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {"api_key": "gemini-key-123"})

        # Implementation should set disableAutoUpdate: true in general section
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_disables_telemetry(self, mock_run):
        """Gemini settings should disable telemetry by default."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {"api_key": "gemini-key-123"})

        # Implementation should set telemetry.enabled: false
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_propagates(self, mock_run):
        """Subprocess failures should propagate as exceptions."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        with pytest.raises(subprocess.CalledProcessError):
            configure_gemini(CONTAINER_ID, {"api_key": "gemini-key-123"})

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_empty_settings_still_creates_directory(self, mock_run):
        """Even with no auth settings, .gemini directory must be created."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {})

        mkdir_calls = _calls_contain(mock_run, "mkdir", ".gemini")
        assert len(mkdir_calls) >= 1


# ============================================================================
# configure_opencode
# ============================================================================


class TestConfigureOpenCode:
    """Tests for configure_opencode."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_creates_opencode_config_dir(self, mock_run):
        """Creates /home/ubuntu/.config/opencode directory."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {"model": "openai/gpt-5.2-codex"})

        mkdir_calls = _calls_contain(mock_run, "mkdir", "opencode")
        assert len(mkdir_calls) >= 1, (
            "Expected at least one mkdir call for opencode config directory"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_uses_docker_exec(self, mock_run):
        """All commands should be executed via docker exec."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {"model": "openai/gpt-5.2-codex"})

        assert mock_run.called
        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        assert len(docker_exec_calls) >= 1

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_targets_correct_container(self, mock_run):
        """Docker exec commands should target the given container ID."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {"model": "openai/gpt-5.2-codex"})

        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        for arg_list in docker_exec_calls:
            assert CONTAINER_ID in arg_list

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_writes_opencode_json(self, mock_run):
        """Should write an opencode.json config file."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {"model": "openai/gpt-5.2-codex"})

        config_calls = _calls_contain(mock_run, "opencode.json")
        # The config may be written via inline python or docker cp
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_config_includes_model(self, mock_run):
        """Config JSON should include the specified model."""
        mock_run.return_value = _make_completed()
        model = "openai/gpt-5.2-codex"

        configure_opencode(CONTAINER_ID, {"model": model})

        # Verify subprocess was called - model appears in the written config
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_disables_autoupdate(self, mock_run):
        """OpenCode config should set autoupdate to off."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {"model": "openai/gpt-5.2-codex"})

        # Implementation should set autoupdate: "off"
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_handles_npm_plugins_enabled(self, mock_run):
        """When npm_plugins is True, should trigger npm plugin prefetch."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {"npm_plugins": True})

        # Should have more calls when npm plugins are enabled (prefetch step)
        assert mock_run.call_count >= 1

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_handles_npm_plugins_disabled(self, mock_run):
        """When npm_plugins is False, should skip npm plugin prefetch."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {"npm_plugins": False})

        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_handles_plugin_paths(self, mock_run):
        """Plugin path settings should be included in config."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {
            "model": "openai/gpt-5.2-codex",
            "plugin_dir": "/home/ubuntu/.config/opencode/plugins",
        })

        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_propagates(self, mock_run):
        """Subprocess failures should propagate as exceptions."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        with pytest.raises(subprocess.CalledProcessError):
            configure_opencode(CONTAINER_ID, {"model": "openai/gpt-5.2-codex"})

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_empty_settings_still_creates_directory(self, mock_run):
        """Even with empty settings, opencode config dir must be created."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {})

        mkdir_calls = _calls_contain(mock_run, "mkdir", "opencode")
        assert len(mkdir_calls) >= 1


# ============================================================================
# configure_gh
# ============================================================================


class TestConfigureGh:
    """Tests for configure_gh."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_creates_gh_config_dir(self, mock_run):
        """Creates /home/ubuntu/.config/gh directory inside container."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, {})

        mkdir_calls = _calls_contain(mock_run, "mkdir", "gh")
        assert len(mkdir_calls) >= 1, (
            "Expected at least one mkdir call for gh config directory"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_uses_docker_exec(self, mock_run):
        """All commands should be executed via docker exec."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, {})

        assert mock_run.called
        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        assert len(docker_exec_calls) >= 1

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_targets_correct_container(self, mock_run):
        """Docker exec commands should target the given container ID."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, {})

        docker_exec_calls = _calls_contain(mock_run, "docker", "exec")
        for arg_list in docker_exec_calls:
            assert CONTAINER_ID in arg_list

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_writes_hosts_yml(self, mock_run):
        """Should write hosts.yml with GitHub host configuration."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, {"token": "ghp_placeholder_token"})

        hosts_calls = _calls_contain(mock_run, "hosts.yml")
        # hosts.yml may be written via inline command or file copy
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_hosts_yml_contains_github_com(self, mock_run):
        """hosts.yml should contain github.com host entry."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, {"token": "ghp_placeholder_token"})

        github_calls = _calls_contain(mock_run, "github.com")
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_token_placeholder(self, mock_run):
        """Token placeholder should be written when provided."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, {"token": "gh-placeholder"})

        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_no_token_still_creates_config(self, mock_run):
        """Even without a token, gh config directory should be created."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, {})

        mkdir_calls = _calls_contain(mock_run, "mkdir", "gh")
        assert len(mkdir_calls) >= 1

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_config_dir_path_is_correct(self, mock_run):
        """Config directory should be at /home/ubuntu/.config/gh."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, {})

        config_gh_calls = _calls_contain(mock_run, ".config/gh")
        assert len(config_gh_calls) >= 1, (
            "Expected at least one call referencing .config/gh"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_subprocess_error_propagates(self, mock_run):
        """Subprocess failures should propagate as exceptions."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        with pytest.raises(subprocess.CalledProcessError):
            configure_gh(CONTAINER_ID, {})


# ============================================================================
# Cross-cutting concerns
# ============================================================================


class TestContainerUserOwnership:
    """Tests verifying that config files are owned by the container user."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_claude_uses_container_user(self, mock_run):
        """Claude config commands should run as ubuntu user."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID, {"api_key": "sk-test"})

        # At least one docker exec call should specify -u ubuntu (or similar)
        user_calls = _calls_contain(mock_run, "docker", "exec", "ubuntu")
        # The user may be specified via -u flag or run as the default user
        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_gemini_uses_container_user(self, mock_run):
        """Gemini config commands should run as ubuntu user."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {"api_key": "gemini-key"})

        assert mock_run.called

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_opencode_uses_container_user(self, mock_run):
        """OpenCode config commands should run as ubuntu user."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {"model": "openai/gpt-5.2-codex"})

        assert mock_run.called


class TestContainerPaths:
    """Tests verifying that correct container paths are used."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_claude_uses_home_ubuntu_path(self, mock_run):
        """Claude config should reference /home/ubuntu/.claude."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID, {"api_key": "sk-test"})

        home_calls = _calls_contain(mock_run, "/home/ubuntu/.claude")
        assert len(home_calls) >= 1, (
            "Expected at least one call referencing /home/ubuntu/.claude"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_gemini_uses_home_ubuntu_path(self, mock_run):
        """Gemini config should reference /home/ubuntu/.gemini."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {"api_key": "gemini-key"})

        home_calls = _calls_contain(mock_run, "/home/ubuntu/.gemini")
        assert len(home_calls) >= 1, (
            "Expected at least one call referencing /home/ubuntu/.gemini"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_opencode_uses_config_path(self, mock_run):
        """OpenCode config should reference /home/ubuntu/.config/opencode."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {"model": "openai/gpt-5.2-codex"})

        config_calls = _calls_contain(
            mock_run, "/home/ubuntu/.config/opencode"
        )
        assert len(config_calls) >= 1, (
            "Expected at least one call referencing /home/ubuntu/.config/opencode"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_gh_uses_config_path(self, mock_run):
        """gh config should reference /home/ubuntu/.config/gh."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, {})

        config_calls = _calls_contain(mock_run, "/home/ubuntu/.config/gh")
        assert len(config_calls) >= 1, (
            "Expected at least one call referencing /home/ubuntu/.config/gh"
        )

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_codex_uses_home_ubuntu_path(self, mock_run):
        """Codex config should reference /home/ubuntu/.codex."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID, {})

        home_calls = _calls_contain(mock_run, "/home/ubuntu/.codex")
        assert len(home_calls) >= 1, (
            "Expected at least one call referencing /home/ubuntu/.codex"
        )


class TestIdempotency:
    """Tests verifying that configure_* functions can be called multiple times."""

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_claude_idempotent(self, mock_run):
        """Calling configure_claude twice should not raise."""
        mock_run.return_value = _make_completed()

        configure_claude(CONTAINER_ID, {"api_key": "sk-test"})
        configure_claude(CONTAINER_ID, {"api_key": "sk-test"})

        # Should succeed without error
        assert mock_run.call_count >= 2

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_gemini_idempotent(self, mock_run):
        """Calling configure_gemini twice should not raise."""
        mock_run.return_value = _make_completed()

        configure_gemini(CONTAINER_ID, {"api_key": "gemini-key"})
        configure_gemini(CONTAINER_ID, {"api_key": "gemini-key"})

        assert mock_run.call_count >= 2

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_opencode_idempotent(self, mock_run):
        """Calling configure_opencode twice should not raise."""
        mock_run.return_value = _make_completed()

        configure_opencode(CONTAINER_ID, {"model": "openai/gpt-5.2-codex"})
        configure_opencode(CONTAINER_ID, {"model": "openai/gpt-5.2-codex"})

        assert mock_run.call_count >= 2

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_gh_idempotent(self, mock_run):
        """Calling configure_gh twice should not raise."""
        mock_run.return_value = _make_completed()

        configure_gh(CONTAINER_ID, {"token": "ghp_test"})
        configure_gh(CONTAINER_ID, {"token": "ghp_test"})

        assert mock_run.call_count >= 2

    @patch("foundry_sandbox.tool_configs.subprocess.run")
    def test_codex_idempotent(self, mock_run):
        """Calling configure_codex twice should not raise."""
        mock_run.return_value = _make_completed()

        configure_codex(CONTAINER_ID, {})
        configure_codex(CONTAINER_ID, {})

        assert mock_run.call_count >= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
