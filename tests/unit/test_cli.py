"""Unit tests for the Click-based CLI entrypoint.

Tests command registration, alias resolution, unknown command rejection,
help output, and basic option parsing using Click's CliRunner. These tests
do NOT require Docker, tmux, or a running sandbox.
"""

from __future__ import annotations

from unittest.mock import patch

import click.testing
import pytest

from foundry_sandbox.cli import ALIASES, KNOWN_SHELL_COMMANDS, CastGroup, cli


@pytest.fixture()
def runner() -> click.testing.CliRunner:
    """Click CliRunner for invoking CLI commands."""
    return click.testing.CliRunner()


# ---------------------------------------------------------------------------
# Group-level tests
# ---------------------------------------------------------------------------


class TestCLIGroup:
    """Tests for the top-level CLI group behaviour."""

    def test_no_args_shows_help(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(cli)
        assert result.exit_code == 0
        assert "Cast" in result.output or "cast" in result.output.lower()

    def test_help_flag(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Usage" in result.output

    def test_all_migrated_commands_registered(self) -> None:
        """All 16 migrated commands are registered on the CLI group."""
        expected = {
            "attach", "build", "config", "destroy", "destroy-all",
            "help", "info", "list", "new", "preset", "prune",
            "refresh-creds", "start", "status", "stop", "upgrade",
        }
        registered = set(cli.commands.keys())
        assert expected.issubset(registered), f"Missing: {expected - registered}"


# ---------------------------------------------------------------------------
# Alias resolution tests
# ---------------------------------------------------------------------------


class TestAliasResolution:
    """Tests for alias rewriting in CastGroup.resolve_command."""

    def test_aliases_dict_has_expected_entries(self) -> None:
        assert "repeat" in ALIASES
        assert "reattach" in ALIASES

    def test_repeat_resolves_to_new_last(self) -> None:
        canonical, prepended = ALIASES["repeat"]
        assert canonical == "new"
        assert "--last" in prepended

    def test_reattach_resolves_to_attach_last(self) -> None:
        canonical, prepended = ALIASES["reattach"]
        assert canonical == "attach"
        assert "--last" in prepended


# ---------------------------------------------------------------------------
# Unknown command validation tests
# ---------------------------------------------------------------------------


class TestUnknownCommandValidation:
    """Tests that unknown commands are rejected instead of silently falling back."""

    def test_unknown_command_fails(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(cli, ["nonexistent-cmd"])
        assert result.exit_code != 0
        assert "Unknown command" in result.output or "unknown command" in result.output.lower()

    def test_typo_command_fails(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(cli, ["destory"])  # typo of 'destroy'
        assert result.exit_code != 0

    def test_known_shell_commands_is_comprehensive(self) -> None:
        """KNOWN_SHELL_COMMANDS includes all commands from sandbox.sh case statement."""
        required = {
            "new", "list", "attach", "start", "stop", "destroy",
            "build", "help", "status", "config", "prune", "info",
            "upgrade", "preset", "refresh-credentials", "destroy-all",
        }
        assert required.issubset(KNOWN_SHELL_COMMANDS)


# ---------------------------------------------------------------------------
# Help command tests
# ---------------------------------------------------------------------------


class TestHelpCommand:
    """Tests for the help command output."""

    def test_help_command_shows_usage(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(cli, ["help"])
        assert result.exit_code == 0
        assert "cast" in result.output.lower()
        assert "new" in result.output
        assert "list" in result.output
        assert "attach" in result.output

    def test_help_command_shows_options(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(cli, ["help"])
        assert result.exit_code == 0
        assert "--mount" in result.output or "--network" in result.output


# ---------------------------------------------------------------------------
# Config command tests
# ---------------------------------------------------------------------------


class TestConfigCommand:
    """Tests for the config command using direct command invocation."""

    def test_config_json_output(self, runner: click.testing.CliRunner) -> None:
        from foundry_sandbox.commands.config import config

        result = runner.invoke(config, ["--json"])
        assert result.exit_code == 0
        import json
        data = json.loads(result.output)
        assert "sandbox_home" in data
        assert "script_dir" in data
        assert "docker_image" in data

    def test_config_json_has_boolean_fields(self, runner: click.testing.CliRunner) -> None:
        from foundry_sandbox.commands.config import config

        result = runner.invoke(config, ["--json"])
        import json
        data = json.loads(result.output)
        assert isinstance(data["debug"], bool)
        assert isinstance(data["verbose"], bool)
        assert isinstance(data["assume_yes"], bool)

    def test_config_text_output(self, runner: click.testing.CliRunner) -> None:
        from foundry_sandbox.commands.config import config

        with patch("subprocess.run") as mock_run:
            # Mock `docker info` check
            mock_run.return_value.returncode = 0
            result = runner.invoke(config, [])
        assert result.exit_code == 0
        assert "SANDBOX_HOME" in result.output
        assert "SCRIPT_DIR" in result.output


# ---------------------------------------------------------------------------
# Info command tests
# ---------------------------------------------------------------------------


class TestInfoCommand:
    """Tests for the info command (calls config + status internally)."""

    def test_info_json_output_structure(self, runner: click.testing.CliRunner) -> None:
        from foundry_sandbox.commands.info import info

        result = runner.invoke(info, ["--json"])
        assert result.exit_code == 0
        import json
        data = json.loads(result.output)
        assert "config" in data
        assert "status" in data

    def test_info_text_includes_config_section(self, runner: click.testing.CliRunner) -> None:
        from foundry_sandbox.commands.info import info

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            result = runner.invoke(info, [])
        assert result.exit_code == 0
        assert "SANDBOX_HOME" in result.output


# ---------------------------------------------------------------------------
# SANDBOX_NONINTERACTIVE environment variable tests
# ---------------------------------------------------------------------------


class TestNonInteractiveFlag:
    """Tests for SANDBOX_NONINTERACTIVE propagation."""

    def test_noninteractive_flag_propagated(self, runner: click.testing.CliRunner) -> None:
        """When SANDBOX_NONINTERACTIVE=1, ctx.obj['noninteractive'] is True."""
        @cli.command("_test_ni")
        @click.pass_context
        def _test_ni(ctx: click.Context) -> None:
            click.echo(f"ni={ctx.obj.get('noninteractive')}")

        try:
            result = runner.invoke(cli, ["_test_ni"], env={"SANDBOX_NONINTERACTIVE": "1"})
            assert "ni=True" in result.output
        finally:
            cli.commands.pop("_test_ni", None)

    def test_noninteractive_flag_default_false(self, runner: click.testing.CliRunner) -> None:
        """Without SANDBOX_NONINTERACTIVE, the flag defaults to False."""
        @cli.command("_test_ni2")
        @click.pass_context
        def _test_ni2(ctx: click.Context) -> None:
            click.echo(f"ni={ctx.obj.get('noninteractive')}")

        try:
            result = runner.invoke(cli, ["_test_ni2"])
            assert "ni=False" in result.output
        finally:
            cli.commands.pop("_test_ni2", None)
