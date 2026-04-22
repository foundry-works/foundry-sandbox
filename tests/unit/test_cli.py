"""Unit tests for the Click-based CLI entrypoint.

Tests command registration, alias resolution, unknown command rejection,
help output, and basic option parsing using Click's CliRunner.
"""
from __future__ import annotations

import subprocess
import sys

import click.testing
import pytest

from foundry_sandbox.cli import ALIASES, cli


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
        expected = {
            "attach", "config", "destroy", "destroy-all",
            "help", "info", "list", "new", "preset",
            "refresh-credentials", "git-mode", "start", "status", "stop",
        }
        ctx = click.Context(cli)
        registered = set(cli.list_commands(ctx))
        assert expected.issubset(registered), f"Missing: {expected - registered}"


# ---------------------------------------------------------------------------
# Alias resolution tests
# ---------------------------------------------------------------------------


class TestAliasResolution:
    """Tests for alias rewriting in CastGroup.resolve_command."""

    def test_aliases_dict_has_expected_entries(self) -> None:
        assert "repeat" in ALIASES
        assert "reattach" in ALIASES
        assert "refresh-creds" in ALIASES

    def test_repeat_resolves_to_new_last(self) -> None:
        canonical, prepended = ALIASES["repeat"]
        assert canonical == "new"
        assert "--last" in prepended

    def test_reattach_resolves_to_attach_last(self) -> None:
        canonical, prepended = ALIASES["reattach"]
        assert canonical == "attach"
        assert "--last" in prepended

    def test_refresh_creds_resolves_to_refresh_credentials(self) -> None:
        canonical, prepended = ALIASES["refresh-creds"]
        assert canonical == "refresh-credentials"
        assert prepended == []


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

    def test_build_command_removed(self, runner: click.testing.CliRunner) -> None:
        """'cast build' was removed in the sbx migration — must not resolve."""
        result = runner.invoke(cli, ["build"])
        assert result.exit_code != 0
        assert "Unknown command" in result.output

    def test_migrate_to_sbx_removed(self, runner: click.testing.CliRunner) -> None:
        """'cast migrate-to-sbx' was removed in 0.23.0 — must not resolve."""
        result = runner.invoke(cli, ["migrate-to-sbx"])
        assert result.exit_code != 0
        assert "Unknown command" in result.output

    def test_migrate_from_sbx_removed(self, runner: click.testing.CliRunner) -> None:
        """'cast migrate-from-sbx' was removed in 0.23.0 — must not resolve."""
        result = runner.invoke(cli, ["migrate-from-sbx"])
        assert result.exit_code != 0
        assert "Unknown command" in result.output

    def test_all_commands_registered_no_shell_fallback(self) -> None:
        required = {
            "new", "list", "attach", "start", "stop", "destroy",
            "help", "status", "config", "info",
            "preset", "refresh-credentials", "git-mode", "destroy-all",
        }
        ctx = click.Context(cli)
        registered = set(cli.list_commands(ctx))
        assert required.issubset(registered), f"Missing: {required - registered}"


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

    def test_help_command_shows_agent_option(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(cli, ["help"])
        assert result.exit_code == 0
        assert "agent" in result.output.lower() or "sbx" in result.output.lower()


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

        result = runner.invoke(config, [])
        assert result.exit_code == 0
        assert "SANDBOX_HOME" in result.output
        assert "SCRIPT_DIR" in result.output


class TestCliFlagRouting:
    """Smoke tests that command-level flags are routed to subcommands."""

    def test_attach_help_routes_to_attach(self, runner: click.testing.CliRunner) -> None:
        result = runner.invoke(cli, ["attach", "--help"])
        assert result.exit_code == 0
        assert "--last" in result.output


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


# ---------------------------------------------------------------------------
# CLI smoke tests (subprocess-based)
# ---------------------------------------------------------------------------


class TestCLISmokeTest:
    """Smoke tests that run the CLI as a subprocess."""

    def test_module_invocation_help(self) -> None:
        """``python3 -m foundry_sandbox.cli --help`` exits 0 and shows usage."""
        result = subprocess.run(
            [sys.executable, "-m", "foundry_sandbox.cli", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Usage" in result.stdout

    def test_module_invocation_unknown_command(self) -> None:
        """``python3 -m foundry_sandbox.cli nonexistent`` exits non-zero."""
        result = subprocess.run(
            [sys.executable, "-m", "foundry_sandbox.cli", "nonexistent"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
