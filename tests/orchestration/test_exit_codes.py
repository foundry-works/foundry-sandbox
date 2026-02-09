"""Baseline exit code documentation for sandbox.sh commands.

These tests document the expected exit codes for each sandbox.sh command
in success and common failure scenarios. This becomes the parity target
for the Python rewrite.

Exit code conventions observed in the codebase:
  - 0: success (explicit return/exit 0, or implicit fall-through)
  - 1: error (explicit exit 1, or die() which calls exit 1)
  - Non-zero from set -e: unhandled command failure propagates its exit code

Key patterns:
  - die() in lib/validate.sh always does exit 1
  - sandbox.sh runs with set -e, so unhandled failures propagate
  - Most commands use explicit "exit 1" for missing required arguments
  - Some commands (list, config, help) never fail under normal conditions
  - destroy with --force tolerates missing resources (|| true patterns)
"""

import pytest

pytestmark = [
    pytest.mark.orchestration,
    pytest.mark.slow,
    pytest.mark.usefixtures("requires_docker"),
]


# ============================================================================
# Success path tests -- verify exit code 0 for valid operations
# ============================================================================


class TestSuccessPathExitCodes:
    """Commands that should return exit code 0 with valid or no arguments."""

    def test_help_returns_0(self, cli):
        """help command prints usage and returns 0.

        Source: commands/help.sh -- cmd_help() has no exit/return statements,
        so it falls through with exit code 0.
        """
        result = cli("help")
        assert result.returncode == 0, (
            f"Expected exit code 0 for help, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_help_flag_returns_0(self, cli):
        """--help flag is dispatched to cmd_help and returns 0.

        Source: sandbox.sh -- '--help' and '-h' are mapped to cmd_help.
        """
        result = cli("--help")
        assert result.returncode == 0, (
            f"Expected exit code 0 for --help, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_list_returns_0_with_no_sandboxes(self, cli):
        """list command returns 0 even when no sandboxes exist.

        Source: commands/list.sh -- cmd_list() iterates WORKTREES_DIR
        and prints a header. No exit/return on empty results, so falls
        through with exit code 0.
        """
        result = cli("list")
        assert result.returncode == 0, (
            f"Expected exit code 0 for list, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_list_json_returns_0_with_no_sandboxes(self, cli):
        """list --json returns 0 and valid JSON even when no sandboxes exist.

        Source: commands/list.sh -- the JSON path iterates directories and
        pipes through json_array_from_lines, which produces '[]' for no input.
        """
        result = cli("list", "--json")
        assert result.returncode == 0, (
            f"Expected exit code 0 for list --json, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_config_returns_0(self, cli):
        """config command prints configuration and returns 0.

        Source: commands/config.sh -- cmd_config() prints key-value pairs
        and checks tool availability. No failure paths lead to non-zero exit.
        """
        result = cli("config")
        assert result.returncode == 0, (
            f"Expected exit code 0 for config, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_config_json_returns_0(self, cli):
        """config --json returns 0 and emits JSON.

        Source: commands/config.sh -- the JSON path uses printf to build
        a JSON object from shell variables, then returns (implicit 0).
        """
        result = cli("config", "--json")
        assert result.returncode == 0, (
            f"Expected exit code 0 for config --json, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_status_no_args_returns_0(self, cli):
        """status with no arguments lists all sandboxes and returns 0.

        Source: commands/status.sh -- when name is empty, cmd_status()
        iterates all worktrees (same as list). Falls through with 0.
        """
        result = cli("status")
        assert result.returncode == 0, (
            f"Expected exit code 0 for status (no args), got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_status_json_no_args_returns_0(self, cli):
        """status --json with no sandbox name returns 0.

        Source: commands/status.sh -- same iteration path as list --json.
        """
        result = cli("status", "--json")
        assert result.returncode == 0, (
            f"Expected exit code 0 for status --json (no args), got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_info_returns_0(self, cli):
        """info command runs config + status and returns 0.

        Source: commands/info.sh -- cmd_info() sources and calls
        cmd_config then cmd_status. Both succeed with no sandboxes.
        """
        result = cli("info")
        assert result.returncode == 0, (
            f"Expected exit code 0 for info, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_info_json_returns_0(self, cli):
        """info --json returns 0 and emits combined config+status JSON.

        Source: commands/info.sh -- builds JSON from cmd_config --json
        and cmd_status --json output.
        """
        result = cli("info", "--json")
        assert result.returncode == 0, (
            f"Expected exit code 0 for info --json, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_prune_returns_0_with_nothing_to_prune(self, cli):
        """prune returns 0 when there are no orphaned configs.

        Source: commands/prune.sh -- when no orphans are found, the function
        prints "no orphaned configs" and falls through with exit code 0.
        """
        result = cli("prune", "-f")
        assert result.returncode == 0, (
            f"Expected exit code 0 for prune, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_preset_list_returns_0(self, cli):
        """preset list returns 0 even with no saved presets.

        Source: commands/preset.sh -- the 'list' action calls
        list_cast_presets which prints a message and returns 0.
        """
        result = cli("preset", "list")
        assert result.returncode == 0, (
            f"Expected exit code 0 for preset list, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_preset_help_returns_0(self, cli):
        """preset help returns 0.

        Source: commands/preset.sh -- the 'help' action prints usage
        and falls through with implicit exit code 0.
        """
        result = cli("preset", "help")
        assert result.returncode == 0, (
            f"Expected exit code 0 for preset help, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_build_returns_0(self, cli):
        """build command returns 0 when Docker images build successfully.

        Source: commands/build.sh -- cmd_build() calls docker compose build
        and docker build via run_cmd. With set -e, any failure would propagate.
        Success means both builds completed without error.

        NOTE: This test is slow -- it builds Docker images. Skip if image
        build infra is not available.
        """
        result = cli("build")
        assert result.returncode == 0, (
            f"Expected exit code 0 for build, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_destroy_all_returns_0_with_no_sandboxes(self, cli):
        """destroy-all returns 0 when no sandboxes exist.

        Source: commands/destroy-all.sh -- when sandboxes array is empty,
        cmd_destroy_all prints "No sandboxes to destroy." and returns 0.
        The function uses 'return 0' explicitly.
        """
        # destroy-all normally prompts for confirmation, but with no sandboxes
        # it returns early before any prompt
        result = cli("destroy-all")
        assert result.returncode == 0, (
            f"Expected exit code 0 for destroy-all (no sandboxes), "
            f"got {result.returncode}.\nstderr: {result.stderr}"
        )

    def test_upgrade_help_returns_0(self, cli):
        """upgrade --help returns 0.

        Source: commands/upgrade.sh -- the '--help' case prints usage
        and does 'return 0' explicitly.
        """
        result = cli("upgrade", "--help")
        assert result.returncode == 0, (
            f"Expected exit code 0 for upgrade --help, got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )


# ============================================================================
# Missing argument tests -- verify non-zero exit for missing required args
# ============================================================================


class TestMissingArgumentExitCodes:
    """Commands that should return non-zero when required arguments are missing."""

    def test_new_no_repo_exits_nonzero(self, cli):
        """new with no arguments launches interactive wizard or shows usage.

        Source: commands/new.sh -- when $# == 0, cmd_new() calls guided_new()
        which is an interactive wizard requiring TTY input. In non-interactive
        mode (piped stdin), gum/read will fail or return empty, causing the
        wizard to error out. The exact exit code depends on the terminal
        environment.

        When a repo is parsed but empty (after wizard fails), cmd_new prints
        usage and does 'exit 1'.

        NOTE: In a non-TTY test environment, this should exit non-zero because
        the interactive wizard cannot proceed.
        """
        result = cli("new")
        assert result.returncode != 0, (
            f"Expected non-zero exit for 'new' with no args in non-TTY, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )

    def test_destroy_no_name_exits_1(self, cli):
        """destroy with no name prints usage and exits 1.

        Source: commands/destroy.sh line 9-12:
            if [ -z "$name" ]; then
                echo "Usage: ..."
                exit 1
            fi
        """
        result = cli("destroy")
        assert result.returncode == 1, (
            f"Expected exit code 1 for destroy with no name, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )

    def test_start_no_name_exits_1(self, cli):
        """start with no name prints usage and exits 1.

        Source: commands/start.sh line 6-8:
            if [ -z "$name" ]; then
                echo "Usage: ..."
                exit 1
            fi
        """
        result = cli("start")
        assert result.returncode == 1, (
            f"Expected exit code 1 for start with no name, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )

    def test_stop_no_name_exits_1(self, cli):
        """stop with no name prints usage and exits 1.

        Source: commands/stop.sh line 6-8:
            if [ -z "$name" ]; then
                echo "Usage: ..."
                exit 1
            fi
        """
        result = cli("stop")
        assert result.returncode == 1, (
            f"Expected exit code 1 for stop with no name, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )

    def test_attach_no_name_exits_1(self, cli):
        """attach with no name (and no fzf, not in worktree) exits 1.

        Source: commands/attach.sh -- when name is empty after all auto-detect
        attempts, and fzf is not available, it prints usage, calls cmd_list,
        and exits 1. If fzf IS available, it opens a selector, but with no
        sandboxes and non-TTY it will exit 1 ("No sandbox selected.").
        """
        result = cli("attach")
        assert result.returncode == 1, (
            f"Expected exit code 1 for attach with no name, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )

    def test_preset_show_no_name_exits_1(self, cli):
        """preset show with no name prints usage and exits 1.

        Source: commands/preset.sh line 15-17:
            if [ -z "$preset_name" ]; then
                echo "Usage: cast preset show <name>"
                exit 1
            fi
        """
        result = cli("preset", "show")
        assert result.returncode == 1, (
            f"Expected exit code 1 for 'preset show' with no name, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )

    def test_preset_delete_no_name_exits_1(self, cli):
        """preset delete with no name prints usage and exits 1.

        Source: commands/preset.sh line 23-26:
            if [ -z "$preset_name" ]; then
                echo "Usage: cast preset delete <name>"
                exit 1
            fi
        """
        result = cli("preset", "delete")
        assert result.returncode == 1, (
            f"Expected exit code 1 for 'preset delete' with no name, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )

    def test_refresh_credentials_no_name_exits_1(self, cli):
        """refresh-credentials with no name (and no auto-detect) exits 1.

        Source: commands/refresh-credentials.sh -- when name is empty after
        all auto-detect attempts and fzf fallback, it prints usage, calls
        cmd_list, and exits 1.
        """
        result = cli("refresh-credentials")
        assert result.returncode == 1, (
            f"Expected exit code 1 for refresh-credentials with no name, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )


# ============================================================================
# Invalid sandbox name tests -- verify non-zero for nonexistent sandbox
# ============================================================================


class TestInvalidSandboxNameExitCodes:
    """Commands that should return non-zero when given a nonexistent sandbox name."""

    NONEXISTENT_NAME = "nonexistent-sandbox-xyz-999"

    def test_status_nonexistent_returns_0(self, cli):
        """status <nonexistent> returns 0 -- it reports status, not validates.

        Source: commands/status.sh -- when a name is given, cmd_status calls
        derive_sandbox_paths (which just computes paths, no validation) and
        collect_sandbox_info (which reports 'no container' and 'missing' for
        worktree/config). It does NOT exit non-zero for a missing sandbox;
        it renders the available info and exits 0.

        This is documented as-is behavior. The status command is a reporter,
        not a validator.
        """
        result = cli("status", self.NONEXISTENT_NAME)
        assert result.returncode == 0, (
            f"Expected exit code 0 for status with nonexistent name "
            f"(status reports, does not validate), got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_start_nonexistent_exits_1(self, cli):
        """start <nonexistent> exits 1 because worktree dir does not exist.

        Source: commands/start.sh line 17-19:
            if [ ! -d "$worktree_path" ]; then
                echo "Error: Sandbox '$name' not found"
                exit 1
            fi
        """
        result = cli("start", self.NONEXISTENT_NAME)
        assert result.returncode == 1, (
            f"Expected exit code 1 for start with nonexistent sandbox, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )

    def test_stop_nonexistent_exits_nonzero(self, cli):
        """stop <nonexistent> exits non-zero because compose_down fails.

        Source: commands/stop.sh -- cmd_stop calls compose_down without
        checking if the sandbox exists first. compose_down runs
        'docker compose ... down' via run_cmd, which fails because there
        is no matching compose project. With set -e in sandbox.sh, this
        failure propagates as a non-zero exit code.

        The exact exit code depends on docker compose's behavior for a
        missing project.
        """
        result = cli("stop", self.NONEXISTENT_NAME)
        assert result.returncode != 0, (
            f"Expected non-zero exit for stop with nonexistent sandbox, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )

    def test_destroy_nonexistent_force_exits_0(self, cli):
        """destroy <nonexistent> --force exits 0 due to tolerant cleanup.

        Source: commands/destroy.sh -- with --force, the confirmation prompt
        is skipped. Then:
        - tmux kill-session uses || true (line 37)
        - compose_down uses 2>/dev/null || true (line 44)
        - remove_stubs_volume and remove_hmac_volume are best-effort
        - network removal uses 2>/dev/null || true
        - load_sandbox_metadata uses || true (line 61)
        - Worktree removal only runs if dir exists (line 71)
        - The function falls through to echo "Sandbox destroyed." with exit 0

        This tolerant behavior is by design -- force-destroy should not fail
        even if the sandbox is already partially or fully cleaned up.
        """
        result = cli("destroy", self.NONEXISTENT_NAME, "--force")
        assert result.returncode == 0, (
            f"Expected exit code 0 for destroy --force with nonexistent sandbox "
            f"(tolerant cleanup), got {result.returncode}.\n"
            f"stderr: {result.stderr}"
        )

    def test_attach_nonexistent_exits_1(self, cli):
        """attach <nonexistent> exits 1 because worktree dir does not exist.

        Source: commands/attach.sh line 57-61:
            if [ ! -d "$worktree_path" ]; then
                echo "Error: Sandbox '$name' not found"
                cmd_list
                exit 1
            fi
        """
        result = cli("attach", self.NONEXISTENT_NAME)
        assert result.returncode == 1, (
            f"Expected exit code 1 for attach with nonexistent sandbox, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )

    def test_refresh_credentials_nonexistent_exits_1(self, cli):
        """refresh-credentials <nonexistent> exits 1 (metadata load or not running).

        Source: commands/refresh-credentials.sh --
        load_sandbox_metadata fails -> die "Failed to load sandbox metadata"
        which calls exit 1. Even if metadata somehow loaded, the container
        would not be running -> die "Sandbox '$name' is not running" (exit 1).
        """
        result = cli("refresh-credentials", self.NONEXISTENT_NAME)
        assert result.returncode == 1, (
            f"Expected exit code 1 for refresh-credentials with nonexistent sandbox, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )


# ============================================================================
# Unknown command tests -- verify non-zero for unrecognized commands
# ============================================================================


class TestUnknownCommandExitCodes:
    """Unknown or invalid commands should fail with non-zero exit codes."""

    def test_unknown_command_exits_1(self, cli):
        """An unrecognized command triggers die() which exits 1.

        Source: sandbox.sh line 69:
            *) die "Unknown command: $cmd" ;;
        die() calls exit 1 (lib/validate.sh line 87-89).
        """
        result = cli("not-a-real-command")
        assert result.returncode == 1, (
            f"Expected exit code 1 for unknown command, "
            f"got {result.returncode}.\nstderr: {result.stderr}"
        )

    def test_preset_unknown_subcommand_exits_1(self, cli):
        """preset with unknown subcommand exits 1.

        Source: commands/preset.sh line 45-48:
            *) echo "Unknown preset command: $action"
               echo "Run 'cast preset help' for usage."
               exit 1 ;;
        """
        result = cli("preset", "not-a-subcommand")
        assert result.returncode == 1, (
            f"Expected exit code 1 for unknown preset subcommand, "
            f"got {result.returncode}.\nstderr: {result.stderr}"
        )

    def test_upgrade_unknown_flag_exits_1(self, cli):
        """upgrade with unknown option exits 1.

        Source: commands/upgrade.sh line 22-24:
            *) echo "Unknown option: $1"
               echo "Usage: cast upgrade [--local]"
               exit 1 ;;
        """
        result = cli("upgrade", "--invalid-flag")
        assert result.returncode == 1, (
            f"Expected exit code 1 for upgrade with unknown flag, "
            f"got {result.returncode}.\nstdout: {result.stdout}"
        )


# ============================================================================
# Validation error tests -- verify non-zero for invalid inputs
# ============================================================================


class TestValidationErrorExitCodes:
    """Input validation errors should produce non-zero exit codes."""

    def test_new_invalid_network_mode_exits_1(self, cli):
        """new with invalid network mode exits 1 via die().

        Source: lib/network.sh -- validate_network_mode() calls die()
        for unrecognized modes. 'full' mode was explicitly removed with
        a die() message; any other invalid value also triggers die().
        die() always exits 1.
        """
        result = cli("new", "owner/repo", "--network", "invalid-mode")
        assert result.returncode == 1, (
            f"Expected exit code 1 for new with invalid network mode, "
            f"got {result.returncode}.\nstderr: {result.stderr}"
        )

    def test_new_removed_flag_exits_1(self, cli):
        """new with a removed flag (--no-ssh) exits 1 via die().

        Source: lib/args.sh -- parse_new_args contains:
            --no-ssh|--without-ssh)
                die "Flag removed: SSH is disabled by default. Use --with-ssh to enable."

        die() always exits 1.
        """
        result = cli("new", "owner/repo", "--no-ssh")
        assert result.returncode == 1, (
            f"Expected exit code 1 for new with removed --no-ssh flag, "
            f"got {result.returncode}.\nstderr: {result.stderr}"
        )

    def test_new_absolute_working_dir_exits_1(self, cli, local_repo):
        """new with absolute --wd path exits 1.

        Source: commands/new.sh line 937-938:
            /*) die "Working directory must be relative, not absolute: $working_dir" ;;

        die() always exits 1.
        """
        result = cli(
            "new", str(local_repo), "test-branch",
            "--wd", "/absolute/path",
            "--skip-key-check",
        )
        assert result.returncode == 1, (
            f"Expected exit code 1 for new with absolute --wd path, "
            f"got {result.returncode}.\nstderr: {result.stderr}"
        )

    def test_new_sparse_without_wd_exits_1(self, cli, local_repo):
        """new with --sparse but no --wd exits 1.

        Source: commands/new.sh line 945-947:
            if [ "$sparse_checkout" = "true" ] && [ -z "$working_dir" ]; then
                die "--sparse requires --wd to specify which directory to include"
            fi

        die() always exits 1.
        """
        result = cli(
            "new", str(local_repo), "test-branch",
            "--sparse",
            "--skip-key-check",
        )
        assert result.returncode == 1, (
            f"Expected exit code 1 for new with --sparse but no --wd, "
            f"got {result.returncode}.\nstderr: {result.stderr}"
        )

    def test_new_parent_traversal_in_wd_exits_1(self, cli, local_repo):
        """new with parent traversal in --wd exits 1.

        Source: commands/new.sh line 939:
            ../*|*/../*) die "Working directory cannot contain parent traversal: ..."

        die() always exits 1.
        """
        result = cli(
            "new", str(local_repo), "test-branch",
            "--wd", "../escape",
            "--skip-key-check",
        )
        assert result.returncode == 1, (
            f"Expected exit code 1 for new with parent traversal in --wd, "
            f"got {result.returncode}.\nstderr: {result.stderr}"
        )
