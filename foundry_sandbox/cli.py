"""Click-based CLI entrypoint for foundry-sandbox.

This module provides the main CLI group and shell fallback mechanism.
Commands that have been migrated to Python are registered as Click subcommands;
unmigrated commands fall back to sandbox.sh execution with full passthrough
of environment, cwd, stdout, stderr, and exit code.
"""

from __future__ import annotations

import os
import sys

import click

from foundry_sandbox.utils import log_debug

# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------
# Each alias maps to (canonical_command, prepended_args).  When the CLI
# encounters an alias it rewrites the invocation *before* dispatch, so
# the canonical command (whether migrated or shell-backed) handles it.

ALIASES: dict[str, tuple[str, list[str]]] = {
    "repeat": ("new", ["--last"]),
    "reattach": ("attach", ["--last"]),
    "refresh-creds": ("refresh-credentials", []),
}

# All commands known to sandbox.sh (used to decide whether a fallback is
# reasonable vs. an outright typo).  Kept in sync with the case-statement
# in sandbox.sh.

# ---------------------------------------------------------------------------
# Custom Click Group
# ---------------------------------------------------------------------------


class CastGroup(click.Group):
    """Custom Click group that supports alias resolution.

    Behaviour:
    * Registered subcommands are dispatched normally by Click.
    * Aliases listed in ``ALIASES`` are rewritten to their canonical form
      before dispatch.
    * Unknown commands produce an error message.
    """

    def format_usage(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Write the usage line into the formatter."""
        super().format_usage(ctx, formatter)

    # -----------------------------------------------------------------
    # Alias + fallback resolution
    # -----------------------------------------------------------------

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        """Resolve a command name, handling aliases and shell fallback.

        Order of operations:
        1. If the token is an alias, rewrite to canonical name + prepend args.
        2. Try normal Click resolution (registered subcommands).
        3. If not found, build a synthetic Click command that invokes the
           shell fallback instead of raising ``UsageError``.
        """
        # Nothing to resolve — let Click handle the empty case.
        if not args:
            return super().resolve_command(ctx, args)

        cmd_name = args[0]
        remaining = list(args[1:])

        # Step 1: Alias resolution ----------------------------------------
        if cmd_name in ALIASES:
            canonical, prepended = ALIASES[cmd_name]
            log_debug(f"Alias '{cmd_name}' -> '{canonical}' with args {prepended}")
            cmd_name = canonical
            remaining = prepended + remaining

        # Step 2: Try registered subcommands --------------------------------
        cmd_obj = self.get_command(ctx, cmd_name)
        if cmd_obj is not None:
            return cmd_name, cmd_obj, remaining

        # Step 3: Unknown command -------------------------------------------
        ctx.fail(
            f"Unknown command '{cmd_name}'. Run 'cast help' for available commands."
        )


# ---------------------------------------------------------------------------
# Main CLI Group
# ---------------------------------------------------------------------------


@click.group(
    cls=CastGroup,
    invoke_without_command=True,
)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Cast - Docker sandbox manager for Claude Code."""
    ctx.ensure_object(dict)

    # Store the non-interactive flag for subcommands to inspect.
    ctx.obj["noninteractive"] = os.environ.get("SANDBOX_NONINTERACTIVE") == "1"

    if ctx.invoked_subcommand is None and not ctx.args:
        # No command given — show help.
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# Command Registration
# ---------------------------------------------------------------------------
# Migrated commands are imported and added here as they become available.

from foundry_sandbox.commands.attach import attach  # noqa: E402
from foundry_sandbox.commands.build import build  # noqa: E402
from foundry_sandbox.commands.config import config  # noqa: E402
from foundry_sandbox.commands.destroy import destroy  # noqa: E402
from foundry_sandbox.commands.destroy_all import destroy_all  # noqa: E402
from foundry_sandbox.commands.help_cmd import help_cmd  # noqa: E402
from foundry_sandbox.commands.info import info  # noqa: E402
from foundry_sandbox.commands.list_cmd import list_cmd  # noqa: E402
from foundry_sandbox.commands.new import new  # noqa: E402
from foundry_sandbox.commands.preset import preset  # noqa: E402
from foundry_sandbox.commands.prune import prune  # noqa: E402
from foundry_sandbox.commands.refresh_creds import refresh_creds  # noqa: E402
from foundry_sandbox.commands.start import start  # noqa: E402
from foundry_sandbox.commands.status import status  # noqa: E402
from foundry_sandbox.commands.stop import stop  # noqa: E402
from foundry_sandbox.commands.upgrade import upgrade  # noqa: E402

cli.add_command(attach)
cli.add_command(build)
cli.add_command(config)
cli.add_command(destroy)
cli.add_command(destroy_all)
cli.add_command(help_cmd)
cli.add_command(info)
cli.add_command(list_cmd)
cli.add_command(new)
cli.add_command(preset)
cli.add_command(prune)
cli.add_command(refresh_creds)
cli.add_command(start)
cli.add_command(status)
cli.add_command(stop)
cli.add_command(upgrade)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the CLI.

    Uses ``standalone_mode=False`` so that Click does not call
    ``sys.exit`` on its own — we manage exit codes explicitly in
    fallback commands and let migrated commands use Click's default
    return behaviour.

    Usage errors (bad flags, missing required args) are normalised to
    exit code 1 to match the shell entrypoint's behaviour.  Click's
    default for ``UsageError`` is exit code 2.
    """
    try:
        result = cli(standalone_mode=False)
    except click.UsageError as exc:
        # Normalise Click's exit code 2 → 1 for shell parity.
        click.echo(f"Error: {exc.format_message()}", err=True)
        sys.exit(1)
    except SystemExit as exc:
        # Catch Click's SystemExit(2) from nested usage errors.
        code = exc.code if isinstance(exc.code, int) else 1
        sys.exit(1 if code == 2 else code)
    # If a migrated command returned an integer exit code, honour it.
    if isinstance(result, int):
        sys.exit(result)


if __name__ == "__main__":
    main()
