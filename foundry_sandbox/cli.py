"""Click-based CLI entrypoint for foundry-sandbox.

All commands are implemented as Click subcommands with lazy loading.
Unknown commands raise an error.
"""

from __future__ import annotations

import importlib
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


_LAZY_COMMANDS: dict[str, tuple[str, str]] = {
    "attach": ("foundry_sandbox.commands.attach", "attach"),
    "build": ("foundry_sandbox.commands.build", "build"),
    "config": ("foundry_sandbox.commands.config", "config"),
    "destroy": ("foundry_sandbox.commands.destroy", "destroy"),
    "destroy-all": ("foundry_sandbox.commands.destroy_all", "destroy_all"),
    "help": ("foundry_sandbox.commands.help_cmd", "help_cmd"),
    "info": ("foundry_sandbox.commands.info", "info"),
    "list": ("foundry_sandbox.commands.list_cmd", "list_cmd"),
    "new": ("foundry_sandbox.commands.new", "new"),
    "preset": ("foundry_sandbox.commands.preset", "preset"),
    "prune": ("foundry_sandbox.commands.prune", "prune"),
    "refresh-credentials": ("foundry_sandbox.commands.refresh_creds", "refresh_creds"),
    "start": ("foundry_sandbox.commands.start", "start"),
    "status": ("foundry_sandbox.commands.status", "status"),
    "stop": ("foundry_sandbox.commands.stop", "stop"),
    "upgrade": ("foundry_sandbox.commands.upgrade", "upgrade"),
}


class CastGroup(click.Group):
    """Custom Click group that supports alias resolution and lazy loading.

    Behaviour:
    * Command modules are imported on first access, not at import time.
    * Aliases listed in ``ALIASES`` are rewritten to their canonical form
      before dispatch.
    * Unknown commands produce an error message.
    """

    def format_usage(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Write the usage line into the formatter."""
        super().format_usage(ctx, formatter)

    def list_commands(self, ctx: click.Context) -> list[str]:
        """Return all available command names (eager + lazy)."""
        eager = set(self.commands or {})
        return sorted(eager | _LAZY_COMMANDS.keys())

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        """Look up a command, importing lazily if needed."""
        # Check eagerly-registered commands first
        cmd = self.commands.get(cmd_name)
        if cmd is not None:
            return cmd

        # Lazy import
        entry = _LAZY_COMMANDS.get(cmd_name)
        if entry is None:
            return None

        module_path, attr_name = entry
        mod = importlib.import_module(module_path)
        loaded_cmd: click.Command = getattr(mod, attr_name)
        # Cache so subsequent lookups skip the import
        self.add_command(loaded_cmd, cmd_name)
        return loaded_cmd

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
        3. If not found, raise an error.
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
# Commands are lazy-loaded via _LAZY_COMMANDS and CastGroup.get_command().


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------


def _validate_lazy_commands() -> None:
    """Verify all lazy command entries resolve to valid modules.

    Only runs when CAST_VALIDATE_COMMANDS=1 is set (debug/CI).
    """
    if not os.environ.get("CAST_VALIDATE_COMMANDS"):
        return
    for cmd_name, (module_path, attr_name) in _LAZY_COMMANDS.items():
        try:
            mod = importlib.import_module(module_path)
            if not hasattr(mod, attr_name):
                raise RuntimeError(
                    f"Lazy command '{cmd_name}' is broken: "
                    f"{module_path}.{attr_name} not found"
                )
        except ImportError as exc:
            raise RuntimeError(
                f"Lazy command '{cmd_name}' is broken: {exc}"
            ) from exc


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
    _validate_lazy_commands()
    try:
        result = cli(standalone_mode=False)
    except click.UsageError as exc:
        # With standalone_mode=False, Click raises UsageError directly
        # (not wrapped in SystemExit). Normalise to exit 1 for shell parity.
        click.echo(f"Error: {exc.format_message()}", err=True)
        sys.exit(1)
    except SystemExit as exc:
        # Commands may raise SystemExit directly. Normalise Click's exit 2
        # (usage error from nested invocations) to 1 for shell parity.
        code = exc.code if isinstance(exc.code, int) else 1
        sys.exit(1 if code == 2 else code)
    # If a migrated command returned an integer exit code, honour it.
    if isinstance(result, int):
        sys.exit(result)


if __name__ == "__main__":
    main()
