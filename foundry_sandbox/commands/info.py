"""Info command — display combined config and status information.

Migrated from commands/info.sh. Combines the output of config and status
commands into a single view, supporting both text and JSON output formats.

Calls the Python config and status commands directly via Click's ctx.invoke().
"""

from __future__ import annotations

import json
import sys
from io import StringIO

import click


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


@click.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def info(ctx: click.Context, json_output: bool) -> None:
    """Show config and status information."""
    from foundry_sandbox.commands.config import config
    from foundry_sandbox.commands.status import status

    if json_output:
        # JSON mode: capture stdout from each subcommand via StringIO
        config_output = _invoke_and_capture(ctx, config, json_output=True)
        status_output = _invoke_and_capture(ctx, status, json_output=True)

        try:
            config_data = json.loads(config_output)
            status_data = json.loads(status_output)
            combined = {"config": config_data, "status": status_data}
            click.echo(json.dumps(combined))
        except json.JSONDecodeError:
            click.echo('{"config":{},"status":{}}')
        return

    # Text mode: invoke both commands sequentially with separator
    ctx.invoke(config, json_output=False)
    click.echo()  # Section break
    ctx.invoke(status, name=None, json_output=False)


def _invoke_and_capture(
    ctx: click.Context, cmd: click.Command, **kwargs: object
) -> str:
    """Invoke a Click command and capture its stdout.

    Temporarily redirects sys.stdout to a StringIO buffer, then restores it.
    """
    buf = StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    try:
        ctx.invoke(cmd, **kwargs)
    finally:
        sys.stdout = old_stdout
    return buf.getvalue().strip()
