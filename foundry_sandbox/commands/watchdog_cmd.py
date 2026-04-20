"""Watchdog command — run the wrapper integrity watchdog standalone."""

from __future__ import annotations

import signal
import sys

import click


@click.command("watchdog")
@click.option(
    "--interval",
    default=10.0,
    show_default=True,
    help="Poll interval in seconds (default tightened from 30s to reduce tamper window)",
)
def watchdog_cmd(interval: float) -> None:
    """Run the wrapper integrity watchdog."""
    from foundry_sandbox.sbx import sbx_check_available

    sbx_check_available()

    from foundry_sandbox.watchdog import start_watchdog

    wd = start_watchdog(poll_interval=interval)
    click.echo(
        f"Wrapper integrity watchdog running (interval={interval}s). "
        "Press Ctrl+C to stop."
    )

    def _signal_handler(sig: int, frame: object) -> None:
        click.echo("\nStopping watchdog...")
        wd.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.pause()
