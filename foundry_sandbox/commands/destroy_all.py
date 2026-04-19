"""Destroy-all command — tear down all sandboxes.

Uses sbx-based destroy_impl() for each sandbox. Requires double confirmation.
"""

from __future__ import annotations

import os
import sys

import click

from foundry_sandbox.commands.destroy import destroy_impl
from foundry_sandbox.sbx import sbx_check_available, sbx_ls
from foundry_sandbox.utils import log_warn


@click.command()
@click.option("--keep-worktree", is_flag=True, help="Keep the git worktrees and configs")
def destroy_all(keep_worktree: bool) -> None:
    """Destroy all sandboxes and clean up all resources."""
    sbx_check_available()

    # ------------------------------------------------------------------
    # List all sandboxes from sbx
    # ------------------------------------------------------------------
    all_sandboxes = sbx_ls()
    sandbox_names = [sb["name"] for sb in all_sandboxes]

    if not sandbox_names:
        click.echo("No sandboxes to destroy.")
        sys.exit(0)

    # ------------------------------------------------------------------
    # Check SANDBOX_NONINTERACTIVE — skip confirmations in CI
    # ------------------------------------------------------------------
    noninteractive = os.environ.get("SANDBOX_NONINTERACTIVE", "") == "1"
    skip_confirm = noninteractive

    # ------------------------------------------------------------------
    # Show what will be destroyed
    # ------------------------------------------------------------------
    click.echo(f"This will destroy ALL sandboxes ({len(sandbox_names)} total):")
    for name in sandbox_names:
        click.echo(f"  - {name}")
    click.echo("")

    # ------------------------------------------------------------------
    # First confirmation
    # ------------------------------------------------------------------
    if not skip_confirm:
        try:
            if not click.confirm("Are you sure you want to destroy all sandboxes?", default=False):
                click.echo("Aborted.")
                sys.exit(0)
        except click.Abort:
            click.echo("\nAborted.")
            sys.exit(0)

        # ------------------------------------------------------------------
        # Second confirmation - must type 'destroy all'
        # ------------------------------------------------------------------
        try:
            response = click.prompt("Type 'destroy all' to confirm", type=str)
            if response != "destroy all":
                click.echo("Aborted.")
                sys.exit(0)
        except click.Abort:
            click.echo("\nAborted.")
            sys.exit(0)

    # ------------------------------------------------------------------
    # Destroy each sandbox using destroy_impl
    # ------------------------------------------------------------------
    failed = []

    for name in sandbox_names:
        click.echo("")
        click.echo(f"Destroying sandbox: {name}...")

        try:
            destroy_impl(
                name,
                keep_worktree=keep_worktree,
                best_effort=True,
            )
            click.echo(f"Sandbox '{name}' destroyed.")
        except Exception as exc:
            log_warn(f"Failed to destroy '{name}': {exc}")
            failed.append(name)

    # ------------------------------------------------------------------
    # Print summary
    # ------------------------------------------------------------------
    click.echo("")
    click.echo(f"Destroyed {len(sandbox_names) - len(failed)} sandbox(es).")

    if failed:
        click.echo(f"Failed to destroy: {', '.join(failed)}")
        sys.exit(1)
