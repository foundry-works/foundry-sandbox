"""Upgrade command — upgrade Foundry Sandbox to latest version.

Migrated from commands/upgrade.sh.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import click

from foundry_sandbox.utils import log_error


SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent


@click.command()
@click.option("--local", "use_local", is_flag=True, help="Upgrade from local repo (for development)")
def upgrade(use_local: bool) -> None:
    """Upgrade Foundry Sandbox to the latest version."""
    if use_local:
        install_sh = SCRIPT_DIR / "install.sh"
        if install_sh.is_file():
            click.echo("Running local installer...")
            result = subprocess.run(
                ["bash", str(install_sh), "--repo", str(SCRIPT_DIR)],
                check=False,
            )
            sys.exit(result.returncode)
        else:
            log_error(f"Local install.sh not found at {install_sh}")
            sys.exit(1)
    else:
        click.echo("Fetching latest installer from GitHub...")
        result = subprocess.run(
            ["bash", "-c", "curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash"],
            check=False,
        )
        sys.exit(result.returncode)
