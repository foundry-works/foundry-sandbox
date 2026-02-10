"""Upgrade command — upgrade Foundry Sandbox to latest version.

Migrated from commands/upgrade.sh.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
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
        click.echo("Downloading latest installer from GitHub...")
        with tempfile.NamedTemporaryFile(suffix=".sh", delete=False) as tmp:
            tmp_path = tmp.name

        dl_result = subprocess.run(
            ["curl", "-fsSL", "-o", tmp_path,
             "https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh"],
            check=False,
        )
        if dl_result.returncode != 0:
            log_error("Failed to download installer")
            os.unlink(tmp_path)
            sys.exit(1)

        click.echo(f"Running installer from {tmp_path}...")
        result = subprocess.run(["bash", tmp_path], check=False)
        os.unlink(tmp_path)
        sys.exit(result.returncode)
