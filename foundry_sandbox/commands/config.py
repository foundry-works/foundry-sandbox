"""Config command — show sandbox configuration and system checks."""

from __future__ import annotations

import json
import os
import shutil

import click

from foundry_sandbox.constants import (
    get_sandbox_configs_dir,
    get_repos_dir,
    get_sandbox_home,
)
from foundry_sandbox.sbx import sbx_is_installed
from foundry_sandbox.utils import BOLD, RESET, format_kv


@click.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def config(json_output: bool) -> None:
    """Show sandbox configuration and system checks."""
    sandbox_home = str(get_sandbox_home())
    repos_dir = str(get_repos_dir())
    configs_dir = str(get_sandbox_configs_dir())
    debug = os.environ.get("SANDBOX_DEBUG", "false")
    verbose = os.environ.get("SANDBOX_VERBOSE", "false")
    assume_yes = os.environ.get("SANDBOX_ASSUME_YES", "false")

    if json_output:
        data = {
            "sandbox_home": sandbox_home,
            "repos_dir": repos_dir,
            "sandbox_configs_dir": configs_dir,
            "debug": debug in ("true", "1"),
            "verbose": verbose in ("true", "1"),
            "assume_yes": assume_yes in ("true", "1"),
        }
        click.echo(json.dumps(data))
        return

    click.echo(f"{BOLD}Sandbox config{RESET}")
    click.echo(format_kv("SANDBOX_HOME", sandbox_home))
    click.echo(format_kv("REPOS_DIR", repos_dir))
    click.echo(format_kv("SANDBOX_CONFIGS_DIR", configs_dir))
    click.echo(format_kv("SANDBOX_DEBUG", debug))
    click.echo(format_kv("SANDBOX_VERBOSE", verbose))
    click.echo(format_kv("SANDBOX_ASSUME_YES", assume_yes))

    click.echo()
    click.echo(f"{BOLD}Checks{RESET}")

    # git check
    if shutil.which("git"):
        click.echo(format_kv("git", "ok"))
    else:
        click.echo(format_kv("git", "missing"))

    # sbx check
    if sbx_is_installed():
        click.echo(format_kv("sbx", "ok"))
    else:
        click.echo(format_kv("sbx", "missing"))
