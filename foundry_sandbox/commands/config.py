"""Config command — show sandbox configuration and system checks.

Migrated from commands/config.sh (70 lines).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import click

from foundry_sandbox.constants import (
    get_claude_configs_dir,
    get_repos_dir,
    get_sandbox_home,
    get_worktrees_dir,
)
from foundry_sandbox.utils import BOLD, RESET, format_kv

SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent


def _get_env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@click.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def config(json_output: bool) -> None:
    """Show sandbox configuration and system checks."""
    sandbox_home = str(get_sandbox_home())
    repos_dir = str(get_repos_dir())
    worktrees_dir = str(get_worktrees_dir())
    configs_dir = str(get_claude_configs_dir())
    script_dir = str(SCRIPT_DIR)
    docker_image = _get_env("DOCKER_IMAGE", "foundry-sandbox")
    docker_uid = _get_env("DOCKER_UID", str(os.getuid()))
    docker_gid = _get_env("DOCKER_GID", str(os.getgid()))
    network_mode = _get_env("SANDBOX_NETWORK_MODE", "limited")
    sync_ssh = _get_env("SANDBOX_SYNC_SSH", "false")
    ssh_mode = _get_env("SANDBOX_SSH_MODE", "")
    debug = _get_env("SANDBOX_DEBUG", "false")
    verbose = _get_env("SANDBOX_VERBOSE", "false")
    assume_yes = _get_env("SANDBOX_ASSUME_YES", "false")

    if json_output:
        data = {
            "sandbox_home": sandbox_home,
            "repos_dir": repos_dir,
            "worktrees_dir": worktrees_dir,
            "claude_configs_dir": configs_dir,
            "script_dir": script_dir,
            "docker_image": docker_image,
            "docker_uid": docker_uid,
            "docker_gid": docker_gid,
            "network_mode": network_mode,
            "sync_ssh": sync_ssh == "true" or sync_ssh == "1",
            "ssh_mode": ssh_mode,
            "debug": debug == "true" or debug == "1",
            "verbose": verbose == "true" or verbose == "1",
            "assume_yes": assume_yes == "true" or assume_yes == "1",
        }
        click.echo(json.dumps(data))
        return

    click.echo(f"{BOLD}Sandbox config{RESET}")
    click.echo(format_kv("SANDBOX_HOME", sandbox_home))
    click.echo(format_kv("REPOS_DIR", repos_dir))
    click.echo(format_kv("WORKTREES_DIR", worktrees_dir))
    click.echo(format_kv("CLAUDE_CONFIGS_DIR", configs_dir))
    click.echo(format_kv("SCRIPT_DIR", script_dir))
    click.echo(format_kv("DOCKER_IMAGE", docker_image))
    click.echo(format_kv("DOCKER_UID", docker_uid))
    click.echo(format_kv("DOCKER_GID", docker_gid))
    click.echo(format_kv("SANDBOX_DEBUG", debug))
    click.echo(format_kv("SANDBOX_VERBOSE", verbose))
    click.echo(format_kv("SANDBOX_ASSUME_YES", assume_yes))
    click.echo(format_kv("SANDBOX_NETWORK_MODE", network_mode))
    click.echo(format_kv("SANDBOX_SYNC_SSH", sync_ssh))
    click.echo(format_kv("SANDBOX_SSH_MODE", ssh_mode))

    click.echo()
    click.echo(f"{BOLD}Checks{RESET}")

    # git check
    if shutil.which("git"):
        click.echo(format_kv("git", "ok"))
    else:
        click.echo(format_kv("git", "missing"))

    # docker check
    if shutil.which("docker"):
        click.echo(format_kv("docker", "ok"))
    else:
        click.echo(format_kv("docker", "missing"))

    # docker daemon check
    result = subprocess.run(
        ["docker", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode == 0:
        click.echo(format_kv("docker daemon", "ok"))
    else:
        click.echo(format_kv("docker daemon", "not running"))
