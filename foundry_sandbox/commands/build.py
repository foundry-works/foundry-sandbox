"""Build command — build sandbox Docker images.

Migrated from commands/build.sh (17 lines).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import click

from foundry_sandbox.utils import log_info

SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent


@click.command()
@click.option("--no-cache", is_flag=True, help="Build without Docker cache")
@click.option("--without-opencode", is_flag=True, help="Exclude OpenCode from build")
def build(no_cache: bool, without_opencode: bool) -> None:
    """Build/rebuild the sandbox Docker images."""
    cache_args = ["--no-cache"] if no_cache else []
    build_args = ["--build-arg", "INCLUDE_OPENCODE=0"] if without_opencode else []

    log_info("Building sandbox image...")
    result = subprocess.run(
        ["docker", "compose", "-f", str(SCRIPT_DIR / "docker-compose.yml"), "build"]
        + cache_args + build_args,
        check=False,
    )
    if result.returncode != 0:
        sys.exit(result.returncode)

    log_info("Building credential isolation proxy image...")
    result = subprocess.run(
        ["docker", "build"] + cache_args + ["-t", "foundry-unified-proxy",
         str(SCRIPT_DIR / "unified-proxy")],
        check=False,
    )
    if result.returncode != 0:
        sys.exit(result.returncode)
