"""Upgrade foundry-mcp to pre-release inside a running container.

Called during ``cast new --pre-foundry`` after container startup but before
network restrictions are applied (PyPI must still be reachable).
"""

from __future__ import annotations

import subprocess
import sys

import click

from foundry_sandbox.constants import CONTAINER_HOME, CONTAINER_USER, TIMEOUT_DOCKER_EXEC, TIMEOUT_PIP_INSTALL, get_sandbox_verbose
from foundry_sandbox.utils import log_debug, log_info, log_warn


def _get_installed_version(container_id: str) -> str:
    """Query the installed foundry-mcp version via ``pip show``.

    Returns:
        Version string (e.g. ``"1.2.0a3"``), or empty string on failure.
    """
    cmd = [
        "docker", "exec", "-u", CONTAINER_USER, container_id,
        "pip", "show", "foundry-mcp",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return ""

    if result.returncode != 0:
        return ""

    for line in result.stdout.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return ""


def _enable_user_site_packages(container_id: str) -> None:
    """Remove ``-s`` flag from foundry-mcp MCP config in the container.

    When a pre-release is installed via ``pip install --pre`` it lands in user
    site-packages (``~/.local/``) because ``PIP_USER=1`` is set in the image.
    The default MCP config uses ``python -s -m foundry_mcp.server`` which
    tells Python to *skip* user site-packages, so the pre-release would be
    invisible to the MCP server.  This helper patches both Claude JSON config
    files to drop the ``-s`` flag after a successful pre-release install.
    """
    container_home = CONTAINER_HOME
    script = f'''
import json, os

for path in ["{container_home}/.claude.json", "{container_home}/.claude/.claude.json"]:
    if not os.path.exists(path):
        continue
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        continue
    fmcp = data.get("mcpServers", {{}}).get("foundry-mcp")
    if not fmcp:
        continue
    args = fmcp.get("args", [])
    if isinstance(args, list) and "-s" in args:
        args.remove("-s")
        fmcp["args"] = args
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\\n")
'''
    result = subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, "-i", container_id,
         "python3", "-c", script],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )
    if result.returncode != 0:
        log_debug(f"Failed to update MCP config for pre-release: {result.stderr}")


def upgrade_foundry_mcp_prerelease(
    container_id: str,
    *,
    pin_version: str | None = None,
    required: bool = False,
) -> str:
    """Install a foundry-mcp pre-release inside the container.

    Args:
        container_id: Docker container ID or name (e.g. ``<container>-dev-1``).
        pin_version: If set, install this exact version (e.g. ``"1.2.0a3"``).
            When *None*, installs the latest pre-release.
        required: If True, raise :class:`click.ClickException` on failure
            instead of falling back to stable silently.

    Returns:
        The installed version string, or empty string on soft failure.

    Raises:
        click.ClickException: When *required* is True and the upgrade fails.
    """
    if pin_version:
        log_info(f"Installing foundry-mcp=={pin_version} (pinned pre-release)...")
        pkg_spec = f"foundry-mcp=={pin_version}"
    else:
        log_info("Upgrading foundry-mcp to latest pre-release...")
        pkg_spec = "foundry-mcp"

    cmd = [
        "docker", "exec", "-u", CONTAINER_USER, container_id,
        "pip", "install", "--pre", "--upgrade", "--no-warn-script-location", pkg_spec,
    ]
    if get_sandbox_verbose():
        print(f"+ {' '.join(cmd)}", file=sys.stderr)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=TIMEOUT_PIP_INSTALL,
        )
    except subprocess.TimeoutExpired:
        if required:
            raise click.ClickException("foundry-mcp pre-release upgrade timed out")
        log_warn("foundry-mcp pre-release upgrade timed out (continuing with stable)")
        return ""

    if result.returncode != 0:
        if required:
            detail = result.stderr.strip() if result.stderr else "unknown error"
            raise click.ClickException(f"foundry-mcp pre-release upgrade failed: {detail}")
        log_warn("foundry-mcp pre-release upgrade failed (continuing with stable)")
        if result.stderr:
            log_debug(f"pip stderr: {result.stderr.strip()}")
        return ""

    version = _get_installed_version(container_id)
    log_info(f"foundry-mcp {version or 'pre-release'} installed successfully")

    # Remove the -s (skip user site-packages) flag from the MCP server config.
    # PIP_USER=1 installs the pre-release to ~/.local/ (user site-packages),
    # but the MCP config uses "python -s" which skips that directory.  Without
    # this fix the MCP server would silently keep running the global stable
    # version even after a successful pre-release upgrade.
    _enable_user_site_packages(container_id)

    return version
