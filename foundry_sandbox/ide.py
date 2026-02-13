"""IDE detection and launch utilities.

Migrated from lib/ide.sh. Provides IDE detection, launch, and interactive
selection for attaching editors to sandbox worktrees.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

import click

from foundry_sandbox.tui import _is_noninteractive

# IDE commands in preference order (matching lib/ide.sh)
IDE_COMMANDS = ("cursor", "zed", "code")

# Display names for IDEs
_DISPLAY_NAMES: dict[str, str] = {
    "cursor": "Cursor",
    "zed": "Zed",
    "code": "VS Code",
}


def ide_exists(ide: str) -> bool:
    """Check if an IDE command is available on PATH."""
    return shutil.which(ide) is not None


def detect_available_ides() -> list[str]:
    """Detect available IDEs on the system.

    Returns:
        List of available IDE command names in preference order.
    """
    return [ide for ide in IDE_COMMANDS if ide_exists(ide)]


def ide_display_name(ide: str) -> str:
    """Get the human-readable display name for an IDE."""
    return _DISPLAY_NAMES.get(ide, ide)


def launch_ide(ide: str, path: str) -> None:
    """Launch an IDE with the given path in the background.

    Args:
        ide: IDE command name (e.g., "cursor", "code").
        path: Path to open in the IDE.
    """
    display = ide_display_name(ide)
    click.echo(f"Launching {display}...")
    try:
        proc = subprocess.Popen(
            [ide, path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        # Fire-and-forget: the IDE runs in its own session and we intentionally
        # never wait on it.  Setting returncode silences Python's ResourceWarning
        # on GC; poll() would also return None immediately since the IDE is still
        # starting up, so we explicitly mark it as "not our problem".
        proc.returncode = 0  # intentional: suppress ResourceWarning for detached process
    except (OSError, FileNotFoundError):
        click.echo(f"Failed to launch {display}.", err=True)


def auto_launch_ide(ide_name: str, path: str) -> bool:
    """Launch a specific IDE by name.

    Args:
        ide_name: IDE name (e.g., "cursor", "code").
        path: Path to open.

    Returns:
        True if IDE was launched, False if not found or empty name.
    """
    if not ide_name or ide_name == "auto":
        return False

    if ide_exists(ide_name):
        launch_ide(ide_name, path)
        return True

    display = ide_display_name(ide_name)
    click.echo(f"Warning: {display} ({ide_name}) not found")
    return False


def prompt_ide_selection(path: str, sandbox_name: str) -> bool:
    """Interactive IDE selection prompt.

    Detects available IDEs and prompts the user to select one.
    In non-interactive mode or when no IDEs are available, returns False.

    Args:
        path: Path to open in the IDE.
        sandbox_name: Sandbox name (for display).

    Returns:
        True if an IDE was launched, False otherwise.
    """
    if not sys.stdin.isatty() or _is_noninteractive():
        return False

    available = detect_available_ides()
    if not available:
        return False

    options = [ide_display_name(ide) for ide in available]
    options.append("Terminal only")

    click.echo()
    click.echo("  Launch an editor?")
    click.echo()

    # Numbered selection
    for i, opt in enumerate(options, 1):
        suffix = " (default)" if i == len(options) else ""
        click.echo(f"  {i}) {opt}{suffix}")
    click.echo()

    try:
        raw = input(f"  Select [{len(options)}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return False

    if not raw:
        choice = len(options)
    else:
        try:
            choice = int(raw)
        except ValueError:
            choice = len(options)

    if choice < 1 or choice > len(options):
        choice = len(options)

    selection = options[choice - 1]

    if selection == "Terminal only":
        return False

    # Map display name back to command
    for ide in available:
        if ide_display_name(ide) == selection:
            launch_ide(ide, path)
            return True

    return False
