"""IDE detection, resolution, and launch utilities.

Provides IDE resolution (alias / explicit path / bare command), launch, and
interactive selection for attaching editors to sandbox worktrees.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Literal

import click

from foundry_sandbox.utils import _is_noninteractive

# Known IDE aliases in preference order
IDE_COMMANDS = ("cursor", "zed", "code", "vscode", "code-insiders", "windsurf")

# Display names for known IDEs
_DISPLAY_NAMES: dict[str, str] = {
    "cursor": "Cursor",
    "zed": "Zed",
    "code": "VS Code",
    "vscode": "VS Code",
    "code-insiders": "VS Code Insiders",
    "windsurf": "Windsurf",
}

# macOS application names for `open -a` fallback
_MACOS_APP_NAMES: dict[str, str] = {
    "cursor": "Cursor",
    "zed": "Zed",
    "code": "Visual Studio Code",
    "vscode": "Visual Studio Code",
    "code-insiders": "Visual Studio Code - Insiders",
    "windsurf": "Windsurf",
}


# ---------------------------------------------------------------------------
# IdeSpec — resolved IDE descriptor
# ---------------------------------------------------------------------------


@dataclass
class IdeSpec:
    kind: Literal["alias", "path", "command"]
    name: str       # canonical command or alias
    display: str    # human-readable name
    executable: str # what to actually run


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def resolve_ide(value: str) -> IdeSpec | None:
    """Resolve an IDE string into an IdeSpec.

    Resolution order:
      1. Contains ``/`` → explicit executable path (must exist + be executable).
      2. Matches a known alias → alias-aware spec.
      3. Bare command → resolve via PATH.

    Returns None if the value cannot be resolved.
    """
    if not value:
        return None

    # Explicit executable path
    if "/" in value:
        path = value
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return IdeSpec(
                kind="path",
                name=os.path.basename(path),
                display=os.path.basename(path),
                executable=path,
            )
        return None

    # Known alias
    if value in _DISPLAY_NAMES:
        exe = shutil.which(value)
        executable = exe if exe else value
        return IdeSpec(
            kind="alias",
            name=value,
            display=_DISPLAY_NAMES[value],
            executable=executable,
        )

    # Bare command on PATH
    exe = shutil.which(value)
    if exe:
        return IdeSpec(
            kind="command",
            name=value,
            display=value,
            executable=exe,
        )

    return None


# ---------------------------------------------------------------------------
# Launch helpers
# ---------------------------------------------------------------------------


def _try_macos_open(spec: IdeSpec, path: str, extra_args: list[str]) -> bool:
    """Try to launch an IDE via macOS ``open -a`` as a fallback."""
    if platform.system() != "Darwin":
        return False
    if spec.kind != "alias":
        return False
    app_name = _MACOS_APP_NAMES.get(spec.name)
    if not app_name:
        return False
    try:
        cmd = ["open", "-a", app_name, "--args", *extra_args, path]
        ret = subprocess.call(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return ret == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _launch_via_cli(executable: str, path: str, extra_args: list[str], display: str) -> bool:
    """Launch an IDE binary directly.

    Returns True if the process started successfully.
    """
    try:
        cmd = [executable, *extra_args, path]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        time.sleep(0.5)
        ret = proc.poll()
        if ret is not None and ret != 0:
            stderr_out = ""
            if proc.stderr:
                stderr_out = proc.stderr.read().decode("utf-8", errors="replace").strip()
                proc.stderr.close()
            if stderr_out:
                click.echo(f"  {display} error: {stderr_out}", err=True)
            return False
        if proc.stderr:
            proc.stderr.close()
        proc.returncode = 0
        return True
    except (OSError, FileNotFoundError):
        return False


def _save_last_ide(name: str) -> None:
    """Persist the last successfully launched IDE name."""
    try:
        from foundry_sandbox.state import save_last_ide as _save
        _save(name)
    except Exception:
        pass  # non-critical — never block IDE launch


def launch_ide(spec: IdeSpec, path: str, extra_args: list[str] | None = None) -> bool:
    """Launch an IDE given a resolved IdeSpec.

    On macOS, alias specs prefer ``open -a`` for reliable app activation.
    Falls back to CLI for all cases.

    Returns True on success, False on failure.
    """
    args = extra_args or []
    click.echo(f"Launching {spec.display}...")

    # macOS alias: try open -a first
    if _try_macos_open(spec, path, args):
        _save_last_ide(spec.name)
        return True

    # CLI launch (all platforms)
    if _launch_via_cli(spec.executable, path, args, spec.display):
        _save_last_ide(spec.name)
        return True

    click.echo(f"Failed to launch {spec.display}.", err=True)
    return False


# ---------------------------------------------------------------------------
# Legacy public API (preserved for backward compatibility)
# ---------------------------------------------------------------------------


def ide_exists(ide: str) -> bool:
    """Check if an IDE command is available on PATH."""
    return shutil.which(ide) is not None


def detect_available_ides() -> list[str]:
    """Detect available IDEs on the system in preference order."""
    return [ide for ide in IDE_COMMANDS if ide_exists(ide)]


def ide_display_name(ide: str) -> str:
    """Get the human-readable display name for an IDE."""
    return _DISPLAY_NAMES.get(ide, ide)


def auto_launch_ide(ide_name: str, path: str) -> bool:
    """Launch a specific IDE by name (legacy API).

    Returns True if IDE was launched, False if not found or empty name.
    """
    if not ide_name or ide_name == "auto":
        return False

    spec = resolve_ide(ide_name)
    if spec is None:
        display = _DISPLAY_NAMES.get(ide_name, ide_name)
        click.echo(f"Warning: {display} ({ide_name}) not found")
        return False

    return launch_ide(spec, path)


def prompt_ide_selection(path: str) -> bool:
    """Interactive IDE selection prompt.

    Detects available IDEs and prompts the user to select one.
    In non-interactive mode or when no IDEs are available, returns False.
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

    for ide in available:
        if ide_display_name(ide) == selection:
            spec = resolve_ide(ide)
            if spec:
                return launch_ide(spec, path)
            return False

    return False
