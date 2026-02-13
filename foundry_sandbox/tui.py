"""Interactive prompt utilities for foundry sandbox.

This module provides reusable interactive prompts using gum (preferred)
with Click fallback. Replaces the shell scripts lib/prompt.sh.

All functions respect SANDBOX_NONINTERACTIVE and SANDBOX_ASSUME_YES
environment variables for automated/batch operations.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from functools import lru_cache
from typing import Optional

import click


@lru_cache(maxsize=1)
def _has_gum() -> bool:
    """Check if gum is available on PATH (cached)."""
    return shutil.which("gum") is not None


def _run_gum(*args: str, input_text: str | None = None) -> tuple[bool, str]:
    """Run a gum command, return (success, stdout)."""
    try:
        result = subprocess.run(
            ["gum", *args],
            stdout=subprocess.PIPE,
            text=True,
            check=False,
            input=input_text,
            timeout=60,
        )
        return result.returncode == 0, result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False, ""


def _is_noninteractive() -> bool:
    """Check if running in non-interactive mode.

    Returns:
        True if SANDBOX_NONINTERACTIVE=1 or SANDBOX_ASSUME_YES=1.
    """
    return (
        os.environ.get("SANDBOX_NONINTERACTIVE") == "1"
        or os.environ.get("SANDBOX_ASSUME_YES") == "1"
    )


def tui_input(prompt: str, default: Optional[str] = None) -> str:
    """Prompt for text input with optional default value.

    Args:
        prompt: The prompt message to display.
        default: Optional default value if user enters nothing.

    Returns:
        The user's input or the default value.

    Raises:
        ValueError: If non-interactive mode and no default provided.
    """
    if _is_noninteractive():
        if default is None:
            raise ValueError(f"Cannot prompt for input in non-interactive mode: {prompt}")
        return default

    if _has_gum():
        gum_args = ["input", "--header", prompt, "--placeholder", "Type here..."]
        if default is not None:
            gum_args.extend(["--value", default])
        ok, value = _run_gum(*gum_args)
        if ok:
            value = value if value else (default or "")
            click.echo(f"  > {value}")
            return value

    result: str = click.prompt(prompt, default=default, type=str)
    return result


def tui_question(prompt: str, choices: list[str]) -> str:
    """Prompt for a choice from a list of options.

    Args:
        prompt: The prompt message to display.
        choices: List of valid choices.

    Returns:
        The selected choice.
    """
    if _is_noninteractive():
        return choices[0]

    if _has_gum():
        ok, value = _run_gum("choose", "--header", prompt, *choices)
        if ok and value in choices:
            click.echo(f"  > {value}")
            return value

    result: str = click.prompt(
        prompt,
        type=click.Choice(choices, case_sensitive=False),
        show_choices=True
    )
    return result


def tui_confirm(prompt: str, default_yes: bool = True) -> bool:
    """Prompt for yes/no confirmation.

    Args:
        prompt: The confirmation message to display.
        default_yes: Whether to default to yes (True) or no (False).

    Returns:
        True if confirmed, False otherwise.
    """
    if _is_noninteractive():
        return default_yes

    if _has_gum():
        gum_args = ["confirm", prompt]
        if default_yes:
            gum_args.append("--default=yes")
        ok, _ = _run_gum(*gum_args)
        click.echo(f"  > {'Yes' if ok else 'No'}")
        return ok

    return click.confirm(prompt, default=default_yes)


def tui_choose(prompt: str, options: list[str], default: Optional[str] = None) -> str:
    """Display options and prompt user to choose one.

    Args:
        prompt: The prompt message to display.
        options: List of options to choose from.
        default: Optional default/pre-selected option.

    Returns:
        The selected option string.

    Raises:
        ValueError: If options list is empty.
    """
    if not options:
        raise ValueError("Cannot choose from empty options list")

    if _is_noninteractive():
        if default and default in options:
            return default
        return options[0]

    if _has_gum():
        click.echo()
        gum_args = ["choose", "--header", prompt]
        if default and default in options:
            gum_args.extend(["--selected", default])
        gum_args.extend(options)
        ok, value = _run_gum(*gum_args)
        if ok and value in options:
            click.echo(f"  > {value}")
            return value

    # Click fallback: numbered options
    click.echo()
    click.echo(prompt)
    default_index = 1
    for i, option in enumerate(options, start=1):
        click.echo(f"  {i}. {option}")
        if default and option == default:
            default_index = i
    click.echo()

    choice = click.prompt(
        "Enter number",
        type=click.IntRange(1, len(options)),
        default=default_index
    )

    return options[int(choice) - 1]


def tui_header(title: str) -> None:
    """Display a styled header.

    Args:
        title: The header text to display.
    """
    if _has_gum():
        ok, output = _run_gum(
            "style",
            "--border", "rounded",
            "--border-foreground", "12",
            "--padding", "0 2",
            "--bold",
            title,
        )
        if ok:
            click.echo()
            click.echo(output)
            return

    # ASCII box fallback
    width = len(title) + 4
    click.echo()
    click.echo(f"  {'─' * width}")
    click.echo(f"  │ {title} │")
    click.echo(f"  {'─' * width}")


def tui_summary(title: str, content: str) -> None:
    """Display a styled summary box.

    Args:
        title: The summary title.
        content: The summary content (may be multi-line).
    """
    if _has_gum():
        ok_title, styled_title = _run_gum(
            "style",
            "--bold",
            "--foreground", "12",
            title,
        )
        ok_box, styled_box = _run_gum(
            "style",
            "--border", "rounded",
            "--border-foreground", "8",
            "--padding", "0 2",
            content,
        )
        if ok_title and ok_box:
            click.echo()
            click.echo(styled_title)
            click.echo(styled_box)
            return

    # ASCII box fallback
    lines = content.split("\n")
    max_width = max(len(line) for line in lines) if lines else 0
    max_width = max(max_width, len(title))

    click.echo()
    click.echo(f"  {title}")
    click.echo(f"  {'─' * (max_width + 4)}")
    for line in lines:
        click.echo(f"  │ {line:<{max_width}} │")
    click.echo(f"  {'─' * (max_width + 4)}")


def tui_step(number: int, total: int, label: str) -> None:
    """Display a styled step header.

    Args:
        number: Current step number.
        total: Total number of steps.
        label: Step label/description.
    """
    step_text = f"Step {number}/{total}: {label}"
    click.echo()
    click.secho(f"  {step_text}", bold=True, fg="bright_blue")


def tui_spin(title: str, *cmd: str) -> tuple[bool, str]:
    """Run a command with a spinner.

    Args:
        title: The spinner title to display.
        *cmd: Command and arguments to run.

    Returns:
        Tuple of (success, stdout).
    """
    if _has_gum():
        try:
            result = subprocess.run(
                ["gum", "spin", "--spinner", "dot", "--title", title, "--", *cmd],
                stdout=subprocess.PIPE,
                text=True,
                check=False,
                timeout=120,
            )
            return result.returncode == 0, result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Fallback: just run the command with a message
    click.echo(f"  {title}...")
    try:
        result = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        return result.returncode == 0, result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False, ""
