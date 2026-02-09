"""Interactive prompt utilities for foundry sandbox.

This module provides reusable interactive prompts using Click,
replacing the shell scripts lib/prompt.sh.

All functions respect SANDBOX_NONINTERACTIVE and SANDBOX_ASSUME_YES
environment variables for automated/batch operations.
"""

from __future__ import annotations

import os
from typing import Optional

import click


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

    return click.prompt(prompt, default=default, type=str)


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

    return click.prompt(
        prompt,
        type=click.Choice(choices, case_sensitive=False),
        show_choices=True
    )


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

    return click.confirm(prompt, default=default_yes)


def tui_choose(prompt: str, options: list[str]) -> str:
    """Display numbered options and prompt user to choose one.

    Args:
        prompt: The prompt message to display.
        options: List of options to choose from.

    Returns:
        The selected option string.

    Raises:
        ValueError: If options list is empty.
    """
    if not options:
        raise ValueError("Cannot choose from empty options list")

    if _is_noninteractive():
        return options[0]

    # Display numbered options
    click.echo()
    click.echo(prompt)
    for i, option in enumerate(options, start=1):
        click.echo(f"  {i}. {option}")
    click.echo()

    # Prompt for selection
    choice = click.prompt(
        "Enter number",
        type=click.IntRange(1, len(options)),
        default=1
    )

    return options[choice - 1]
