"""Logging and formatting utilities for foundry sandbox.

This module provides logging and text formatting utilities that replace
the shell scripts lib/utils.sh, lib/format.sh, and lib/runtime.sh.
"""

from __future__ import annotations

import os
import sys


# Color codes - respect TERM environment variable
def _should_use_colors() -> bool:
    """Check if colors should be used based on TERM environment variable."""
    term = os.environ.get("TERM", "")
    if not term or term == "dumb":
        return False
    return True


_USE_COLORS = _should_use_colors()

# ANSI color codes
BOLD = "\033[1m" if _USE_COLORS else ""
RESET = "\033[0m" if _USE_COLORS else ""
RED = "\033[91m" if _USE_COLORS else ""
YELLOW = "\033[93m" if _USE_COLORS else ""
BLUE = "\033[94m" if _USE_COLORS else ""
GREEN = "\033[92m" if _USE_COLORS else ""


def log_info(msg: str) -> None:
    """Log an info message to stdout.

    Args:
        msg: The message to log.
    """
    print(msg)


def log_debug(msg: str) -> None:
    """Log a debug message (only if SANDBOX_DEBUG=1).

    Args:
        msg: The message to log.
    """
    if os.environ.get("SANDBOX_DEBUG") == "1":
        print(f"DEBUG: {msg}")


def log_warn(msg: str) -> None:
    """Log a warning message to stderr.

    Args:
        msg: The message to log.
    """
    print(f"Warning: {msg}", file=sys.stderr)


def log_error(msg: str) -> None:
    """Log an error message to stderr.

    Args:
        msg: The message to log.
    """
    print(f"Error: {msg}", file=sys.stderr)


def log_section(msg: str) -> None:
    """Log a section header with arrow and bold formatting.

    Args:
        msg: The section title.
    """
    print()
    print(f"{BOLD}▸ {msg}{RESET}")


def log_step(msg: str) -> None:
    """Log an indented step message (2 spaces indent).

    Args:
        msg: The step message.
    """
    print(f"  {msg}")


# Formatting helper functions (pure functions, not logging)


def format_kv(key: str, value: str) -> str:
    """Format a key-value pair with 2 spaces indent.

    Args:
        key: The key name.
        value: The value.

    Returns:
        Formatted string "  {key}: {value}".
    """
    return f"  {key}: {value}"


def format_table_row(
    name: str, *cols: str, name_width: int = 30
) -> str:
    """Format a table row with fixed column widths.

    Args:
        name: The name column (leftmost).
        *cols: Additional columns to display.
        name_width: Width of the name column (default 30 chars).

    Returns:
        Formatted table row string.
    """
    # Start with the name column, left-aligned, padded to name_width
    row = f"  {name:<{name_width}}"

    # Append additional columns
    for col in cols:
        row += f" {col}"

    return row
