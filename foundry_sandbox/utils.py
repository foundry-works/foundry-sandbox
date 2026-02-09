"""Logging and formatting utilities for foundry sandbox.

This module provides logging and text formatting utilities that replace
the shell scripts lib/utils.sh, lib/format.sh, and lib/runtime.sh.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Optional


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


class SandboxFormatter(logging.Formatter):
    """Custom formatter that matches shell script output format."""

    def __init__(self, use_colors: bool = True) -> None:
        """Initialize the formatter.

        Args:
            use_colors: Whether to use ANSI color codes in output.
        """
        super().__init__()
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record.

        Args:
            record: The log record to format.

        Returns:
            The formatted log message.
        """
        # Get the base message
        msg = record.getMessage()

        # Add log level prefix for debug and error
        if record.levelno == logging.DEBUG:
            return f"DEBUG: {msg}"
        elif record.levelno == logging.ERROR:
            return f"Error: {msg}"
        elif record.levelno == logging.WARNING:
            return f"Warning: {msg}"

        # Info level has no prefix
        return msg


# Configure module-level logger
_logger = logging.getLogger("foundry_sandbox")
_logger.setLevel(logging.DEBUG)

# Only add handler if one doesn't exist
if not _logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _formatter = SandboxFormatter(use_colors=_USE_COLORS)
    _handler.setFormatter(_formatter)
    _logger.addHandler(_handler)

    # Add stderr handler for warnings and errors
    _stderr_handler = logging.StreamHandler(sys.stderr)
    _stderr_handler.setLevel(logging.WARNING)
    _stderr_handler.setFormatter(_formatter)
    _logger.addHandler(_stderr_handler)


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
