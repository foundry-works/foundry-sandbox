"""Non-interactive mode detection for foundry sandbox."""

from __future__ import annotations

import os


def _is_noninteractive() -> bool:
    """Check if running in non-interactive mode.

    Returns:
        True if SANDBOX_NONINTERACTIVE=1 or SANDBOX_ASSUME_YES=1.
    """
    return (
        os.environ.get("SANDBOX_NONINTERACTIVE") == "1"
        or os.environ.get("SANDBOX_ASSUME_YES") == "1"
    )
