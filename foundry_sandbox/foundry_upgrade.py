"""Stub module — foundry-mcp pre-release upgrade has been removed.

The skills system replaces per-sandbox foundry-mcp management.
This module exists only for backward compatibility with imports.
"""
from __future__ import annotations

from foundry_sandbox.utils import log_debug


def upgrade_foundry_mcp_prerelease(
    container_id: str,
    *,
    pin_version: str | None = None,
    required: bool = False,
) -> str:
    """No-op. Returns empty string.

    The skills system replaces per-sandbox foundry-mcp management.
    """
    log_debug("upgrade_foundry_mcp_prerelease is a no-op (skills system replaces it)")
    return ""
