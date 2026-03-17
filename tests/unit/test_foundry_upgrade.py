"""Unit tests for foundry_sandbox.foundry_upgrade.

The module is now a no-op stub — upgrade_foundry_mcp_prerelease always
returns empty string. Tests verify the no-op behavior.
"""

from __future__ import annotations

from foundry_sandbox.foundry_upgrade import upgrade_foundry_mcp_prerelease


def test_returns_empty_string() -> None:
    """No-op stub always returns empty string."""
    assert upgrade_foundry_mcp_prerelease("ctr-1") == ""


def test_returns_empty_with_pin_version() -> None:
    """pin_version is accepted but ignored."""
    assert upgrade_foundry_mcp_prerelease("ctr-1", pin_version="1.2.0a3") == ""


def test_returns_empty_when_required() -> None:
    """required=True is accepted but does not raise."""
    assert upgrade_foundry_mcp_prerelease("ctr-1", required=True) == ""
