"""API key validation for foundry-sandbox.

Read-only environment variable checking for AI provider keys
and CLI authentication status.
No side effects — only reads env vars and auth files.

No Click or Pydantic imports at module level (bridge-callable constraint).
"""

from __future__ import annotations

import os
from pathlib import Path


def has_claude_key() -> bool:
    """Check if Claude authentication is available."""
    return bool(
        os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
        or os.environ.get("ANTHROPIC_API_KEY")
    )


def has_opencode_key() -> bool:
    """Check if OpenCode auth file exists."""
    return (Path.home() / ".local" / "share" / "opencode" / "auth.json").is_file()


def has_zai_key() -> bool:
    """Check if ZAI (Zhipu) API key is available."""
    return bool(os.environ.get("ZHIPU_API_KEY", ""))


def check_claude_key_required() -> tuple[bool, str]:
    """Check that Claude authentication is present (mandatory).

    Returns:
        Tuple of (has_key, message). message contains error or conflict warning.
    """
    if not has_claude_key():
        msg = (
            "Error: Claude Code requires authentication.\n"
            "\n"
            "Set one of:\n"
            "  - CLAUDE_CODE_OAUTH_TOKEN (run: claude setup-token)\n"
            "  - ANTHROPIC_API_KEY"
        )
        return False, msg

    # Warn if both are set
    if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN") and os.environ.get("ANTHROPIC_API_KEY"):
        return True, (
            "Note: Both CLAUDE_CODE_OAUTH_TOKEN and ANTHROPIC_API_KEY are set.\n"
            "  Claude Code will prefer OAuth; consider unsetting one to avoid ambiguity."
        )
    return True, ""
