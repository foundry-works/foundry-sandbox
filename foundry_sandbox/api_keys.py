"""API key validation for foundry-sandbox.

Replaces lib/api_keys.sh (323 lines). Read-only environment variable checking
for AI provider keys, search provider keys, and CLI authentication status.
No side effects — only reads env vars and auth files.

No Click or Pydantic imports at module level (bridge-callable constraint).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from foundry_sandbox.constants import TIMEOUT_LOCAL_CMD
from foundry_sandbox.utils import log_step


# ============================================================================
# AI Provider Key Constants
# ============================================================================

AI_PROVIDER_KEYS = ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY")
"""Claude authentication — at least one required."""


# ============================================================================
# Key Detection Functions
# ============================================================================


def check_any_ai_key() -> bool:
    """Check if at least one AI provider key is set.

    Returns:
        True if any AI provider key is present in the environment.
    """
    return any(os.environ.get(key) for key in AI_PROVIDER_KEYS)


def has_claude_key() -> bool:
    """Check if Claude authentication is available.

    Returns:
        True if CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY is set.
    """
    return bool(
        os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
        or os.environ.get("ANTHROPIC_API_KEY")
    )


def has_gemini_key() -> bool:
    """Check if Gemini OAuth credentials exist.

    Checks for OAuth credentials file or a non-placeholder GEMINI_API_KEY.

    Returns:
        True if Gemini auth is available.
    """
    if (Path.home() / ".gemini" / "oauth_creds.json").is_file():
        return True
    api_key = os.environ.get("GEMINI_API_KEY", "")
    return bool(api_key and api_key != "CREDENTIAL_PROXY_PLACEHOLDER" and not api_key.startswith("CRED_PROXY_"))


def has_opencode_key() -> bool:
    """Check if OpenCode auth file exists.

    Returns:
        True if auth file is present.
    """
    return (Path.home() / ".local" / "share" / "opencode" / "auth.json").is_file()


def has_codex_key() -> bool:
    """Check if Codex authentication is available.

    Returns:
        True if auth file exists or OPENAI_API_KEY is set.
    """
    if (Path.home() / ".codex" / "auth.json").is_file():
        return True
    return bool(os.environ.get("OPENAI_API_KEY"))


def has_zai_key() -> bool:
    """Check if ZAI (Zhipu) API key is available.

    Excludes proxy placeholder values.

    Returns:
        True if a real ZHIPU_API_KEY is set.
    """
    key = os.environ.get("ZHIPU_API_KEY", "")
    if not key:
        return False
    return key not in ("CREDENTIAL_PROXY_PLACEHOLDER", "PROXY_PLACEHOLDER_OPENCODE") and not key.startswith("CRED_PROXY_")


def opencode_enabled() -> bool:
    """Check if OpenCode is explicitly enabled and authenticated.

    Returns:
        True if SANDBOX_ENABLE_OPENCODE=1 and auth is present.
    """
    return os.environ.get("SANDBOX_ENABLE_OPENCODE", "0") == "1" and has_opencode_key()


def check_any_search_key() -> bool:
    """Check if at least one search provider is configured.

    Returns:
        True if TAVILY_API_KEY or PERPLEXITY_API_KEY is set.
    """
    return bool(
        os.environ.get("TAVILY_API_KEY")
        or os.environ.get("PERPLEXITY_API_KEY")
    )


# ============================================================================
# Auth Conflict Detection
# ============================================================================


def warn_claude_auth_conflict() -> str:
    """Check for multiple Claude auth modes and return warning if conflict found.

    Returns:
        Warning message string, or empty string if no conflict.
    """
    if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN") and os.environ.get("ANTHROPIC_API_KEY"):
        return (
            "Note: Both CLAUDE_CODE_OAUTH_TOKEN and ANTHROPIC_API_KEY are set.\n"
            "  Claude Code will prefer OAuth; consider unsetting one to avoid ambiguity."
        )
    return ""


# ============================================================================
# Status & Warning Messages
# ============================================================================


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

    conflict = warn_claude_auth_conflict()
    return True, conflict


def get_optional_cli_warnings() -> list[str]:
    """Get warnings for optional CLIs that are not configured.

    Returns:
        List of warning message strings.
    """
    warnings: list[str] = []

    if not has_gemini_key():
        warnings.append(
            "Note: Gemini CLI not configured\n"
            "  Run 'gemini auth' or set GEMINI_API_KEY"
        )

    if os.environ.get("SANDBOX_ENABLE_OPENCODE", "0") == "1":
        if not has_opencode_key():
            warnings.append(
                "Note: OpenCode CLI not configured\n"
                "  Run 'opencode auth login' to authenticate"
            )

    if not has_codex_key():
        warnings.append(
            "Note: Codex CLI not configured\n"
            "  Run 'codex auth' or set OPENAI_API_KEY"
        )

    return warnings


def get_cli_status() -> list[str]:
    """Get CLI configuration status lines for sandbox setup display.

    Returns:
        List of status strings (e.g., "Claude: configured").
    """
    lines: list[str] = []

    # Claude (always configured at this point)
    lines.append("Claude: configured")

    # GitHub CLI
    gh_ok = False
    if shutil.which("gh"):
        try:
            result = subprocess.run(
                ["gh", "auth", "status"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=TIMEOUT_LOCAL_CMD,
            )
            gh_ok = result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            pass
    lines.append(f"GitHub CLI: {'configured' if gh_ok else 'not configured'}")

    # Gemini
    lines.append(f"Gemini: {'configured' if has_gemini_key() else 'not configured'}")

    # Codex
    lines.append(f"Codex: {'configured' if has_codex_key() else 'not configured'}")

    # OpenCode (only if enabled)
    if os.environ.get("SANDBOX_ENABLE_OPENCODE") == "1":
        lines.append(
            f"OpenCode: {'configured' if has_opencode_key() else 'not configured'}"
        )

    # Search providers
    providers: list[str] = []
    if os.environ.get("TAVILY_API_KEY"):
        providers.append("Tavily")
    if os.environ.get("PERPLEXITY_API_KEY"):
        providers.append("Perplexity")
    if providers:
        lines.append(f"Search: {', '.join(providers)}")
    else:
        lines.append("Search: not configured")

    return lines


def show_cli_status() -> None:
    """Display CLI configuration status using log_step."""
    for line in get_cli_status():
        log_step(line)


def get_missing_keys_warning() -> str:
    """Get warning message about missing keys (both AI and search).

    Returns:
        Warning message string, or empty string if all keys present.
    """
    parts: list[str] = []
    missing_ai = not check_any_ai_key()
    missing_search = not check_any_search_key()

    if missing_ai:
        parts.append(
            "Warning: Claude authentication not found.\n"
            "\n"
            "Expected one of:\n"
            "  - CLAUDE_CODE_OAUTH_TOKEN (run: claude setup-token)\n"
            "  - ANTHROPIC_API_KEY"
        )

    if missing_search:
        parts.append(
            "Warning: No search provider API keys found.\n"
            "Deep research features (foundry-mcp) will be unavailable.\n"
            "\n"
            "Expected at least one of:\n"
            "  - TAVILY_API_KEY\n"
            "  - PERPLEXITY_API_KEY"
        )

    if missing_ai or missing_search:
        parts.append(
            "Set the required environment variables before running:\n"
            "  export CLAUDE_CODE_OAUTH_TOKEN=\"your-token\"\n"
            "  export ANTHROPIC_API_KEY=\"your-key\"\n"
            "  export TAVILY_API_KEY=\"your-key\"\n"
            "\n"
            "See .env.example for all supported keys."
        )

    return "\n\n".join(parts)


def check_api_keys_status() -> dict[str, Any]:
    """Full API key check returning structured status.

    This is the Python equivalent of check_api_keys_with_prompt, but returns
    data instead of prompting (the prompt happens in the CLI layer).

    Returns:
        Dictionary with:
          - has_ai_key: bool
          - has_search_key: bool
          - conflict_warning: str (empty if none)
          - missing_warning: str (empty if none)
          - can_proceed: bool (True if AI key present)
    """
    has_ai = check_any_ai_key()
    has_search = check_any_search_key()
    conflict = warn_claude_auth_conflict() if has_ai else ""
    missing = get_missing_keys_warning()

    return {
        "has_ai_key": has_ai,
        "has_search_key": has_search,
        "conflict_warning": conflict,
        "missing_warning": missing,
        "can_proceed": has_ai,
    }


# ============================================================================
# GitHub Token Export
# ============================================================================


def export_gh_token() -> str:
    """Extract gh CLI token from system keyring/keychain.

    Returns:
        GitHub token string, or empty string if not available.
    """
    # Check if already set
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN", "")
    if token:
        return token

    # Try gh CLI
    if shutil.which("gh"):
        try:
            status = subprocess.run(
                ["gh", "auth", "status"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=TIMEOUT_LOCAL_CMD,
            )
            if status.returncode == 0:
                result = subprocess.run(
                    ["gh", "auth", "token"],
                    capture_output=True, text=True, check=False,
                    timeout=TIMEOUT_LOCAL_CMD,
                )
                token = result.stdout.strip()
                if token:
                    return token
        except (OSError, subprocess.SubprocessError):
            pass

    return ""

