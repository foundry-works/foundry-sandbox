"""Builtin MCP server registry.

Each entry returns a dict fragment compatible with Claude Code's .mcp.json
format. The compiler merges all server fragments into a single file at
/workspace/.mcp.json.
"""

from __future__ import annotations

import copy
from typing import Any

_BUILTIN_REGISTRY: dict[str, dict[str, Any]] = {
    "github": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-github"],
    },
    "filesystem": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
    },
    "memory": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-memory"],
    },
}


def get_builtin(name: str) -> dict[str, Any] | None:
    """Look up a builtin MCP server spec by name.

    Returns a deep copy so callers can mutate without affecting the registry.
    Returns None if the name is not in the registry.
    """
    spec = _BUILTIN_REGISTRY.get(name)
    return copy.deepcopy(spec) if spec else None


def list_builtins() -> list[str]:
    """Return sorted list of registered builtin names."""
    return sorted(_BUILTIN_REGISTRY.keys())
