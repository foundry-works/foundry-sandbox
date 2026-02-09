"""JSON configuration file operations and utilities.

Provides utilities for loading, merging, and manipulating JSON configuration files,
plus JSON formatting helpers for shell integration.

Migrated from lib/python/json_config.py and lib/json.sh.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from foundry_sandbox._bridge import bridge_main


def load_json(path: str) -> dict[str, Any]:
    """Load a JSON file, returning empty dict on missing/invalid file.

    Args:
        path: Path to JSON file to load.

    Returns:
        Dictionary containing JSON data, or empty dict if file is missing/invalid.
    """
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return {}


def write_json(path: str, data: dict[str, Any]) -> None:
    """Write JSON data to a file, creating parent directories as needed.

    Args:
        path: Path to write JSON file.
        data: Dictionary to serialize as JSON.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Deep merge two dicts. Overlay values take precedence for non-dict conflicts.

    Args:
        base: Base dictionary.
        overlay: Dictionary to merge into base.

    Returns:
        Merged dictionary where overlay wins conflicts.
    """
    result = base.copy()
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def deep_merge_no_overwrite(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Deep merge where overlay only fills in missing keys (base wins conflicts).

    Args:
        base: Base dictionary (takes precedence).
        overlay: Dictionary to merge into base.

    Returns:
        Merged dictionary where base wins conflicts.
    """
    result = base.copy()
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_no_overwrite(result[key], value)
        elif key not in result:
            result[key] = value
    return result


def json_escape(s: str) -> str:
    """Escape a string for safe inclusion in JSON.

    Handles backslashes, quotes, and control characters.
    Migrated from lib/json.sh.

    Args:
        s: String to escape.

    Returns:
        Escaped string suitable for JSON.
    """
    # Order matters: backslash must be first
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    return s


def json_array_from_lines(lines: str) -> str:
    """Convert newline-separated lines to a JSON array string.

    Empty lines are skipped. Assumes each line is already valid JSON.
    Migrated from lib/json.sh.

    Args:
        lines: Newline-separated string where each line is a JSON value.

    Returns:
        JSON array string with proper formatting.
    """
    result = []
    for line in lines.splitlines():
        line = line.strip()
        if line:
            result.append(line)

    if not result:
        return "[]"

    # Format with indentation
    output = ["["]
    for i, line in enumerate(result):
        if i == 0:
            output.append(f"  {line}")
        else:
            output.append(f"  ,{line}")
    output.append("]")
    return "\n".join(output)


# Command handlers for bridge dispatcher


def _cmd_load(path: str) -> dict[str, Any]:
    """Load command: Load JSON from file.

    Args:
        path: Path to JSON file.

    Returns:
        Dictionary containing JSON data.
    """
    return load_json(path)


def _cmd_merge(base_path: str, overlay_path: str, output_path: str) -> None:
    """Merge command: Deep merge two JSON files and write result.

    Args:
        base_path: Path to base JSON file.
        overlay_path: Path to overlay JSON file.
        output_path: Path to write merged JSON.
    """
    base = load_json(base_path)
    overlay = load_json(overlay_path)
    merged = deep_merge(base, overlay)
    write_json(output_path, merged)


if __name__ == "__main__":
    bridge_main({
        "load": _cmd_load,
        "merge": _cmd_merge,
    })
