"""Shared utilities for JSON configuration file operations.

Extracted from lib/container_config.sh inline Python scripts to enable
unit testing and reduce duplication across sandbox configuration functions.

Usage from shell:
    python3 /path/to/json_config.py load <path>
    python3 /path/to/json_config.py merge <base_path> <overlay_path> <output_path>
"""

import json
import os
import sys
from typing import Any, Dict


def load_json(path: str) -> Dict[str, Any]:
    """Load a JSON file, returning empty dict on missing/invalid file."""
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return {}


def write_json(path: str, data: Dict[str, Any]) -> None:
    """Write JSON data to a file, creating parent directories as needed."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dicts. Overlay values take precedence for non-dict conflicts.

    For dict values present in both, merge recursively.
    For keys only in base, preserve the base value.
    For keys only in overlay, add the overlay value.
    """
    result = base.copy()
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def deep_merge_no_overwrite(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge where overlay only fills in missing keys (base wins conflicts).

    For dict values present in both, merge recursively.
    For scalar keys present in base, keep the base value.
    """
    result = base.copy()
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_no_overwrite(result[key], value)
        elif key not in result:
            result[key] = value
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: json_config.py <command> [args...]", file=sys.stderr)
        print("Commands: load, merge", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]

    if command == "load":
        if len(sys.argv) != 3:
            print("Usage: json_config.py load <path>", file=sys.stderr)
            sys.exit(1)
        data = load_json(sys.argv[2])
        json.dump(data, sys.stdout, indent=2)
        print()

    elif command == "merge":
        if len(sys.argv) != 5:
            print("Usage: json_config.py merge <base_path> <overlay_path> <output_path>", file=sys.stderr)
            sys.exit(1)
        base = load_json(sys.argv[2])
        overlay = load_json(sys.argv[3])
        merged = deep_merge(base, overlay)
        write_json(sys.argv[4], merged)

    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)
