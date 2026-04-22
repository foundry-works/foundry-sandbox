"""JSON configuration file operations.

Provides utilities for loading and writing JSON configuration files.

Migrated from lib/python/json_config.py.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any



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
    """Write JSON data to a file atomically, creating parent directories as needed.

    Uses write-to-temp + rename to avoid truncated files on interruption.

    Args:
        path: Path to write JSON file.
        data: Dictionary to serialize as JSON.
    """
    dir_path = os.path.dirname(path) or "."
    os.makedirs(dir_path, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.rename(tmp_path, path)
    except OSError:
        os.unlink(tmp_path)
        raise
