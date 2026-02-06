"""Merge host Claude settings with container settings.

Extracted from lib/container_config.sh merge_claude_settings() function.
Preserves sandbox-specific keys (model, subagentModel, hooks) from
container settings while merging in host user preferences.

Usage:
    python3 merge_claude_settings.py <container_settings_path> <host_settings_path>
"""

import os
import sys

# Import shared utilities
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from json_config import load_json, write_json


# Keys that should be preserved from container defaults, not overwritten by host
PRESERVE_KEYS = {"model", "subagentModel", "hooks"}


def merge_claude_settings(container_path: str, host_path: str) -> None:
    """Merge host settings into container settings, preserving sandbox defaults.

    Args:
        container_path: Path to container's settings.json (may have hooks from prepopulate).
        host_path: Path to host's settings.json.
    """
    host_data = load_json(host_path)
    container_data = load_json(container_path)

    # Save values that should be preserved from container
    preserved = {k: container_data[k] for k in PRESERVE_KEYS if k in container_data}

    # Merge: host settings take precedence, except for preserved keys
    merged = {**container_data, **host_data}

    # Restore preserved settings (opus model, haiku subagent, hooks config)
    merged.update(preserved)

    # Remove foundry plugin from enabledPlugins - we use direct global install
    # This prevents "Plugin not found" errors from stale host config
    if "enabledPlugins" in merged:
        merged["enabledPlugins"].pop("foundry@claude-foundry", None)
        if not merged["enabledPlugins"]:
            del merged["enabledPlugins"]

    write_json(container_path, merged)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: merge_claude_settings.py <container_settings_path> <host_settings_path>",
              file=sys.stderr)
        sys.exit(1)

    merge_claude_settings(sys.argv[1], sys.argv[2])
