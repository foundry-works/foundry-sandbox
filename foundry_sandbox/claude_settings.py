"""Claude settings merge utilities.

Merge host Claude settings with container settings. Preserves sandbox-specific
keys (model, subagentModel, hooks) from container settings while merging in
host user preferences.

Migrated from lib/python/merge_claude_settings.py.
"""

from __future__ import annotations

from foundry_sandbox._bridge import bridge_main
from foundry_sandbox.config import load_json, write_json

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

    # Remove extra marketplaces - the sandbox pre-installs what it needs and
    # can't clone new ones (git proxy blocks writes to the dev container FS)
    merged.pop("extraKnownMarketplaces", None)

    write_json(container_path, merged)


# Command handlers for bridge dispatcher


def _cmd_merge(container_path: str, host_path: str) -> None:
    """Merge command: Merge host Claude settings into container settings.

    Args:
        container_path: Path to container's settings.json.
        host_path: Path to host's settings.json.
    """
    merge_claude_settings(container_path, host_path)


if __name__ == "__main__":
    bridge_main({
        "merge": _cmd_merge,
    })
