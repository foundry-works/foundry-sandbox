"""Claude settings merge functions for sandbox containers.

Extracted from credential_setup.py for independent testability.
These are security-critical merge functions: they control what host
settings reach the sandbox, with credential stripping in safe mode.

SECURITY-CRITICAL: merge_claude_settings_safe strips credential-bearing
keys before copying to sandbox.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from foundry_sandbox.constants import (
    CONTAINER_HOME,
    CONTAINER_USER,
    TIMEOUT_DOCKER_EXEC,
)
from foundry_sandbox.container_io import copy_file_to_container
from foundry_sandbox.errors import DockerError
from foundry_sandbox.utils import log_warn


def merge_claude_settings_in_container(container_id: str, host_settings: str) -> bool:
    """Merge host Claude settings into container settings via docker exec.

    Matches the shell merge_claude_settings() in lib/container_config.sh:
    1. Copy host settings to temp location inside container
    2. Run merge inside container (preserves hooks, model from container defaults)
    3. Clean up temp file

    Returns True if the merge succeeded, False on failure.
    """
    temp_host = "/tmp/host-settings.json"
    container_settings = f"{CONTAINER_HOME}/.claude/settings.json"

    try:
        copy_file_to_container(container_id, host_settings, temp_host)
    except (OSError, subprocess.CalledProcessError, DockerError) as exc:
        log_warn(f"Failed to copy host settings for merge: {exc}")
        return False

    result = subprocess.run(
        [
            "docker", "exec", "-u", CONTAINER_USER, container_id,
            "python3", "-m", "foundry_sandbox.claude_settings",
            "merge", container_settings, temp_host,
        ],
        check=False,
        capture_output=True,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    if result.returncode != 0:
        log_warn(f"Settings merge failed in container (exit {result.returncode})")
        # Clean up temp file before returning
        subprocess.run(
            ["docker", "exec", container_id, "rm", "-f", temp_host],
            check=False,
            capture_output=True,
            timeout=TIMEOUT_DOCKER_EXEC,
        )
        return False

    # Clean up temp file
    subprocess.run(
        ["docker", "exec", container_id, "rm", "-f", temp_host],
        check=False,
        capture_output=True,
        timeout=TIMEOUT_DOCKER_EXEC,
    )
    return True


def merge_claude_settings_safe(container_id: str, host_settings: str) -> bool:
    """Merge host Claude settings into container, stripping credential-bearing keys.

    Used when credential isolation is enabled to prevent real API keys or
    tokens embedded in settings.json from leaking into the sandbox.

    Keys stripped: env (may contain API keys), mcpServers (may embed tokens),
    oauthTokens, apiKey.
    """
    try:
        with open(host_settings) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log_warn(f"Failed to read host settings for safe merge: {exc}")
        return False

    # Strip keys that commonly carry credentials
    for key in ("env", "mcpServers", "oauthTokens", "apiKey"):
        data.pop(key, None)

    # Write sanitised copy to temp file in the same directory as host_settings
    # (user-owned, not world-writable /tmp) to prevent symlink attacks.
    tmp_path: str | None = None
    try:
        _tmp_dir = str(Path(host_settings).resolve().parent)
        fd, tmp_path = tempfile.mkstemp(dir=_tmp_dir, suffix=".json", prefix="settings-safe-")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        return merge_claude_settings_in_container(container_id, tmp_path)
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
