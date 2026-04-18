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
    """Merge host Claude settings into container settings.

    Reads container settings out via docker exec, merges on the host
    (where foundry_sandbox is installed), and copies the result back.

    Returns True if the merge succeeded, False on failure.
    """
    from foundry_sandbox.claude_settings import merge_claude_settings

    container_settings = f"{CONTAINER_HOME}/.claude/settings.json"
    tmp_path: str | None = None

    try:
        # Read container settings to a temp file on the host
        result = subprocess.run(
            [
                "docker", "exec", "-u", CONTAINER_USER, container_id,
                "cat", container_settings,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_DOCKER_EXEC,
        )

        tmp_dir = str(Path(host_settings).resolve().parent)
        fd, tmp_path = tempfile.mkstemp(dir=tmp_dir, suffix=".json", prefix="container-settings-")
        with os.fdopen(fd, "w") as f:
            if result.returncode == 0 and result.stdout.strip():
                f.write(result.stdout)
            else:
                f.write("{}")

        # Merge on the host (writes result to tmp_path)
        merge_claude_settings(tmp_path, host_settings)

        # Copy merged result back to container
        copy_file_to_container(container_id, tmp_path, container_settings)
        return True

    except (OSError, subprocess.SubprocessError, DockerError) as exc:
        log_warn(f"Settings merge failed: {exc}")
        return False
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


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
