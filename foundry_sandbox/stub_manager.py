"""Workspace documentation stub management.

Migrated from lib/container_config.sh: install_foundry_workspace_docs.
"""
from __future__ import annotations

import os
import subprocess

from foundry_sandbox.constants import CONTAINER_USER, TIMEOUT_DOCKER_EXEC, get_sandbox_home, get_sandbox_verbose
from foundry_sandbox.utils import log_debug, log_info


def install_foundry_workspace_docs(container_id: str) -> None:
    """Install CLAUDE.md and AGENTS.md stubs into container workspace.

    Reads stubs from host stubs directory and appends to /workspace files
    if foundry-instructions marker not already present.

    Args:
        container_id: Container ID or name
    """
    verbose = get_sandbox_verbose()
    stubs_dir = get_sandbox_home() / "stubs"

    if verbose:
        log_debug(f"Installing workspace docs from {stubs_dir}")

    for stub_file in ["CLAUDE.md", "AGENTS.md"]:
        stub_path = stubs_dir / stub_file

        if not os.path.isfile(stub_path):
            if verbose:
                log_debug(f"Stub file not found: {stub_path}")
            continue

        # Check if marker already exists in container file
        target_path = f"/workspace/{stub_file}"
        check_cmd = [
            "docker", "exec",
            "-u", CONTAINER_USER,
            container_id,
            "grep", "-q", "<foundry-instructions>", target_path
        ]

        result = subprocess.run(check_cmd, capture_output=True, text=True, check=False, timeout=TIMEOUT_DOCKER_EXEC)

        if result.returncode == 0:
            # Marker found, skip
            if verbose:
                log_debug(f"Foundry instructions already present in {target_path}")
            continue

        # Ensure target file exists
        touch_cmd = [
            "docker", "exec",
            "-u", CONTAINER_USER,
            container_id,
            "touch", target_path
        ]
        subprocess.run(touch_cmd, check=False, timeout=TIMEOUT_DOCKER_EXEC)

        # Read stub content
        with open(stub_path, 'r') as f:
            stub_content = f.read()

        # Append stub content to container file
        append_cmd = [
            "docker", "exec",
            "-i",
            "-u", CONTAINER_USER,
            container_id,
            "sh", "-c", f"cat >> {target_path}"
        ]

        result = subprocess.run(
            append_cmd,
            input=stub_content,
            text=True,
            capture_output=True,
            check=False,
            timeout=TIMEOUT_DOCKER_EXEC,
        )

        if result.returncode == 0:
            log_info(f"Installed {stub_file} into container workspace")
        else:
            if verbose:
                log_debug(f"Failed to install {stub_file}: {result.stderr}")
