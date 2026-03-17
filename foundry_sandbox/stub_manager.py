"""Workspace documentation stub management.

Installs stub files (CLAUDE.md, AGENTS.md, etc.) into container workspace.
Skill-specific stubs are handled by the skills system (skills.py).
"""
from __future__ import annotations

import os
import subprocess

from foundry_sandbox.constants import CONTAINER_USER, TIMEOUT_DOCKER_EXEC, get_sandbox_home, get_sandbox_verbose
from foundry_sandbox.utils import log_debug, log_info


def install_workspace_stubs(container_id: str, stub_files: list[str] | None = None) -> None:
    """Install stub files into container workspace.

    Reads stubs from host stubs directory and appends to /workspace files.

    Args:
        container_id: Container ID or name
        stub_files: List of stub file names to install. Defaults to empty (no stubs).
    """
    if not stub_files:
        return

    verbose = get_sandbox_verbose()
    stubs_dir = get_sandbox_home() / "stubs"

    if verbose:
        log_debug(f"Installing workspace stubs from {stubs_dir}")

    for stub_file in stub_files:
        stub_path = stubs_dir / stub_file

        if not os.path.isfile(stub_path):
            if verbose:
                log_debug(f"Stub file not found: {stub_path}")
            continue

        # Read stub content
        with open(stub_path, 'r') as f:
            stub_content = f.read()

        if not stub_content.strip():
            if verbose:
                log_debug(f"Stub file is empty, skipping: {stub_path}")
            continue

        target_path = f"/workspace/{stub_file}"

        # Check if stub was already appended (idempotency via marker)
        marker = f"<!-- cast-stub:{stub_file} -->"
        check_result = subprocess.run(
            ["docker", "exec", "-u", CONTAINER_USER, container_id,
             "grep", "-qF", marker, target_path],
            capture_output=True, check=False, timeout=TIMEOUT_DOCKER_EXEC,
        )
        if check_result.returncode == 0:
            if verbose:
                log_debug(f"Stub {stub_file} already installed, skipping")
            continue

        # Ensure target file exists
        subprocess.run(
            ["docker", "exec", "-u", CONTAINER_USER, container_id,
             "touch", target_path],
            check=False, timeout=TIMEOUT_DOCKER_EXEC,
        )

        # Prepend marker and append to container file
        content_with_marker = f"{marker}\n{stub_content}"
        result = subprocess.run(
            ["docker", "exec", "-i", "-u", CONTAINER_USER, container_id,
             "sh", "-c", f"cat >> {target_path}"],
            input=content_with_marker,
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
