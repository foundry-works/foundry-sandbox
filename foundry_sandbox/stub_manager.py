"""Workspace documentation stub management.

Migrated from lib/container_config.sh: install_foundry_workspace_docs,
inject_sandbox_branch_context.
"""
from __future__ import annotations

import os
import re
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


def inject_sandbox_branch_context(
    container_id: str,
    repo_url: str = "",
    from_branch: str = "",
    branch: str = ""
) -> None:
    """Inject sandbox branch context into /workspace/CLAUDE.md.

    Appends context block with repository, branch, and base branch information
    if sandbox-context marker not already present.

    Args:
        container_id: Container ID or name
        repo_url: Repository URL (cleaned to owner/repo format)
        from_branch: Base branch name
        branch: Current branch name
    """
    # Guard: skip if required parameters missing
    if not branch or not from_branch:
        verbose = get_sandbox_verbose()
        if verbose:
            log_debug("Skipping branch context injection: branch or from_branch not provided")
        return

    verbose = get_sandbox_verbose()

    # Check if marker already exists
    target_path = "/workspace/CLAUDE.md"
    check_cmd = [
        "docker", "exec",
        "-u", CONTAINER_USER,
        container_id,
        "grep", "-q", "<sandbox-context>", target_path
    ]

    result = subprocess.run(check_cmd, capture_output=True, text=True, check=False, timeout=TIMEOUT_DOCKER_EXEC)

    if result.returncode == 0:
        if verbose:
            log_debug("Sandbox context already present in CLAUDE.md")
        return

    # Clean repo_url to owner/repo format
    repo_spec = ""
    if repo_url:
        # Strip https://github.com/ or http://github.com/
        cleaned = re.sub(r'^(https?://)?github\.com/', '', repo_url)
        # Strip git@github.com:
        cleaned = re.sub(r'^git@github\.com:', '', cleaned)
        # Strip .git suffix
        cleaned = re.sub(r'\.git$', '', cleaned)
        repo_spec = cleaned

    # Build context block
    context_lines = [
        "",
        "<sandbox-context>",
        "## Sandbox Context"
    ]

    if repo_spec:
        context_lines.append(f"- **Repository**: {repo_spec}")

    context_lines.extend([
        f"- **Branch**: `{branch}`",
        f"- **Based on**: `{from_branch}`",
        "",
        f"When creating PRs, target `{from_branch}` as the base branch.",
        "</sandbox-context>",
        ""
    ])

    context_block = "\n".join(context_lines)

    # Ensure CLAUDE.md exists
    touch_cmd = [
        "docker", "exec",
        "-u", CONTAINER_USER,
        container_id,
        "touch", target_path
    ]
    subprocess.run(touch_cmd, check=False, timeout=TIMEOUT_DOCKER_EXEC)

    # Append context block
    append_cmd = [
        "docker", "exec",
        "-i",
        "-u", CONTAINER_USER,
        container_id,
        "sh", "-c", f"cat >> {target_path}"
    ]

    result = subprocess.run(
        append_cmd,
        input=context_block,
        text=True,
        capture_output=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    if result.returncode == 0:
        log_info("Injected sandbox branch context into CLAUDE.md")
    else:
        if verbose:
            log_debug(f"Failed to inject branch context: {result.stderr}")
