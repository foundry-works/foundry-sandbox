"""Validation helpers for the ``new`` command.

Extracted from new.py to reduce module size. Contains precondition checks,
working directory validation, and mount path validation.
"""

from __future__ import annotations

import os
import sys

import click

from foundry_sandbox.api_keys import check_claude_key_required
from foundry_sandbox.image import check_image_freshness
from foundry_sandbox.utils import log_error
from foundry_sandbox.validate import check_docker_network_capacity, validate_git_url, validate_mount_path


def _validate_preconditions(
    ctx: click.Context,
    repo_url: str,
    copies: tuple[str, ...],
    skip_key_check: bool,
    isolate_credentials: bool,
) -> None:
    """Validate API keys, copy sources, image freshness, and network capacity.

    Args:
        ctx: Click context (for invoking build command).
        repo_url: Validated repository URL.
        copies: Tuple of copy specs (host:container).
        skip_key_check: Whether to skip API key validation.
        isolate_credentials: Whether credential isolation is enabled.

    Raises:
        SystemExit: On validation failure.
    """
    ok, msg = validate_git_url(repo_url)
    if not ok:
        log_error(msg)
        sys.exit(1)

    if not skip_key_check:
        ok, msg = check_claude_key_required()
        if not ok:
            log_error("Sandbox creation cancelled - Claude authentication required.")
            sys.exit(1)

    for copy_spec in copies:
        src, _, _ = copy_spec.partition(":")
        if not os.path.exists(src):
            log_error(f"Copy source does not exist: {src}")
            sys.exit(1)

    if check_image_freshness():
        if click.confirm("Rebuild image now?", default=True):
            from foundry_sandbox.commands.build import build as build_cmd
            ctx.invoke(build_cmd)

    ok, msg = check_docker_network_capacity(isolate_credentials)
    if not ok:
        log_error(msg)
        sys.exit(1)


def _validate_working_dir(wd: str) -> tuple[bool, str]:
    """Validate that a working directory path is safe.

    Args:
        wd: Working directory path to validate.

    Returns:
        Tuple of (ok, error_message). ok is True if valid.
    """
    if wd.startswith("/"):
        return False, "Working directory must be relative, not absolute"
    if ".." in wd:
        return False, "Working directory cannot contain parent traversal"
    return True, ""


def _validate_mounts(
    mounts: tuple[str, ...],
) -> tuple[bool, str]:
    """Validate all mount paths against the mount path allowlist.

    Args:
        mounts: Tuple of mount specs (host:container[:ro]).

    Returns:
        Tuple of (ok, error_message). ok is True if all mounts are valid.
    """
    for mount in mounts:
        src, _, _ = mount.partition(":")
        ok, msg = validate_mount_path(src)
        if not ok:
            return False, msg
    return True, ""
