"""Commit-time file restriction validation.

Extracted from operations.py.  Provides commit-time checks that prevent
agents from building up commits that will be rejected at push time.
The security boundary remains at push time — commit validation is a
developer-experience improvement.
"""

import logging
import os
import subprocess

from .branch_types import GIT_BINARY, SHA_CHECK_TIMEOUT, ValidationError
from .config import (
    ConfigError,
    check_file_restrictions,
    get_file_restrictions_config,
)
from .subprocess_env import build_clean_env

logger = logging.getLogger(__name__)


def check_commit_file_restrictions(
    repo_root: str,
    metadata: dict | None = None,
) -> ValidationError | None:
    """Check if a commit stages restricted files.

    Enumerates staged files via ``git diff --cached --name-only`` and
    checks each against the file restriction config (blocked/warned patterns).

    This is a developer-experience improvement — the security boundary is
    at push time (check_push_file_restrictions). Commit-time validation
    prevents the agent from building up commits that will all be rejected
    at push.

    Fails closed: if the config cannot be loaded or the diff cannot be
    computed, returns a ValidationError (blocks the commit).
    """
    # Load file restrictions config (warn-and-allow on error — security
    # boundary is at push time via check_push_file_restrictions)
    try:
        config = get_file_restrictions_config()
    except ConfigError as exc:
        logger.warning(
            "File restrictions config unavailable at commit time, "
            "allowing commit (push-time validation remains active): %s", exc,
        )
        return None

    # Enumerate staged files
    resolved_cwd = os.path.realpath(repo_root)
    env = build_clean_env()
    changed_files = _enumerate_staged_files(resolved_cwd, env)

    if changed_files is None:
        logger.warning(
            "Cannot enumerate staged files for commit file validation; "
            "allowing commit (push-time validation remains active)"
        )
        return None

    if not changed_files:
        return None

    result = check_file_restrictions(changed_files, config)

    if result.blocked:
        return ValidationError(result.reason)

    if result.warned_files:
        logger.warning(
            "Commit stages sensitive files: %s",
            ", ".join(result.warned_files),
        )

    return None


def _enumerate_staged_files(
    cwd: str,
    env: dict[str, str],
) -> list[str] | None:
    """Enumerate files staged for commit.

    Returns:
        List of staged file paths, or None if the diff fails.
    """
    try:
        result = subprocess.run(
            [GIT_BINARY, "diff", "--cached", "--name-only", "--"],
            cwd=cwd,
            capture_output=True,
            timeout=SHA_CHECK_TIMEOUT,
            env=env,
        )
        if result.returncode != 0:
            stderr_out = result.stderr.decode("utf-8", errors="replace").strip()
            logger.warning(
                "git diff --cached failed (exit %d): %s",
                result.returncode,
                stderr_out or "(no stderr)",
            )
            return None
        output = result.stdout.decode("utf-8", errors="replace").strip()
        if not output:
            return []
        return output.splitlines()
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("git diff --cached raised exception: %s", exc)
        return None
