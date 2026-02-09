"""Shared validator for protected branch enforcement.

Prevents direct pushes (create/update/delete) to protected branches like
main, master, release/*, and production. Used by git_proxy.py addon.

Metadata precedence: flow metadata > env vars > hardcoded defaults.
"""

import fnmatch
import os
from dataclasses import dataclass, field
from typing import List, Optional

DEFAULT_PROTECTED_PATTERNS: List[str] = [
    "refs/heads/main",
    "refs/heads/master",
    "refs/heads/release/*",
    "refs/heads/production",
]

DEFAULT_RESTRICTED_PUSH_PATHS: List[str] = [
    ".github/workflows",
    ".github/actions",
]

ZERO_SHA = "0" * 40


@dataclass
class BranchPolicyConfig:
    """Configuration for protected branch enforcement."""

    enabled: bool = True
    patterns: List[str] = field(
        default_factory=lambda: list(DEFAULT_PROTECTED_PATTERNS)
    )


def load_branch_policy(metadata: Optional[dict] = None) -> BranchPolicyConfig:
    """Load branch policy config with precedence: metadata > env vars > defaults.

    Args:
        metadata: Container metadata dict from flow (may contain
                  git.protected_branches.enabled and
                  git.protected_branches.patterns).

    Returns:
        BranchPolicyConfig with resolved settings.
    """
    enabled = True
    patterns = list(DEFAULT_PROTECTED_PATTERNS)

    # Layer 2: env vars override defaults
    env_enabled = os.environ.get("GIT_PROTECTED_BRANCHES_ENABLED")
    if env_enabled is not None:
        enabled = env_enabled.lower() in ("true", "1", "yes")

    env_patterns = os.environ.get("GIT_PROTECTED_BRANCHES_PATTERNS")
    if env_patterns:
        parsed = [p.strip() for p in env_patterns.split(",") if p.strip()]
        if parsed:
            patterns = parsed

    # Layer 3: flow metadata overrides env vars
    if metadata:
        git_config = metadata.get("git", {})
        if isinstance(git_config, dict):
            pb_config = git_config.get("protected_branches", {})
            if isinstance(pb_config, dict):
                if "enabled" in pb_config:
                    enabled = bool(pb_config["enabled"])
                if "patterns" in pb_config:
                    meta_patterns = pb_config["patterns"]
                    if isinstance(meta_patterns, list) and meta_patterns:
                        patterns = meta_patterns

    return BranchPolicyConfig(enabled=enabled, patterns=patterns)


def check_protected_branches(
    refname: str,
    old_sha: str,
    new_sha: str,
    bare_repo_path: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> Optional[str]:
    """Check if a ref update violates protected branch policy.

    Args:
        refname: The full ref being updated (e.g. refs/heads/main).
        old_sha: The current SHA of the ref (all zeros for creation).
        new_sha: The new SHA of the ref (all zeros for deletion).
        bare_repo_path: Path to the bare repo, used for bootstrap lock file.
        metadata: Container metadata dict for policy configuration.

    Returns:
        None if the operation is allowed, or a string describing the block reason.
    """
    config = load_branch_policy(metadata)

    if not config.enabled:
        return None

    # Check if refname matches any protected pattern
    is_protected = any(
        fnmatch.fnmatch(refname, pattern) for pattern in config.patterns
    )

    if not is_protected:
        return None

    is_deletion = new_sha == ZERO_SHA
    is_creation = old_sha == ZERO_SHA

    if is_deletion:
        return f"Deletion of protected branch {refname} is not allowed"

    if is_creation:
        return _check_bootstrap_creation(refname, bare_repo_path)

    # is_update: neither creation nor deletion
    return f"Direct push to protected branch {refname} is not allowed"


def _check_bootstrap_creation(
    refname: str,
    bare_repo_path: Optional[str],
) -> Optional[str]:
    """Allow first refs/heads/main creation via atomic lock file, block all others.

    The bootstrap guard uses O_CREAT | O_EXCL | O_WRONLY to atomically create
    a lock file. If the file already exists, the bootstrap window has closed.
    Lock cleanup is admin-only (no automatic time-based orphan cleanup).

    Args:
        refname: The ref being created.
        bare_repo_path: Path to the bare repo for lock file placement.

    Returns:
        None if bootstrap creation is allowed, or a block reason string.
    """
    if refname == "refs/heads/main" and bare_repo_path:
        lock_path = os.path.join(bare_repo_path, "foundry-bootstrap.lock")
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return None  # Bootstrap creation allowed
        except FileExistsError:
            return (
                f"Creation of protected branch {refname} is not allowed "
                f"(bootstrap already completed)"
            )
        except OSError as exc:
            return (
                f"Creation of protected branch {refname} is not allowed "
                f"(lock file error: {exc})"
            )

    return f"Creation of protected branch {refname} is not allowed"
