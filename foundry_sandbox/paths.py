"""Path resolution utilities for foundry-sandbox.

Provides functions for:
  - Resolving sandbox paths (configs, metadata)
  - Directory and path management (ensure_dir)
  - Sandbox name generation
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from foundry_sandbox.constants import (
    SANDBOX_NAME_MAX_LENGTH,
    get_claude_configs_dir,
    get_repos_dir,
    get_sandbox_home,
)
from foundry_sandbox.utils import sanitize_ref_component


# ============================================================================
# Path Safety
# ============================================================================


def _assert_safe_path_component(name: str) -> None:
    """Reject names that could escape the intended directory.

    Raises:
        ValueError: If *name* is empty, contains ``/`` or ``\\``,
            or equals ``.`` or ``..``.
    """
    if not name:
        raise ValueError("Sandbox/preset name must not be empty")
    if "/" in name or "\\" in name:
        raise ValueError(f"Name must not contain path separators: {name!r}")
    if name in (".", ".."):
        raise ValueError(f"Name must not be '.' or '..': {name!r}")


# ============================================================================
# Path Resolution Functions
# ============================================================================


def path_claude_config(name: str) -> Path:
    """Get the path to a sandbox's Claude configuration directory.

    Args:
        name: Sandbox name

    Returns:
        Path to the Claude config directory
    """
    _assert_safe_path_component(name)
    return get_claude_configs_dir() / name


def path_metadata_file(name: str) -> Path:
    """Get the path to a sandbox's metadata file (JSON).

    Args:
        name: Sandbox name

    Returns:
        Path to the metadata.json file
    """
    _assert_safe_path_component(name)
    return path_claude_config(name) / "metadata.json"


def path_last_cast_new() -> Path:
    """Get the path to the last 'cast new' session info file.

    Returns:
        Path to .last-cast-new.json in sandbox home
    """
    return get_sandbox_home() / ".last-cast-new.json"


def path_last_attach() -> Path:
    """Get the path to the last 'attach' session info file.

    Returns:
        Path to .last-attach.json in sandbox home
    """
    return get_sandbox_home() / ".last-attach.json"


def path_version_check() -> Path:
    """Get the path to the version-check cache file.

    Returns:
        Path to .version-check.json in sandbox home
    """
    return get_sandbox_home() / ".version-check.json"


def path_presets_dir() -> Path:
    """Get the path to the presets directory.

    Returns:
        Path to the presets directory in sandbox home
    """
    return get_sandbox_home() / "presets"


def path_preset_file(name: str) -> Path:
    """Get the path to a specific preset file.

    Args:
        name: Preset name (without .json extension)

    Returns:
        Path to the preset JSON file
    """
    _assert_safe_path_component(name)
    return path_presets_dir() / f"{name}.json"


def resolve_host_worktree_path(name: str) -> Path:
    """Resolve the host-side workspace path for a sandbox.

    Reads ``host_worktree_path`` from sandbox metadata.

    Args:
        name: Sandbox name.

    Returns:
        Resolved workspace path (may not exist on disk).

    Raises:
        ValueError: If metadata has no ``host_worktree_path`` set.
    """
    from foundry_sandbox.state import load_sandbox_metadata

    _assert_safe_path_component(name)
    metadata = load_sandbox_metadata(name)
    if metadata and metadata.get("host_worktree_path"):
        return Path(metadata["host_worktree_path"])
    raise ValueError(f"Sandbox '{name}' has no host_worktree_path in metadata")


# ============================================================================
# File System Helpers (from lib/fs.sh)
# ============================================================================


def ensure_dir(path: str | Path) -> Path:
    """Ensure a directory exists, creating it if necessary.

    Equivalent to `mkdir -p`. Creates all parent directories as needed.

    Args:
        path: Directory path (string or Path)

    Returns:
        Path object of the directory
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


# ============================================================================
# Repository & Sandbox Name Helpers (moved from commands/_helpers.py)
# ============================================================================


def repo_url_to_checkout_path(repo_url: str) -> str:
    """Convert a repository URL to a local checkout path under REPOS_DIR.

    Unlike ``repo_url_to_bare_path``, this returns a regular (non-bare)
    checkout path for sbx-managed worktrees.

    Args:
        repo_url: Repository URL or local path.

    Returns:
        Absolute path string for the checkout directory.
    """
    repos_dir = str(get_repos_dir())

    if not repo_url:
        return f"{repos_dir}/unknown"

    # Local filesystem path — use the path directly
    if repo_url.startswith(("~/", "/", "./", "../")):
        expanded = repo_url
        if expanded.startswith("~/"):
            expanded = str(Path.home()) + expanded[1:]
        return expanded

    # HTTPS, HTTP, or git@ URL
    path = repo_url
    path = path.removeprefix("https://")
    path = path.removeprefix("http://")
    path = path.removeprefix("git@")
    path = path.replace(":", "/", 1) if ":" in path else path
    if path.endswith(".git"):
        path = path[:-4]
    return f"{repos_dir}/{path}"


def repo_name_from_url(repo_url: str) -> str:
    """Extract the repository name from a URL or local path.

    Args:
        repo_url: Full repository URL or local path.

    Returns:
        Repository name (e.g. 'repo' from 'https://github.com/org/repo').
    """
    name = repo_url.rstrip("/")
    if name.endswith(".git"):
        name = name[:-4]
    name = os.path.basename(name)
    return name or "repo"


def sandbox_name(repo_name: str, branch: str) -> str:
    """Generate a sandbox name from repo name and branch.

    Args:
        repo_name: Repository name (e.g. 'repo' from owner/repo URL).
        branch: Branch name.

    Returns:
        Sanitised sandbox name.
    """
    repo = sanitize_ref_component(repo_name) or "repo"
    branch_part = sanitize_ref_component(branch) or "branch"
    name = f"{repo}-{branch_part}".lower()
    if len(name) > SANDBOX_NAME_MAX_LENGTH:
        digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:8]
        name = f"{name[:SANDBOX_NAME_MAX_LENGTH - 9]}-{digest}"
    return name


def find_next_sandbox_name(base_name: str) -> str:
    """Find next available sandbox name by appending a numeric suffix.

    Only checks the claude-config directory — it is the authoritative registry
    covering both old-layout (worktrees/) and new-layout (sbx-managed) sandboxes.

    Args:
        base_name: Desired sandbox name.

    Returns:
        *base_name* if available, otherwise *base_name*-N.
    """
    configs = get_claude_configs_dir()

    def _taken(candidate: str) -> bool:
        return (configs / candidate).exists()

    if not _taken(base_name):
        return base_name

    for i in range(2, 10_000):
        candidate = f"{base_name}-{i}"
        if not _taken(candidate):
            return candidate
    return f"{base_name}-{os.getpid()}"


def strip_github_url(repo_url: str) -> str:
    """Strip GitHub URL prefixes and .git suffix to get owner/repo spec.

    Args:
        repo_url: Full repository URL.

    Returns:
        Short ``owner/repo`` form.
    """
    spec = repo_url
    spec = spec.removeprefix("https://github.com/")
    spec = spec.removeprefix("http://github.com/")
    spec = spec.removeprefix("git@github.com:")
    if spec.endswith(".git"):
        spec = spec[:-4]
    return spec
