"""Sandbox metadata persistence and state management.

Handles:
  - Sandbox metadata read/write (JSON format, sbx backend)
  - Cast-new presets and history
  - Last-attach state tracking
  - File permission security validation

Pure data management with no subprocess calls.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from foundry_sandbox.atomic_io import (
    file_lock as _state_lock,
    atomic_write_unlocked as _secure_write_unlocked,
    atomic_write as _secure_write,
)
from foundry_sandbox.config import load_json
from foundry_sandbox.constants import get_claude_configs_dir
from foundry_sandbox.utils import log_debug, log_error
from foundry_sandbox.models import CastNewPreset, SbxSandboxMetadata
from foundry_sandbox.paths import (
    ensure_dir,
    path_last_attach,
    path_last_cast_new,
    path_metadata_file,
    path_preset_file,
    path_presets_dir,
)


# ============================================================================
# Security Validation
# ============================================================================


def metadata_is_secure(path: str | Path) -> bool:
    """Check that a metadata file has secure ownership and permissions.

    Validates:
      - File is owned by the current user
      - File is not group/world-writable (no bits in 022)

    Args:
        path: Path to the metadata file.

    Returns:
        True if secure, False if not.
    """
    p = Path(path)
    if not p.exists():
        return False

    try:
        st = p.stat()
    except OSError:
        return False

    if st.st_uid != os.getuid():
        return False

    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False

    return True


# ============================================================================
# Sandbox Metadata
# ============================================================================


def write_sandbox_metadata(
    name: str,
    metadata: SbxSandboxMetadata,
) -> None:
    """Write sandbox metadata to a JSON file.

    Args:
        name: Sandbox name identifier.
        metadata: Complete sandbox metadata to persist.
    """
    data = metadata.model_dump()

    path = path_metadata_file(name)
    content = json.dumps(data) + "\n"
    _secure_write(path, content)


def patch_sandbox_metadata(name: str, **updates: Any) -> None:
    """Update specific fields in existing sandbox metadata.

    Args:
        name: Sandbox name identifier.
        **updates: Field names and values to update.

    Raises:
        FileNotFoundError: If no metadata file exists for *name*.
        ValueError: If any key in *updates* is not a SbxSandboxMetadata field.
    """
    valid_fields = set(SbxSandboxMetadata.model_fields)
    bad_keys = set(updates) - valid_fields
    if bad_keys:
        raise ValueError(f"Unknown SbxSandboxMetadata fields: {sorted(bad_keys)}")

    json_path = path_metadata_file(name)
    if not json_path.exists():
        raise FileNotFoundError(f"No metadata file for sandbox '{name}'")

    with _state_lock(json_path):
        data = load_json(str(json_path))
        if not data:
            raise FileNotFoundError(f"Empty metadata for sandbox '{name}'")
        data.update(updates)
        model = SbxSandboxMetadata(**data)
        content = json.dumps(model.model_dump()) + "\n"
        _secure_write_unlocked(json_path, content)


def _load_metadata_from_json(json_path: Path) -> dict[str, Any] | None:
    """Read and validate metadata from a JSON file without acquiring a lock.

    Args:
        json_path: Path to the JSON metadata file.

    Returns:
        Validated metadata dictionary, or None if the file is empty/missing.
    """
    data = load_json(str(json_path))
    if not data:
        return None
    try:
        model = SbxSandboxMetadata(**data)
        return model.model_dump()
    except (ValueError, TypeError) as exc:
        from pydantic import ValidationError

        if isinstance(exc, ValidationError):
            error_types = {e["type"] for e in exc.errors()}
            version_skew_types = {"extra_forbidden"}
            if error_types and error_types <= version_skew_types:
                log_debug(
                    f"Metadata at '{json_path}' has extra fields (version skew): {exc}; "
                    "returning raw data"
                )
                return data
        log_error(
            f"Metadata at '{json_path}' failed schema validation: {exc}; "
            "returning None (possible corruption)"
        )
        return None


def load_sandbox_metadata(name: str) -> dict[str, Any] | None:
    """Load sandbox metadata from JSON file.

    Args:
        name: Sandbox name identifier.

    Returns:
        Metadata dictionary, or None if not found.
    """
    json_path = path_metadata_file(name)

    if not json_path.exists():
        return None

    if not metadata_is_secure(json_path):
        return None

    try:
        with _state_lock(json_path, shared=True):
            return _load_metadata_from_json(json_path)
    except OSError as exc:
        log_debug(f"Skipping metadata for '{name}': lock unavailable ({exc})")
        return None


def list_sandboxes() -> list[dict[str, Any]]:
    """List all sandboxes with their metadata.

    Scans the claude-config directory for sandbox metadata files.

    Returns:
        List of dicts with 'name' and metadata fields for each sandbox.
    """
    config_dir = get_claude_configs_dir()
    if not config_dir.exists():
        return []

    results = []
    for entry in sorted(config_dir.iterdir()):
        if not entry.is_dir():
            continue
        name = entry.name
        metadata = load_sandbox_metadata(name)
        if metadata is not None:
            results.append({"name": name, **metadata})

    return results


def inspect_sandbox(name: str) -> dict[str, Any] | None:
    """Get full metadata for a single sandbox.

    Args:
        name: Sandbox name identifier.

    Returns:
        Metadata dictionary with 'name' field, or None if not found.
    """
    metadata = load_sandbox_metadata(name)
    if metadata is None:
        return None
    return {"name": name, **metadata}


# ============================================================================
# Cast New Presets & History
# ============================================================================


def _build_command_line(
    repo: str,
    agent: str = "claude",
    branch: str = "",
    from_branch: str = "",
    working_dir: str = "",
    pip_requirements: str = "",
    allow_pr: bool = False,
    enable_opencode: bool = False,
    enable_zai: bool = False,
    copies: list[str] | None = None,
) -> str:
    """Build a display-friendly command line string from cast-new arguments."""
    parts = ["cast new", repo]
    if branch:
        parts.append(branch)
    if from_branch:
        parts.append(from_branch)
    if agent != "claude":
        parts.extend(["--agent", agent])
    if working_dir:
        parts.extend(["--wd", working_dir])
    if pip_requirements:
        parts.extend(["--pip-requirements", pip_requirements])
    if allow_pr:
        parts.append("--allow-pr")
    if enable_opencode:
        parts.append("--with-opencode")
    if enable_zai:
        parts.append("--with-zai")
    for copy in (copies or []):
        parts.extend(["--copy", copy])
    return " ".join(parts)


def _write_cast_new_json(
    path: str | Path,
    *,
    repo: str,
    agent: str = "claude",
    branch: str = "",
    from_branch: str = "",
    working_dir: str = "",
    pip_requirements: str = "",
    allow_pr: bool = False,
    enable_opencode: bool = False,
    enable_zai: bool = False,
    copies: list[str] | None = None,
    template: str = "",
    template_managed: bool = False,
) -> str:
    """Write cast-new JSON to a file.

    Returns:
        The command line string for display.
    """
    preset = CastNewPreset(
        repo=repo,
        agent=agent,
        branch=branch,
        from_branch=from_branch,
        working_dir=working_dir,
        pip_requirements=pip_requirements,
        allow_pr=allow_pr,
        enable_opencode=enable_opencode,
        enable_zai=enable_zai,
        copies=copies or [],
        template=template,
        template_managed=template_managed,
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    command_line = _build_command_line(
        repo, agent, branch, from_branch, working_dir,
        pip_requirements, allow_pr,
        enable_opencode, enable_zai, copies,
    )

    data = {
        "timestamp": timestamp,
        "command_line": command_line,
        "args": preset.model_dump(),
    }

    content = json.dumps(data, indent=2) + "\n"
    _secure_write(Path(path), content)
    return command_line


def save_last_cast_new(
    *,
    repo: str,
    agent: str = "claude",
    branch: str = "",
    from_branch: str = "",
    working_dir: str = "",
    pip_requirements: str = "",
    allow_pr: bool = False,
    enable_opencode: bool = False,
    enable_zai: bool = False,
    copies: list[str] | None = None,
    template: str = "",
    template_managed: bool = False,
) -> str:
    """Save the most recent cast-new command.

    Returns:
        The command line string for display.
    """
    path = path_last_cast_new()
    return _write_cast_new_json(
        path, repo=repo, agent=agent, branch=branch, from_branch=from_branch,
        working_dir=working_dir, pip_requirements=pip_requirements,
        allow_pr=allow_pr,
        enable_opencode=enable_opencode, enable_zai=enable_zai,
        copies=copies, template=template, template_managed=template_managed,
    )


def save_cast_preset(
    preset_name: str,
    *,
    repo: str,
    agent: str = "claude",
    branch: str = "",
    from_branch: str = "",
    working_dir: str = "",
    pip_requirements: str = "",
    allow_pr: bool = False,
    enable_opencode: bool = False,
    enable_zai: bool = False,
    copies: list[str] | None = None,
    template: str = "",
    template_managed: bool = False,
) -> None:
    """Save a named cast-new preset."""
    ensure_dir(path_presets_dir())
    path = path_preset_file(preset_name)
    _write_cast_new_json(
        path, repo=repo, agent=agent, branch=branch, from_branch=from_branch,
        working_dir=working_dir, pip_requirements=pip_requirements,
        allow_pr=allow_pr,
        enable_opencode=enable_opencode, enable_zai=enable_zai,
        copies=copies, template=template, template_managed=template_managed,
    )


def _load_cast_new_json(path: str | Path) -> dict[str, Any] | None:
    """Load and parse a cast-new JSON file.

    Returns:
        Dictionary with 'command_line' and 'args' fields, or None on failure.
    """
    data = load_json(str(path))
    if not data:
        return None

    args = data.get("args", {})
    try:
        preset = CastNewPreset(**args)
        result = preset.model_dump()
    except (ValueError, TypeError):
        result = {
            "repo": args.get("repo", ""),
            "agent": args.get("agent", "claude"),
            "branch": args.get("branch", ""),
            "from_branch": args.get("from_branch", ""),
            "working_dir": args.get("working_dir", ""),
            "pip_requirements": args.get("pip_requirements", ""),
            "allow_pr": args.get("allow_pr", False),
            "enable_opencode": args.get("enable_opencode", False),
            "enable_zai": args.get("enable_zai", False),
            "copies": args.get("copies", []),
            "template": args.get("template", ""),
            "template_managed": args.get("template_managed", False),
        }
    result["command_line"] = data.get("command_line", "")
    return result


def load_last_cast_new() -> dict[str, Any] | None:
    """Load the last cast-new arguments.

    Returns:
        Dictionary with cast-new arguments, or None if not found.
    """
    path = path_last_cast_new()
    if not path.exists():
        return None
    return _load_cast_new_json(path)


def load_cast_preset(preset_name: str) -> dict[str, Any] | None:
    """Load a named cast-new preset.

    Args:
        preset_name: Name of the preset.

    Returns:
        Dictionary with preset arguments, or None if not found.
    """
    path = path_preset_file(preset_name)
    if not path.exists():
        return None
    return _load_cast_new_json(path)


def list_cast_presets() -> list[str]:
    """List all saved preset names.

    Returns:
        Sorted list of preset names (without .json extension).
    """
    presets_dir = path_presets_dir()
    if not presets_dir.exists():
        return []

    return sorted(p.stem for p in presets_dir.glob("*.json"))


def show_cast_preset(preset_name: str) -> str | None:
    """Get pretty-printed JSON for a preset.

    Args:
        preset_name: Name of the preset.

    Returns:
        Pretty-printed JSON string, or None if not found.
    """
    path = path_preset_file(preset_name)
    if not path.exists():
        return None
    data = load_json(str(path))
    if not data:
        return None
    return json.dumps(data, indent=2)


def delete_cast_preset(preset_name: str) -> bool:
    """Delete a named preset.

    Args:
        preset_name: Name of the preset to delete.

    Returns:
        True if deleted, False if not found.
    """
    path = path_preset_file(preset_name)
    if not path.exists():
        return False
    path.unlink()
    return True


# ============================================================================
# Last Attach State
# ============================================================================


def save_last_attach(sandbox_name: str) -> None:
    """Save the last attached sandbox name.

    Args:
        sandbox_name: Name of the sandbox that was attached.
    """
    path = path_last_attach()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = {
        "timestamp": timestamp,
        "sandbox_name": sandbox_name,
    }
    content = json.dumps(data, indent=2) + "\n"
    _secure_write(path, content)


def load_last_attach() -> str | None:
    """Load the last attached sandbox name.

    Returns:
        Sandbox name string, or None if not found or empty.
    """
    path = path_last_attach()
    if not path.exists():
        return None
    data = load_json(str(path))
    name = data.get("sandbox_name", "")
    return name if name else None
