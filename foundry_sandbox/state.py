"""Sandbox metadata persistence and state management.

Replaces lib/state.sh (891 lines). Handles:
  - Sandbox metadata read/write (JSON format, with legacy ENV migration)
  - Cast-new presets and history
  - Last-attach state tracking
  - File permission security validation

Pure data management with no Docker calls.
"""

from __future__ import annotations

import json
import os
import shlex
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from foundry_sandbox._bridge import bridge_main
from foundry_sandbox.config import load_json, write_json
from foundry_sandbox.utils import flag_enabled as _flag_enabled
from foundry_sandbox.models import SandboxMetadata
from foundry_sandbox.paths import (
    ensure_dir,
    path_claude_config,
    path_last_attach,
    path_last_cast_new,
    path_metadata_file,
    path_metadata_legacy_file,
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

    # Check ownership
    if st.st_uid != os.getuid():
        return False

    # Check not group/world-writable
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False

    return True


def _secure_write(path: Path, content: str) -> None:
    """Write content to a file atomically with 600 permissions.

    Uses write-to-temp + os.replace() to avoid corrupted files on crash.
    """
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ============================================================================
# Sandbox Metadata
# ============================================================================


def write_sandbox_metadata(
    name: str,
    *,
    repo_url: str,
    branch: str,
    from_branch: str = "",
    network_mode: str = "",
    sync_ssh: int = 0,
    ssh_mode: str = "",
    working_dir: str = "",
    sparse_checkout: bool = False,
    pip_requirements: str = "",
    allow_pr: bool = False,
    enable_opencode: bool = False,
    enable_zai: bool = False,
    mounts: list[str] | None = None,
    copies: list[str] | None = None,
) -> None:
    """Write sandbox metadata to a JSON file.

    Args:
        name: Sandbox name identifier.
        repo_url: Git repository URL.
        branch: Target branch name.
        from_branch: Base branch for PR creation.
        network_mode: Network mode (limited, host-only, none).
        sync_ssh: SSH sync flag (0 or 1).
        ssh_mode: SSH mode (always, disabled).
        working_dir: Working directory path.
        sparse_checkout: Whether to use sparse checkout.
        pip_requirements: Path to requirements file.
        allow_pr: Whether to allow PR creation.
        enable_opencode: Whether to enable OpenCode.
        enable_zai: Whether to enable ZAI.
        mounts: List of Docker mount specs.
        copies: List of copy specs.
    """
    # Validate through Pydantic model before persisting
    model = SandboxMetadata(
        repo_url=repo_url,
        branch=branch,
        from_branch=from_branch,
        network_mode=network_mode,
        sync_ssh=sync_ssh,
        ssh_mode=ssh_mode,
        working_dir=working_dir,
        sparse_checkout=sparse_checkout,
        pip_requirements=pip_requirements,
        allow_pr=allow_pr,
        enable_opencode=enable_opencode,
        enable_zai=enable_zai,
        mounts=mounts or [],
        copies=copies or [],
    )
    data = model.model_dump()

    path = path_metadata_file(name)
    content = json.dumps(data) + "\n"
    _secure_write(path, content)


def _parse_legacy_metadata(path: str | Path) -> dict[str, Any]:
    """Parse legacy shell ENV format metadata file.

    Legacy format uses shell variable assignments like:
        SANDBOX_REPO_URL=value
        SANDBOX_MOUNTS=(item1 item2)

    Args:
        path: Path to legacy metadata.env file.

    Returns:
        Dictionary matching the JSON metadata structure.
    """
    key_map = {
        "SANDBOX_REPO_URL": "repo_url",
        "SANDBOX_BRANCH": "branch",
        "SANDBOX_FROM_BRANCH": "from_branch",
        "SANDBOX_NETWORK_MODE": "network_mode",
        "SANDBOX_SYNC_SSH": "sync_ssh",
    }

    data: dict[str, Any] = {"mounts": [], "copies": []}

    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("SANDBOX_MOUNTS="):
                inner = line.split("=", 1)[1].strip()
                if inner.startswith("(") and inner.endswith(")"):
                    inner = inner[1:-1]
                data["mounts"] = shlex.split(inner)
                continue

            if line.startswith("SANDBOX_COPIES="):
                inner = line.split("=", 1)[1].strip()
                if inner.startswith("(") and inner.endswith(")"):
                    inner = inner[1:-1]
                data["copies"] = shlex.split(inner)
                continue

            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key not in key_map:
                continue
            parts = shlex.split(value)
            data[key_map[key]] = parts[0] if parts else ""

    return data


def load_sandbox_metadata(name: str) -> dict[str, Any] | None:
    """Load sandbox metadata, with auto-migration from legacy format.

    Checks for JSON metadata first, falls back to legacy ENV format.
    Legacy files are auto-migrated to JSON and the legacy file is removed.

    Args:
        name: Sandbox name identifier.

    Returns:
        Metadata dictionary, or None if not found.
    """
    json_path = path_metadata_file(name)
    legacy_path = path_metadata_legacy_file(name)

    if json_path.exists():
        if not metadata_is_secure(json_path):
            return None
        data = load_json(str(json_path))
        if data:
            # Auto-derive ssh_mode if missing
            if not data.get("ssh_mode"):
                data["ssh_mode"] = "always" if str(data.get("sync_ssh", "0")) == "1" else "disabled"
            # Validate through Pydantic model (lenient: extra keys are ignored)
            try:
                model = SandboxMetadata(**data)
                return model.model_dump()
            except (ValueError, TypeError):
                # Fall back to raw dict if validation fails (e.g. legacy data)
                return data
        return None

    if legacy_path.exists():
        if not metadata_is_secure(legacy_path):
            return None
        try:
            data = _parse_legacy_metadata(legacy_path)
        except (OSError, ValueError):
            return None

        # Auto-derive ssh_mode
        if not data.get("ssh_mode"):
            data["ssh_mode"] = "always" if str(data.get("sync_ssh", "0")) == "1" else "disabled"

        # Migrate to JSON format
        write_sandbox_metadata(
            name,
            repo_url=data.get("repo_url", ""),
            branch=data.get("branch", ""),
            from_branch=data.get("from_branch", ""),
            network_mode=data.get("network_mode", ""),
            sync_ssh=int(data.get("sync_ssh", 0)),
            ssh_mode=data.get("ssh_mode", ""),
            working_dir=data.get("working_dir", ""),
            sparse_checkout=bool(data.get("sparse_checkout")),
            pip_requirements=data.get("pip_requirements", ""),
            allow_pr=bool(data.get("allow_pr")),
            enable_opencode=bool(data.get("enable_opencode")),
            enable_zai=bool(data.get("enable_zai")),
            mounts=data.get("mounts", []),
            copies=data.get("copies", []),
        )
        # Remove legacy file after successful migration
        try:
            legacy_path.unlink()
        except OSError:
            pass

        return data

    return None


def list_sandboxes() -> list[dict[str, Any]]:
    """List all sandboxes with their metadata.

    Scans the claude-config directory for sandbox metadata files.

    Returns:
        List of dicts with 'name' and metadata fields for each sandbox.
    """
    config_dir = path_claude_config("")  # get claude-config dir
    # path_claude_config("") gives us the claude-config directory itself
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
    branch: str = "",
    from_branch: str = "",
    working_dir: str = "",
    sparse: bool = False,
    pip_requirements: str = "",
    allow_pr: bool = False,
    network_mode: str = "limited",
    sync_ssh: bool = False,
    enable_opencode: bool = False,
    enable_zai: bool = False,
    mounts: list[str] | None = None,
    copies: list[str] | None = None,
) -> str:
    """Build a display-friendly command line string from cast-new arguments."""
    parts = ["cast new", repo]
    if branch:
        parts.append(branch)
    if from_branch:
        parts.append(from_branch)
    if working_dir:
        parts.extend(["--wd", working_dir])
    if _flag_enabled(sparse):
        parts.append("--sparse")
    if pip_requirements:
        parts.extend(["--pip-requirements", pip_requirements])
    if _flag_enabled(allow_pr):
        parts.append("--allow-pr")
    if network_mode and network_mode != "limited":
        parts.extend(["--network", network_mode])
    if _flag_enabled(sync_ssh):
        parts.append("--with-ssh")
    if _flag_enabled(enable_opencode):
        parts.append("--with-opencode")
    if _flag_enabled(enable_zai):
        parts.append("--with-zai")
    for mount in (mounts or []):
        parts.extend(["--mount", mount])
    for copy in (copies or []):
        parts.extend(["--copy", copy])
    return " ".join(parts)


def _write_cast_new_json(
    path: str | Path,
    *,
    repo: str,
    branch: str = "",
    from_branch: str = "",
    working_dir: str = "",
    sparse: bool = False,
    pip_requirements: str = "",
    allow_pr: bool = False,
    network_mode: str = "limited",
    sync_ssh: bool = False,
    enable_opencode: bool = False,
    enable_zai: bool = False,
    mounts: list[str] | None = None,
    copies: list[str] | None = None,
) -> str:
    """Write cast-new JSON to a file.

    Returns:
        The command line string for display.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    command_line = _build_command_line(
        repo, branch, from_branch, working_dir, sparse,
        pip_requirements, allow_pr, network_mode, sync_ssh,
        enable_opencode, enable_zai, mounts, copies,
    )

    data = {
        "timestamp": timestamp,
        "command_line": command_line,
        "args": {
            "repo": repo,
            "branch": branch,
            "from_branch": from_branch,
            "working_dir": working_dir,
            "sparse": sparse,
            "pip_requirements": pip_requirements,
            "allow_pr": allow_pr,
            "mounts": mounts or [],
            "copies": copies or [],
            "network_mode": network_mode,
            "sync_ssh": sync_ssh,
            "enable_opencode": enable_opencode,
            "enable_zai": enable_zai,
        },
    }

    content = json.dumps(data, indent=2) + "\n"
    _secure_write(Path(path), content)
    return command_line


def save_last_cast_new(
    *,
    repo: str,
    branch: str = "",
    from_branch: str = "",
    working_dir: str = "",
    sparse: bool = False,
    pip_requirements: str = "",
    allow_pr: bool = False,
    network_mode: str = "limited",
    sync_ssh: bool = False,
    enable_opencode: bool = False,
    enable_zai: bool = False,
    mounts: list[str] | None = None,
    copies: list[str] | None = None,
) -> str:
    """Save the most recent cast-new command.

    Returns:
        The command line string for display.
    """
    path = path_last_cast_new()
    return _write_cast_new_json(
        path, repo=repo, branch=branch, from_branch=from_branch,
        working_dir=working_dir, sparse=sparse,
        pip_requirements=pip_requirements, allow_pr=allow_pr,
        network_mode=network_mode, sync_ssh=sync_ssh,
        enable_opencode=enable_opencode, enable_zai=enable_zai,
        mounts=mounts, copies=copies,
    )


def save_cast_preset(
    preset_name: str,
    *,
    repo: str,
    branch: str = "",
    from_branch: str = "",
    working_dir: str = "",
    sparse: bool = False,
    pip_requirements: str = "",
    allow_pr: bool = False,
    network_mode: str = "limited",
    sync_ssh: bool = False,
    enable_opencode: bool = False,
    enable_zai: bool = False,
    mounts: list[str] | None = None,
    copies: list[str] | None = None,
) -> None:
    """Save a named cast-new preset.

    Args:
        preset_name: Name for the preset.
    """
    ensure_dir(path_presets_dir())
    path = path_preset_file(preset_name)
    _write_cast_new_json(
        path, repo=repo, branch=branch, from_branch=from_branch,
        working_dir=working_dir, sparse=sparse,
        pip_requirements=pip_requirements, allow_pr=allow_pr,
        network_mode=network_mode, sync_ssh=sync_ssh,
        enable_opencode=enable_opencode, enable_zai=enable_zai,
        mounts=mounts, copies=copies,
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
    return {
        "command_line": data.get("command_line", ""),
        "repo": args.get("repo", ""),
        "branch": args.get("branch", ""),
        "from_branch": args.get("from_branch", ""),
        "working_dir": args.get("working_dir", ""),
        "sparse": _flag_enabled(args.get("sparse", False)),
        "pip_requirements": args.get("pip_requirements", ""),
        "allow_pr": _flag_enabled(args.get("allow_pr", False)),
        "mounts": args.get("mounts", []),
        "copies": args.get("copies", []),
        "network_mode": args.get("network_mode", "limited"),
        "sync_ssh": _flag_enabled(args.get("sync_ssh", False)),
        "enable_opencode": _flag_enabled(args.get("enable_opencode", False)),
        "enable_zai": _flag_enabled(args.get("enable_zai", False)),
    }


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

    return sorted(
        p.stem for p in presets_dir.glob("*.json")
    )


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


# ============================================================================
# Bridge Commands
# ============================================================================


def _cmd_load_metadata(name: str) -> dict[str, Any] | None:
    """Bridge command: Load sandbox metadata."""
    return load_sandbox_metadata(name)


_WRITE_METADATA_KEYS = frozenset({
    "repo_url", "branch", "from_branch", "network_mode", "sync_ssh",
    "ssh_mode", "working_dir", "sparse_checkout", "pip_requirements",
    "allow_pr", "enable_opencode", "enable_zai", "mounts", "copies",
})


def _cmd_write_metadata(name: str, json_str: str) -> None:
    """Bridge command: Write sandbox metadata from JSON string."""
    data = json.loads(json_str)
    unknown = set(data.keys()) - _WRITE_METADATA_KEYS
    if unknown:
        raise ValueError(f"Unknown metadata keys: {', '.join(sorted(unknown))}")
    write_sandbox_metadata(name, **data)


def _cmd_list_sandboxes() -> list[dict[str, Any]]:
    """Bridge command: List all sandboxes."""
    return list_sandboxes()


def _cmd_inspect(name: str) -> dict[str, Any] | None:
    """Bridge command: Inspect a single sandbox."""
    return inspect_sandbox(name)


def _cmd_save_last_attach(sandbox_name: str) -> None:
    """Bridge command: Save last attach."""
    save_last_attach(sandbox_name)


def _cmd_load_last_attach() -> str | None:
    """Bridge command: Load last attach."""
    return load_last_attach()


def _cmd_list_presets() -> list[str]:
    """Bridge command: List presets."""
    return list_cast_presets()


def _cmd_show_preset(preset_name: str) -> str | None:
    """Bridge command: Show preset."""
    return show_cast_preset(preset_name)


def _cmd_delete_preset(preset_name: str) -> bool:
    """Bridge command: Delete preset."""
    return delete_cast_preset(preset_name)


if __name__ == "__main__":
    bridge_main({
        "load-metadata": _cmd_load_metadata,
        "write-metadata": _cmd_write_metadata,
        "list": _cmd_list_sandboxes,
        "inspect": _cmd_inspect,
        "save-last-attach": _cmd_save_last_attach,
        "load-last-attach": _cmd_load_last_attach,
        "list-presets": _cmd_list_presets,
        "show-preset": _cmd_show_preset,
        "delete-preset": _cmd_delete_preset,
    })
