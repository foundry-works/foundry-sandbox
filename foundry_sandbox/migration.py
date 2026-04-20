"""Migration logic for upgrading from 0.20.x (docker-compose) to 0.21.x (sbx).

Handles metadata format conversion, credential migration, preset translation,
snapshot/rollback, and idempotent re-run detection.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from foundry_sandbox.config import load_json
from foundry_sandbox.constants import get_sandbox_home
from foundry_sandbox.models import CastNewPreset, SbxSandboxMetadata
from foundry_sandbox.paths import path_metadata_legacy_file
from foundry_sandbox.utils import log_error, log_step


# Network mode mapping: old 0.20.x values -> sbx profiles
NETWORK_MODE_MAP: dict[str, str] = {
    "limited": "balanced",
    "host-only": "allow-all",
    "none": "deny-all",
}

# Known SANDBOX_ prefixed keys in legacy metadata.env
_ENV_KEY_MAP: dict[str, str] = {
    "SANDBOX_REPO_URL": "repo_url",
    "SANDBOX_BRANCH": "branch",
    "SANDBOX_FROM_BRANCH": "from_branch",
    "SANDBOX_NETWORK_MODE": "network_mode",
    "SANDBOX_WORKING_DIR": "working_dir",
    "SANDBOX_PIP_REQUIREMENTS": "pip_requirements",
    "SANDBOX_ALLOW_PR": "allow_pr",
    "SANDBOX_ENABLE_OPENCODE": "enable_opencode",
    "SANDBOX_ENABLE_ZAI": "enable_zai",
    "SANDBOX_SYNC_SSH": "sync_ssh",
    "SANDBOX_SSH_MODE": "ssh_mode",
    "SANDBOX_SPARSE_CHECKOUT": "sparse_checkout",
    "SANDBOX_PRE_FOUNDRY": "pre_foundry",
    "SANDBOX_PRE_FOUNDRY_VERSION": "pre_foundry_version",
    "SANDBOX_MOUNTS": "mounts",
    "SANDBOX_COMPOSE_EXTRAS": "compose_extras",
    "SANDBOX_COPIES": "copies",
    "SANDBOX_AGENT": "agent",
}

# Fields present in 0.20.x but dropped in 0.21.x
DROPPED_FIELDS: frozenset[str] = frozenset({
    "mounts", "compose_extras", "sparse_checkout", "sync_ssh",
    "ssh_mode", "pre_foundry", "pre_foundry_version", "network_mode",
})

# Credentials to push via sbx secret set -g
CREDENTIAL_ENV_MAP: dict[str, list[str]] = {
    "anthropic": ["ANTHROPIC_API_KEY"],
    "github": ["GITHUB_TOKEN", "GH_TOKEN"],
    "openai": ["OPENAI_API_KEY"],
}

MIGRATION_SNAPSHOTS_DIR = ".migration-snapshots"
MIGRATION_LOCK_FILE = ".migration-in-progress"
SNAPSHOT_MANIFEST_FILE = "snapshot-manifest.json"


def parse_legacy_env_metadata(path: Path) -> dict[str, Any]:
    """Parse a legacy metadata.env file (0.20.x key=value format).

    Handles comments, blank lines, and bash array syntax like
    ``SANDBOX_COPIES=(file.txt:/dest/file.txt)``.

    Args:
        path: Path to the metadata.env file.

    Returns:
        Dictionary with old SandboxMetadata field names.
    """
    if not path.exists():
        return {}

    data: dict[str, Any] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        field = _ENV_KEY_MAP.get(key)
        if not field:
            continue

        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]

        # Handle bash array syntax: KEY=(item1 item2)
        if value.startswith("(") and value.endswith(")"):
            inner = value[1:-1].strip()
            if inner:
                items = [item.strip() for item in inner.split() if item.strip()]
            else:
                items = []
            data[field] = items
        elif field in ("allow_pr", "enable_opencode", "enable_zai", "sync_ssh",
                       "sparse_checkout", "pre_foundry"):
            data[field] = _parse_bool(value)
        else:
            data[field] = value

    return data


def convert_old_metadata_to_sbx(
    old_data: dict[str, Any],
    sandbox_name: str,
) -> tuple[dict[str, Any], list[str]]:
    """Convert old SandboxMetadata dict to SbxSandboxMetadata format.

    Args:
        old_data: Old metadata dict (from metadata.env or old metadata.json).
        sandbox_name: Sandbox directory name (used as sbx_name).

    Returns:
        Tuple of (new metadata dict, list of warning strings).
    """
    warnings: list[str] = []

    # Map network_mode -> network_profile
    network_profile = "balanced"
    old_network = old_data.get("network_mode", "limited")
    if old_network in NETWORK_MODE_MAP:
        network_profile = NETWORK_MODE_MAP[old_network]
    elif old_network:
        warnings.append(f"Unknown network_mode '{old_network}', defaulting to 'balanced'")

    # Collect dropped fields for reporting
    for field in DROPPED_FIELDS:
        val = old_data.get(field)
        if val and val not in ("", [], False, 0, "0"):
            if field != "network_mode":  # network_mode is mapped, not truly dropped
                warnings.append(f"Dropped field '{field}' (value: {val!r})")

    # Parse boolean fields
    allow_pr = _parse_bool(old_data.get("allow_pr", False))
    enable_opencode = _parse_bool(old_data.get("enable_opencode", False))
    enable_zai = _parse_bool(old_data.get("enable_zai", False))

    copies = old_data.get("copies", [])
    if isinstance(copies, str):
        copies = [c.strip() for c in copies.split() if c.strip()] if copies.strip() else []

    new_data = {
        "backend": "sbx",
        "sbx_name": sandbox_name,
        "agent": old_data.get("agent", "claude") or "claude",
        "repo_url": old_data.get("repo_url", ""),
        "branch": old_data.get("branch", ""),
        "from_branch": old_data.get("from_branch", ""),
        "network_profile": network_profile,
        "git_safety_enabled": True,
        "workspace_dir": "/workspace",
        "working_dir": old_data.get("working_dir", ""),
        "pip_requirements": old_data.get("pip_requirements", ""),
        "allow_pr": allow_pr,
        "enable_opencode": enable_opencode,
        "enable_zai": enable_zai,
        "copies": copies,
        "template": "",
    }

    # Validate via Pydantic
    try:
        model = SbxSandboxMetadata(**new_data)
        return model.model_dump(), warnings
    except Exception as exc:
        warnings.append(f"Schema validation issue: {exc}")
        return new_data, warnings


def convert_old_preset_to_new(
    old_preset: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Convert old CastNewPreset args dict to new format.

    Args:
        old_preset: Dict from preset file's "args" key.

    Returns:
        Tuple of (new args dict, list of warning strings).
    """
    warnings: list[str] = []
    args = dict(old_preset)

    # Map network_mode -> network_profile
    if "network_mode" in args:
        old_val = args.pop("network_mode")
        if old_val and old_val in NETWORK_MODE_MAP:
            args.setdefault("network_profile", NETWORK_MODE_MAP[old_val])
        elif old_val:
            args.setdefault("network_profile", "balanced")
            warnings.append(f"Unknown network_mode '{old_val}', defaulted to 'balanced'")

    # Add agent default if missing
    if "agent" not in args:
        args["agent"] = "claude"

    # Report dropped fields
    for field in ("sparse", "pre_foundry", "sync_ssh", "mounts", "compose_extras"):
        val = args.pop(field, None)
        if val and val not in ("", [], False, 0, "0"):
            warnings.append(f"Dropped preset field '{field}' (value: {val!r})")

    # Remove any remaining unknown keys not in CastNewPreset
    valid_fields = set(CastNewPreset.model_fields)
    unknown = set(args) - valid_fields
    for key in unknown:
        val = args.pop(key)
        warnings.append(f"Removed unknown preset field '{key}'")

    # Validate via Pydantic
    try:
        model = CastNewPreset(**args)
        return model.model_dump(), warnings
    except Exception as exc:
        warnings.append(f"Preset validation issue: {exc}")
        return args, warnings


def classify_sandbox_dirs(sandbox_home: Path | None = None) -> list[dict[str, str]]:
    """Scan claude-config/ and classify each sandbox by metadata format.

    Args:
        sandbox_home: Override sandbox home directory.

    Returns:
        List of dicts with 'name' and 'format' keys.
    """
    if sandbox_home is None:
        sandbox_home = get_sandbox_home()

    config_dir = sandbox_home / "claude-config"
    if not config_dir.exists():
        return []

    results: list[dict[str, str]] = []
    for entry in sorted(config_dir.iterdir()):
        if not entry.is_dir():
            continue

        name = entry.name
        json_path = entry / "metadata.json"
        env_path = path_metadata_legacy_file(name)

        if json_path.exists():
            data = load_json(str(json_path))
            if data.get("backend") == "sbx":
                fmt = "sbx"
            else:
                fmt = "old_json"
        elif env_path.exists():
            fmt = "legacy_env"
        else:
            fmt = "empty"

        results.append({"name": name, "format": fmt})

    return results


def snapshot_sandbox_home(
    sandbox_home: Path | None = None,
    snapshot_dir: Path | None = None,
) -> Path:
    """Create a timestamped snapshot of metadata files in ~/.sandboxes/.

    Snapshots claude-config/, presets/, and state dot-files.
    Does NOT copy repos/ or worktrees/ (large, regenerable).

    Args:
        sandbox_home: Override sandbox home directory.
        snapshot_dir: Override snapshot destination path.

    Returns:
        Path to the snapshot directory.
    """
    if sandbox_home is None:
        sandbox_home = get_sandbox_home()

    if snapshot_dir is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        snapshot_dir = sandbox_home / MIGRATION_SNAPSHOTS_DIR / ts

    snapshot_dir.mkdir(parents=True, exist_ok=True)

    # Paths to snapshot
    items_to_copy: list[tuple[str, Path]] = [
        ("claude-config", sandbox_home / "claude-config"),
        ("presets", sandbox_home / "presets"),
    ]
    dot_files: list[tuple[str, Path]] = [
        (".last-cast-new.json", sandbox_home / ".last-cast-new.json"),
        (".last-attach.json", sandbox_home / ".last-attach.json"),
    ]

    copied_files = 0
    copied_dirs = 0

    for label, src in items_to_copy:
        if not src.exists():
            continue
        dst = snapshot_dir / label
        shutil.copytree(src, dst, symlinks=False, dirs_exist_ok=True)
        copied_dirs += 1

    for label, src in dot_files:
        if not src.exists():
            continue
        dst = snapshot_dir / label
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied_files += 1

    # Write manifest
    sandbox_names: list[str] = []
    config_dir = sandbox_home / "claude-config"
    if config_dir.exists():
        sandbox_names = sorted(
            e.name for e in config_dir.iterdir() if e.is_dir()
        )

    preset_names: list[str] = []
    presets_dir = sandbox_home / "presets"
    if presets_dir.exists():
        preset_names = sorted(p.stem for p in presets_dir.glob("*.json"))

    manifest = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_version": "0.20.x",
        "sandbox_names": sandbox_names,
        "preset_names": preset_names,
        "copied_dirs": copied_dirs,
        "copied_files": copied_files,
    }

    manifest_path = snapshot_dir / SNAPSHOT_MANIFEST_FILE
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    # Write migration lock
    lock_path = sandbox_home / MIGRATION_LOCK_FILE
    lock_path.write_text(json.dumps({
        "snapshot_dir": str(snapshot_dir),
        "timestamp": manifest["timestamp"],
    }) + "\n")

    return snapshot_dir


def restore_from_snapshot(
    snapshot_dir: Path,
    sandbox_home: Path | None = None,
) -> None:
    """Restore ~/.sandboxes/ metadata from a snapshot.

    Replaces current claude-config/ and presets/ with snapshot contents.

    Args:
        snapshot_dir: Path to the snapshot directory.
        sandbox_home: Override sandbox home directory.
    """
    if sandbox_home is None:
        sandbox_home = get_sandbox_home()

    # Restore directories
    for label in ("claude-config", "presets"):
        src = snapshot_dir / label
        dst = sandbox_home / label
        if not src.exists():
            continue
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, symlinks=False, dirs_exist_ok=True)

    # Restore dot-files
    for label in (".last-cast-new.json", ".last-attach.json"):
        src = snapshot_dir / label
        dst = sandbox_home / label
        if not src.exists():
            continue
        shutil.copy2(src, dst)

    # Remove migration lock
    lock_path = sandbox_home / MIGRATION_LOCK_FILE
    if lock_path.exists():
        lock_path.unlink()


def find_latest_snapshot(sandbox_home: Path | None = None) -> Path | None:
    """Find the most recent migration snapshot.

    Args:
        sandbox_home: Override sandbox home directory.

    Returns:
        Path to the latest snapshot directory, or None if no snapshots exist.
    """
    if sandbox_home is None:
        sandbox_home = get_sandbox_home()

    snapshots_dir = sandbox_home / MIGRATION_SNAPSHOTS_DIR
    if not snapshots_dir.exists():
        return None

    snapshots = sorted(
        (d for d in snapshots_dir.iterdir() if d.is_dir()),
        key=lambda d: d.name,
        reverse=True,
    )

    if not snapshots:
        return None

    latest = snapshots[0]
    if not (latest / SNAPSHOT_MANIFEST_FILE).exists():
        return None

    return latest


def push_credentials(
    dry_run: bool = False,
) -> tuple[list[str], list[str]]:
    """Push host credentials to sbx secrets.

    Args:
        dry_run: If True, don't actually push secrets.

    Returns:
        Tuple of (pushed_services, missing_services).
    """
    from foundry_sandbox.sbx import sbx_secret_set

    pushed: list[str] = []
    missing: list[str] = []

    for service, env_keys in CREDENTIAL_ENV_MAP.items():
        value = ""
        for key in env_keys:
            value = os.environ.get(key, "")
            if value:
                break

        if not value:
            missing.append(service)
            continue

        if dry_run:
            log_step(f"Would push: {service}")
        else:
            try:
                sbx_secret_set(service, value, global_scope=True)
                log_step(f"Pushed: {service}")
            except Exception as exc:
                log_error(f"Failed to push {service}: {exc}")
                missing.append(service)
                continue

        pushed.append(service)

    # Push user-defined service credentials
    try:
        from foundry_sandbox.user_services import _slug, get_user_services

        for svc in get_user_services():
            slug = _slug(str(svc["name"]))
            value = os.environ.get(str(svc["env_var"]), "")
            if not value:
                missing.append(slug)
                continue
            if dry_run:
                log_step(f"Would push: {slug}")
            else:
                try:
                    sbx_secret_set(slug, value, global_scope=True)
                    log_step(f"Pushed: {slug}")
                except Exception as exc:
                    log_error(f"Failed to push {slug}: {exc}")
                    missing.append(slug)
                    continue
            pushed.append(slug)
    except Exception as exc:
        from foundry_sandbox.utils import log_warn
        log_warn(f"User service credential migration skipped: {exc}")

    return pushed, missing


def get_migration_lock(sandbox_home: Path | None = None) -> dict[str, Any] | None:
    """Read the migration-in-progress lock file.

    Args:
        sandbox_home: Override sandbox home directory.

    Returns:
        Lock data dict if lock exists, None otherwise.
    """
    if sandbox_home is None:
        sandbox_home = get_sandbox_home()

    lock_path = sandbox_home / MIGRATION_LOCK_FILE
    if not lock_path.exists():
        return None

    return load_json(str(lock_path))


def remove_migration_lock(sandbox_home: Path | None = None) -> None:
    """Remove the migration-in-progress lock file."""
    if sandbox_home is None:
        sandbox_home = get_sandbox_home()

    lock_path = sandbox_home / MIGRATION_LOCK_FILE
    if lock_path.exists():
        lock_path.unlink()


def _parse_bool(value: Any) -> bool:
    """Parse a boolean value from various formats."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False
