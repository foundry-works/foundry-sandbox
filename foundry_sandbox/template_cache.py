"""Managed template caching for profile-backed environments.

Builds a cached sbx template from a profile's bakeable inputs (packages,
tooling bundles) so subsequent sandboxes start faster. Secrets, git-safety
state, and runtime configuration are never baked into templates.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from foundry_sandbox.paths import path_template_cache_dir, path_template_cache_file


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TemplateCacheEntry(BaseModel):
    """Cache state for a single profile's managed template."""

    profile_name: str
    cache_key: str
    template_tag: str
    base_template: str
    built_at: str  # ISO 8601 UTC
    sbx_version: str
    cast_version: str
    bakeable_inputs: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Cache key derivation
# ---------------------------------------------------------------------------

_SECRET_PATTERN = re.compile(r"\$\{from_host:[^}]+\}")


def _sanitize_env_for_hash(env: dict[str, str] | None) -> dict[str, str]:
    """Replace secret references with a sentinel so they don't affect the hash."""
    if not env:
        return {}
    return {k: (_SECRET_PATTERN.sub("__LATE_BOUND__", v)) for k, v in env.items()}


def _serialize_bundle_for_hash(bundle: Any) -> dict[str, Any]:
    """Serialize a ToolingBundle into a hashable dict, stripping secrets."""
    entry: dict[str, Any] = {}
    if hasattr(bundle, "skills") and bundle.skills:
        entry["skills"] = [s.model_dump() for s in bundle.skills]
    if hasattr(bundle, "commands") and bundle.commands:
        entry["commands"] = list(bundle.commands)
    if hasattr(bundle, "mcp_servers") and bundle.mcp_servers:
        servers = []
        for srv in bundle.mcp_servers:
            d = srv.model_dump()
            if "env" in d and isinstance(d["env"], dict):
                d["env"] = _sanitize_env_for_hash(d["env"])
            servers.append(d)
        entry["mcp_servers"] = servers
    if hasattr(bundle, "hooks") and bundle.hooks:
        entry["hooks"] = {
            k: [{"match": r.match, "command": r.command} for r in rules]
            for k, rules in bundle.hooks.items()
        }
    if hasattr(bundle, "permissions") and bundle.permissions:
        entry["permissions"] = bundle.permissions.model_dump()
    if hasattr(bundle, "packages") and bundle.packages:
        entry["packages"] = bundle.packages.model_dump()
    return entry


def _serialize_packages(profile: Any) -> dict[str, Any]:
    """Normalize a DevProfile's packages + pip_requirements into a dict."""
    result: dict[str, Any] = {}
    packages = getattr(profile, "packages", None)
    pip_req = getattr(profile, "pip_requirements", None) or ""

    if packages:
        result = packages.model_dump(exclude_none=True)
    if pip_req and "pip" not in result:
        result["pip"] = pip_req
    return result


def derive_cache_key(
    profile_name: str,
    profile: Any,
    config: Any,
    base_template: str,
) -> str:
    """Derive a 16-char hex cache key from the profile's bakeable inputs."""
    from foundry_sandbox import __version__
    from foundry_sandbox.sbx import get_sbx_version

    canonical: dict[str, Any] = {
        "profile_name": profile_name,
        "base_template": base_template,
        "packages": _serialize_packages(profile),
        "tooling": [],
    }
    tooling_names = getattr(profile, "tooling", []) or []
    bundles = getattr(config, "tooling_bundles", {}) or {}
    for name in tooling_names:
        bundle = bundles.get(name)
        entry: dict[str, Any] = {"name": name}
        if bundle:
            entry.update(_serialize_bundle_for_hash(bundle))
        canonical["tooling"].append(entry)

    canonical["cast_version"] = __version__
    canonical["sbx_version"] = get_sbx_version() or "unknown"

    blob = json.dumps(canonical, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def _has_bakeable_content(profile: Any, config: Any) -> bool:
    """Check if a profile has anything worth baking into a template."""
    packages = _serialize_packages(profile)
    if packages:
        return True
    tooling_names = getattr(profile, "tooling", []) or []
    bundles = getattr(config, "tooling_bundles", {}) or {}
    for name in tooling_names:
        bundle = bundles.get(name)
        if bundle and bundle.packages:
            return True
    return False


# ---------------------------------------------------------------------------
# Managed tag naming
# ---------------------------------------------------------------------------

def _managed_tag(profile_name: str, cache_key: str) -> str:
    """Generate a managed template tag: profile-<name>-<key>:latest."""
    normalized = re.sub(r"[^a-zA-Z0-9._-]", "-", profile_name)
    tag = f"profile-{normalized}-{cache_key}:latest"
    image_name = tag.split(":")[0]
    if (
        not image_name
        or image_name[-1] in ".-"
        or len(image_name) < 2
        or "--" in image_name
    ):
        raise ValueError(f"Cannot derive valid template tag for profile: {profile_name!r}")
    return tag


# ---------------------------------------------------------------------------
# Cache state read/write
# ---------------------------------------------------------------------------

def _read_cache_entry(profile_name: str) -> TemplateCacheEntry | None:
    """Read a cache entry from disk. Returns None if missing or corrupt."""
    path = path_template_cache_file(profile_name)
    if not path.exists():
        return None
    try:
        return TemplateCacheEntry.model_validate_json(path.read_text())
    except Exception:
        return None


def _write_cache_entry(entry: TemplateCacheEntry) -> None:
    """Write a cache entry to disk atomically."""
    from foundry_sandbox.atomic_io import atomic_write

    path = path_template_cache_file(entry.profile_name)
    atomic_write(path, entry.model_dump_json(indent=2))


def _bakeable_inputs_snapshot(profile: Any, config: Any, base_template: str) -> dict[str, Any]:
    """Capture the current bakeable inputs for provenance tracking."""
    tooling_names = getattr(profile, "tooling", []) or []
    return {
        "packages": _serialize_packages(profile),
        "tooling": list(tooling_names),
        "base_template": base_template,
    }


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

def lookup_cached_template(profile_name: str) -> str | None:
    """Return the managed template tag if a valid cache exists, else None.

    Validates that the template actually exists in sbx (not just the cache file).
    """
    entry = _read_cache_entry(profile_name)
    if entry is None:
        return None

    from foundry_sandbox.sbx import sbx_template_ls

    templates = sbx_template_ls()
    if not any(entry.template_tag in t for t in templates):
        return None

    return entry.template_tag


def is_cache_stale(
    profile_name: str,
    profile: Any,
    config: Any,
    base_template: str,
) -> bool:
    """Check if the current profile inputs differ from the cached template."""
    entry = _read_cache_entry(profile_name)
    if entry is None:
        return True

    current_key = derive_cache_key(profile_name, profile, config, base_template)
    return current_key != entry.cache_key


# ---------------------------------------------------------------------------
# Build flow
# ---------------------------------------------------------------------------

def build_profile_template(
    profile_name: str,
    profile: Any,
    config: Any,
    base_template: str,
) -> str:
    """Build (or reuse) a cached template for the given profile.

    Returns the managed template tag. On failure, raises RuntimeError.
    """
    from foundry_sandbox import __version__
    from foundry_sandbox.foundry_config import (
        DevProfile,
        collect_bundle_packages,
        normalize_profile_packages,
    )
    from foundry_sandbox.sbx import (
        bootstrap_packages,
        get_sbx_version,
        sbx_create,
        sbx_rm,
        sbx_template_ls,
        sbx_template_save,
    )

    cache_key = derive_cache_key(profile_name, profile, config, base_template)
    tag = _managed_tag(profile_name, cache_key)

    # Cache hit: template already exists
    templates = sbx_template_ls()
    if any(tag in t for t in templates):
        entry = _read_cache_entry(profile_name)
        if entry and entry.cache_key == cache_key:
            return tag

    # Clean up old template if cache key changed
    old_entry = _read_cache_entry(profile_name)
    if old_entry and old_entry.template_tag != tag:
        from foundry_sandbox.sbx import sbx_template_rm
        try:
            sbx_template_rm(old_entry.template_tag)
        except Exception:
            pass

    # Resolve packages to bake (profile + bundles)
    packages = normalize_profile_packages(profile)
    if getattr(profile, "tooling", None):
        bundle_pkgs = collect_bundle_packages(config, profile)
        if bundle_pkgs:
            bp = normalize_profile_packages(DevProfile(packages=bundle_pkgs))
            for k, v in bp.items():
                if k not in packages:
                    packages[k] = v

    # Build seed sandbox
    seed_name = f"profile-seed-{profile_name}-{os.getpid()}"

    # Ensure base template is available
    from foundry_sandbox.git_safety import FOUNDRY_TEMPLATE_TAG, ensure_foundry_template
    use_base = base_template or FOUNDRY_TEMPLATE_TAG
    if use_base == FOUNDRY_TEMPLATE_TAG:
        ensure_foundry_template()

    try:
        sbx_create(seed_name, "shell", "/tmp", template=use_base)

        if packages:
            bootstrap_packages(seed_name, packages)

        sbx_template_save(seed_name, tag)

        entry = TemplateCacheEntry(
            profile_name=profile_name,
            cache_key=cache_key,
            template_tag=tag,
            base_template=use_base,
            built_at=datetime.now(timezone.utc).isoformat(),
            sbx_version=get_sbx_version() or "unknown",
            cast_version=__version__,
            bakeable_inputs=_bakeable_inputs_snapshot(profile, config, base_template),
        )
        _write_cache_entry(entry)

        return tag

    except Exception as exc:
        raise RuntimeError(f"Profile template build failed for '{profile_name}': {exc}") from exc
    finally:
        try:
            sbx_rm(seed_name)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# List / Invalidate
# ---------------------------------------------------------------------------

def list_cached_templates() -> list[TemplateCacheEntry]:
    """List all cache entries (reads from disk, no sbx validation)."""
    cache_dir = path_template_cache_dir()
    if not cache_dir.exists():
        return []
    entries = []
    for f in sorted(cache_dir.glob("*.json")):
        try:
            entries.append(TemplateCacheEntry.model_validate_json(f.read_text()))
        except Exception:
            pass
    return entries


def invalidate_cached_template(profile_name: str) -> bool:
    """Remove a cached template (sbx image + cache file). Returns True if anything was removed."""
    from foundry_sandbox.sbx import sbx_template_rm

    entry = _read_cache_entry(profile_name)
    removed = False

    if entry:
        try:
            sbx_template_rm(entry.template_tag)
            removed = True
        except Exception:
            pass

    path = path_template_cache_file(profile_name)
    if path.exists():
        path.unlink()
        removed = True

    return removed
