"""Artifact bundles: typed side-effect descriptors and the fixed-order applier.

Each compiler emits an ``ArtifactBundle``. Bundles merge into one; the applier
is the only code with side effects. Apply order is fixed:

1. sbx secrets (before anything that reads them)
2. Policy patches (git-safety registration)
3. File writes (base64-through-sbx-exec)
4. Env vars (profile.d / bash.bashrc / .env)
5. Post steps (runtime has everything it needs)

Phase 2 lands step 2 (policy patches). Other steps raise ``NotImplementedError``
until their respective phases ship.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from foundry_sandbox.atomic_io import atomic_write
from foundry_sandbox.sbx import sbx_exec

logger = logging.getLogger(__name__)

_FOUNDRY_BASE = os.path.expanduser("~/.foundry")
_DEFAULT_DATA_DIR = os.environ.get(
    "FOUNDRY_DATA_DIR", f"{_FOUNDRY_BASE}/data/git-safety"
)


# ---------------------------------------------------------------------------
# Artifact types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileWrite:
    container_path: str
    content: bytes
    mode: int = 0o644
    owner: str = "agent"


@dataclass(frozen=True)
class PolicyPatch:
    op: Literal["add"]
    path: str  # e.g. "protected_branches", "blocked_patterns", "allow_pr"
    value: list[str] | bool


@dataclass(frozen=True)
class PostStep:
    cmd: list[str]
    user: str = "agent"


@dataclass
class ArtifactBundle:
    file_writes: list[FileWrite] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    policy_patches: list[PolicyPatch] = field(default_factory=list)
    sbx_secrets: list[tuple[str, str]] = field(default_factory=list)
    post_steps: list[PostStep] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


def _merge_bundles(bundles: list[ArtifactBundle]) -> ArtifactBundle:
    """Merge multiple bundles into one. Lists concatenate, dicts merge."""
    merged = ArtifactBundle()
    for b in bundles:
        merged.file_writes.extend(b.file_writes)
        merged.env_vars.update(b.env_vars)
        merged.policy_patches.extend(b.policy_patches)
        merged.sbx_secrets.extend(b.sbx_secrets)
        merged.post_steps.extend(b.post_steps)
    return merged


# ---------------------------------------------------------------------------
# Policy-patch applier
# ---------------------------------------------------------------------------


def _sandbox_metadata_path(sandbox_id: str) -> Path:
    base_dir = os.environ.get("FOUNDRY_DATA_DIR", _DEFAULT_DATA_DIR)
    return Path(base_dir) / "sandboxes" / f"{sandbox_id}.json"


def _patch_sandbox_policy(sandbox_id: str, patches: list[PolicyPatch]) -> None:
    """Apply policy patches additively to a sandbox's registration file.

    Reads the existing JSON, extends lists (never overwrites), sets flags only
    if currently unset or tightening, writes atomically.
    """
    if not patches:
        return

    meta_path = _sandbox_metadata_path(sandbox_id)

    # Read existing metadata
    if meta_path.exists():
        meta: dict[str, object] = json.loads(meta_path.read_text())
    else:
        meta = {}

    for patch in patches:
        if patch.op != "add":
            continue

        key = patch.path
        if isinstance(patch.value, bool):
            # Boolean flags: only tighten (never loosen).
            # If already False, keep False. If unset, set to value.
            current = meta.get(key)
            if current is None:
                meta[key] = patch.value
            elif isinstance(current, bool) and isinstance(patch.value, bool):
                meta[key] = current and patch.value
        elif isinstance(patch.value, list):
            existing = meta.get(key)
            if isinstance(existing, list):
                # Extend, dedup preserving order
                seen = set(existing)
                for item in patch.value:
                    if item not in seen:
                        existing.append(item)
                        seen.add(item)
            else:
                meta[key] = list(patch.value)

    atomic_write(meta_path, json.dumps(meta, indent=2))
    meta_path.chmod(0o644)


# ---------------------------------------------------------------------------
# sbx-secret applier
# ---------------------------------------------------------------------------


def _apply_sbx_secrets(secrets: list[tuple[str, str]]) -> None:
    """Push secrets to the host so the proxy can read them at request time.

    Each entry is (slug, host_env_var_name). The real value is read from
    os.environ on the host — never stored in the bundle.
    """
    from foundry_sandbox.sbx import sbx_secret_set

    for slug_name, env_var in secrets:
        value = os.environ.get(env_var, "")
        if not value:
            logger.warning("sbx secret %s: host env %s is unset, skipping", slug_name, env_var)
            continue
        sbx_secret_set(slug_name, value)


# ---------------------------------------------------------------------------
# Env-var applier
# ---------------------------------------------------------------------------


def _apply_env_vars(sandbox_name: str, env_vars: dict[str, str]) -> None:
    """Write env vars into a sandbox via profile.d + bash.bashrc + .env.

    Uses the same base64-through-sbx-exec pattern as git_safety.py.
    """
    import base64

    if not env_vars:
        return

    lines = "".join(f"export {k}={v}\n" for k, v in sorted(env_vars.items()))

    # profile.d (login shells)
    payload = base64.b64encode(lines.encode()).decode()
    sbx_exec(
        sandbox_name,
        ["sh", "-c",
         f"echo '{payload}' | base64 -d > /etc/profile.d/foundry-user-services.sh "
         f"&& chmod 644 /etc/profile.d/foundry-user-services.sh"],
        user="root",
        quiet=True,
    )

    # bash.bashrc (non-login interactive shells) — guarded append
    block = f"# >>> foundry-user-services >>>\n{lines}# <<< foundry-user-services <<<\n"
    payload = base64.b64encode(block.encode()).decode()
    sbx_exec(
        sandbox_name,
        ["sh", "-c",
         f"if ! grep -q 'foundry-user-services' /etc/bash.bashrc 2>/dev/null; then "
         f"echo '{payload}' | base64 -d >> /etc/bash.bashrc; fi"],
        user="root",
        quiet=True,
    )

    # Plain env for programmatic reads
    plain_lines = "".join(f"{k}={v}\n" for k, v in sorted(env_vars.items()))
    payload = base64.b64encode(plain_lines.encode()).decode()
    sbx_exec(
        sandbox_name,
        ["sh", "-c",
         f"mkdir -p /var/lib/foundry && echo '{payload}' | base64 -d "
         f"> /var/lib/foundry/user-services.env && chmod 644 /var/lib/foundry/user-services.env"],
        user="root",
        quiet=True,
    )


# ---------------------------------------------------------------------------
# Top-level applier (5-step fixed order)
# ---------------------------------------------------------------------------


def apply_artifacts(
    name: str,
    bundle: ArtifactBundle,
    *,
    sandbox_id: str,
) -> None:
    """Apply a merged artifact bundle to a sandbox in fixed order."""
    # Step 1: sbx secrets
    if bundle.sbx_secrets:
        logger.info("Pushing %d sbx secrets for %s", len(bundle.sbx_secrets), sandbox_id)
        _apply_sbx_secrets(bundle.sbx_secrets)

    # Step 2: Policy patches
    if bundle.policy_patches:
        logger.info("Applying %d policy patches to %s", len(bundle.policy_patches), sandbox_id)
        _patch_sandbox_policy(sandbox_id, bundle.policy_patches)

    # Step 3: File writes
    if bundle.file_writes:
        raise NotImplementedError("file_writes apply (Phase 4+)")

    # Step 4: Env vars
    if bundle.env_vars:
        logger.info("Injecting %d env vars into %s", len(bundle.env_vars), sandbox_id)
        _apply_env_vars(name, bundle.env_vars)

    # Step 5: Post steps
    if bundle.post_steps:
        raise NotImplementedError("post_steps apply (Phase 5+)")
