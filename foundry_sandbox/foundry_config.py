"""Declarative foundry.yaml config: schema, three-layer resolver, plan renderer, compilers.

Layers resolve in order: built-in defaults -> ~/.foundry/foundry.yaml -> repo foundry.yaml.
Merge is additive-only: lists concatenate, allow flags AND across layers, overlays can only
tighten policy. The repo layer cannot weaken a user-layer forbid.

Compilers turn resolved config sections into ArtifactBundles (pure functions).
"""

from __future__ import annotations

import importlib.resources
import logging
from pathlib import Path
from typing import Annotated, Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from foundry_sandbox.artifacts import ArtifactBundle, PolicyPatch
from foundry_sandbox.user_services import slug

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# git-safety overlay
# ---------------------------------------------------------------------------


class ProtectedBranchesAdd(_Strict):
    add: list[str] = Field(default_factory=list)


class FileRestrictionsAdd(_Strict):
    blocked_patterns_add: list[str] = Field(default_factory=list)


class GitSafetyOverlay(_Strict):
    protected_branches: ProtectedBranchesAdd | None = None
    file_restrictions: FileRestrictionsAdd | None = None
    allow_pr_operations: bool | None = None


# ---------------------------------------------------------------------------
# MCP servers (discriminated union)
# ---------------------------------------------------------------------------


class McpServerBuiltin(_Strict):
    name: str
    type: Literal["builtin"]
    env: dict[str, str] = Field(default_factory=dict)


class McpServerProxy(_Strict):
    name: str
    type: Literal["proxy"]
    host_env: str
    target: str


class McpServerNpm(_Strict):
    name: str
    type: Literal["npm"]
    package: str
    env: dict[str, str] = Field(default_factory=dict)


McpServer = Annotated[
    Union[McpServerBuiltin, McpServerProxy, McpServerNpm],
    Field(discriminator="type"),
]


# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------


class SkillSource(_Strict):
    source: str | None = None
    git: str | None = None
    path: str | None = None


class HookRule(_Strict):
    match: str
    command: str


class Permissions(_Strict):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class ClaudeCodeConfig(_Strict):
    skills: list[SkillSource] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    hooks: dict[str, list[HookRule]] = Field(default_factory=dict)
    permissions: Permissions | None = None


# ---------------------------------------------------------------------------
# user-defined services
# ---------------------------------------------------------------------------


class UserService(_Strict):
    name: str
    env_var: str
    domain: str
    header: str = "Authorization"
    format: Literal["bearer", "header", "query"] = "bearer"


# ---------------------------------------------------------------------------
# top level
# ---------------------------------------------------------------------------


class FoundryConfig(_Strict):
    version: Literal["1"]
    git_safety: GitSafetyOverlay | None = None
    mcp_servers: list[McpServer] = Field(default_factory=list)
    claude_code: ClaudeCodeConfig | None = None
    user_services: list[UserService] = Field(default_factory=list)
    allow_third_party_mcp: bool = False

    @model_validator(mode="after")
    def _gate_third_party_mcp(self) -> FoundryConfig:
        if not self.allow_third_party_mcp:
            bad = [s.name for s in self.mcp_servers if s.type == "npm"]
            if bad:
                raise ValueError(
                    f"MCP servers {bad} are type=npm but allow_third_party_mcp is off"
                )
        return self


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

_USER_CONFIG_PATH = Path.home() / ".foundry" / "foundry.yaml"


def _builtin_defaults_path() -> Path:
    ref = importlib.resources.files("foundry_sandbox.default_config").joinpath("foundry.yaml")
    return Path(str(ref))


def _load_layer(path: Path) -> FoundryConfig | None:
    if not path.exists():
        return None
    try:
        raw = yaml.safe_load(path.read_text())
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to load foundry config %s: %s", path, exc)
        return None
    if not raw:
        return None
    try:
        return FoundryConfig(**raw)
    except (ValidationError, ValueError) as exc:
        logger.warning("Invalid foundry config %s: %s", path, exc)
        return None


def _merge(layers: list[FoundryConfig]) -> FoundryConfig:
    if not layers:
        return FoundryConfig(version="1")
    if len(layers) == 1:
        return layers[0]

    versions = {layer.version for layer in layers}
    if len(versions) > 1:
        raise ValueError(
            f"foundry.yaml version mismatch across layers: {sorted(versions)}"
        )

    result = FoundryConfig(version=layers[0].version)

    # allow_third_party_mcp: AND across layers
    result.allow_third_party_mcp = all(layer.allow_third_party_mcp for layer in layers)

    # Lists: concatenate
    all_mcp: list[McpServer] = []
    all_user_svcs: list[UserService] = []
    for layer in layers:
        all_mcp.extend(layer.mcp_servers)
        all_user_svcs.extend(layer.user_services)
    result.mcp_servers = all_mcp
    result.user_services = all_user_svcs

    # Git safety overlay: additive merge
    result.git_safety = _merge_git_safety(layers)

    # Claude code: last non-None wins (hooks merge per-key)
    result.claude_code = _merge_claude_code(layers)

    return result


def _merge_git_safety(layers: list[FoundryConfig]) -> GitSafetyOverlay | None:
    has_any = any(layer.git_safety is not None for layer in layers)
    if not has_any:
        return None

    prot_add: list[str] = []
    blocked_add: list[str] = []
    allow_pr: bool | None = None

    for layer in layers:
        g = layer.git_safety
        if g is None:
            continue
        if g.protected_branches:
            prot_add.extend(g.protected_branches.add)
        if g.file_restrictions:
            blocked_add.extend(g.file_restrictions.blocked_patterns_add)
        if g.allow_pr_operations is not None:
            # AND semantics: once False, stays False
            if allow_pr is None:
                allow_pr = g.allow_pr_operations
            else:
                allow_pr = allow_pr and g.allow_pr_operations

    return GitSafetyOverlay(
        protected_branches=ProtectedBranchesAdd(add=prot_add) if prot_add else None,
        file_restrictions=FileRestrictionsAdd(blocked_patterns_add=blocked_add) if blocked_add else None,
        allow_pr_operations=allow_pr,
    )


def _merge_claude_code(layers: list[FoundryConfig]) -> ClaudeCodeConfig | None:
    has_any = any(layer.claude_code is not None for layer in layers)
    if not has_any:
        return None

    all_skills: list[SkillSource] = []
    all_commands: list[str] = []
    merged_hooks: dict[str, list[HookRule]] = {}
    merged_perms: Permissions | None = None

    for layer in layers:
        c = layer.claude_code
        if c is None:
            continue
        all_skills.extend(c.skills)
        all_commands.extend(c.commands)
        for key, rules in c.hooks.items():
            merged_hooks.setdefault(key, []).extend(rules)
        if c.permissions is not None:
            if merged_perms is None:
                merged_perms = Permissions(
                    allow=list(c.permissions.allow),
                    deny=list(c.permissions.deny),
                )
            else:
                merged_perms.allow.extend(c.permissions.allow)
                merged_perms.deny.extend(c.permissions.deny)

    return ClaudeCodeConfig(
        skills=all_skills,
        commands=all_commands,
        hooks=merged_hooks,
        permissions=merged_perms,
    )


def resolve_foundry_config(repo_root: Path) -> FoundryConfig:
    layers: list[FoundryConfig] = []
    layer_names: list[str] = []

    builtin = _load_layer(_builtin_defaults_path())
    if builtin is not None:
        layers.append(builtin)
        layer_names.append("builtin-defaults")

    user = _load_layer(_USER_CONFIG_PATH)
    if user is not None:
        layers.append(user)
        layer_names.append(str(_USER_CONFIG_PATH))

    repo_path = repo_root / "foundry.yaml"
    repo = _load_layer(repo_path)
    if repo is not None:
        layers.append(repo)
        layer_names.append(str(repo_path))

    if not layers:
        return FoundryConfig(version="1")

    config = _merge(layers)
    config._layer_names = layer_names  # type: ignore[attr-defined]
    return config


# ---------------------------------------------------------------------------
# Plan renderer
# ---------------------------------------------------------------------------


def render_plan_text(config: FoundryConfig) -> str:
    lines: list[str] = []
    layer_names = getattr(config, "_layer_names", ["(defaults)"])

    lines.append("Loaded layers:")
    for name in layer_names:
        lines.append(f"  {name}")
    lines.append("")

    # Gates
    lines.append("Gates (AND across layers):")
    lines.append(f"  allow_third_party_mcp: {'true' if config.allow_third_party_mcp else 'false'}")
    lines.append("")

    # Artifacts (Phase 1: always empty since no compilers yet)
    lines.append("Artifacts to apply:")
    n_patches = 0
    n_writes = 0
    n_env = 0
    n_secrets = 0
    n_steps = 0

    if config.git_safety:
        g = config.git_safety
        if g.protected_branches and g.protected_branches.add:
            n_patches += 1
        if g.file_restrictions and g.file_restrictions.blocked_patterns_add:
            n_patches += 1
        if g.allow_pr_operations is not None:
            n_patches += 1

    if config.user_services:
        n_env = len(config.user_services)
        n_secrets = len(config.user_services)

    lines.append(f"  policy_patches ({n_patches}):")
    if config.git_safety:
        g = config.git_safety
        if g.protected_branches and g.protected_branches.add:
            lines.append(f'    add protected_branches += {g.protected_branches.add}')
        if g.file_restrictions and g.file_restrictions.blocked_patterns_add:
            lines.append(f'    add blocked_patterns   += {g.file_restrictions.blocked_patterns_add}')
        if g.allow_pr_operations is not None:
            lines.append(f'    set allow_pr_operations  = {g.allow_pr_operations}')

    lines.append(f"  file_writes ({n_writes}):")
    lines.append(f"  env_vars ({n_env}):")
    if config.user_services:
        for svc in config.user_services:
            s = slug(svc.name)
            lines.append(f"    {svc.env_var}=http://host.docker.internal:8083/proxy/{s}")
    lines.append(f"  sbx_secrets ({n_secrets}):")
    if config.user_services:
        for svc in config.user_services:
            s = slug(svc.name)
            lines.append(f"    {s} (from host ${svc.env_var})")
    lines.append(f"  post_steps ({n_steps}):")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Compilers
# ---------------------------------------------------------------------------


def compile_git_safety(overlay: GitSafetyOverlay) -> ArtifactBundle:
    """Compile a git-safety overlay into an ArtifactBundle.

    Pure function: no side effects. Emits PolicyPatch entries for
    protected branches, blocked patterns, and allow_pr_operations.
    """
    patches: list[PolicyPatch] = []

    if overlay.protected_branches and overlay.protected_branches.add:
        patches.append(PolicyPatch(
            op="add",
            path="protected_branches",
            value=list(overlay.protected_branches.add),
        ))

    if overlay.file_restrictions and overlay.file_restrictions.blocked_patterns_add:
        patches.append(PolicyPatch(
            op="add",
            path="blocked_patterns",
            value=list(overlay.file_restrictions.blocked_patterns_add),
        ))

    if overlay.allow_pr_operations is not None:
        patches.append(PolicyPatch(
            op="add",
            path="allow_pr",
            value=overlay.allow_pr_operations,
        ))

    return ArtifactBundle(policy_patches=patches)


def compile_user_services(
    services: list[UserService],
    *,
    port: int = 8083,
    host: str = "host.docker.internal",
) -> ArtifactBundle:
    """Compile user-defined services into an ArtifactBundle.

    Produces env_vars pointing sandbox tools at the host-side proxy and
    sbx_secrets so the proxy can read the real credentials from the host.
    """
    if not services:
        return ArtifactBundle()

    env_vars: dict[str, str] = {}
    sbx_secrets: list[tuple[str, str]] = []

    for svc in services:
        s = slug(svc.name)
        proxy_url = f"http://{host}:{port}/proxy/{s}"
        env_vars[svc.env_var] = proxy_url
        # sbx_secret stores (slug, host_env_var) — the applier reads
        # the real value from os.environ[host_env_var] at apply time.
        sbx_secrets.append((s, svc.env_var))

    return ArtifactBundle(env_vars=env_vars, sbx_secrets=sbx_secrets)
