"""Declarative foundry.yaml config: schema, three-layer resolver, plan renderer, compilers.

Layers resolve in order: built-in defaults -> ~/.foundry/foundry.yaml -> repo foundry.yaml.
Merge is additive-only: lists concatenate, allow flags AND across layers, overlays can only
tighten policy. The repo layer cannot weaken a user-layer forbid.

Compilers turn resolved config sections into ArtifactBundles (pure functions).
"""

from __future__ import annotations

import importlib.resources
import logging
import os
import re
from pathlib import Path
from typing import Annotated, Any, Literal, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from foundry_sandbox.artifacts import ArtifactBundle, PolicyPatch, PostStep

logger = logging.getLogger(__name__)
_ENV_VAR_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def slug(name: str) -> str:
    """Convert a service or env-var name to a proxy-safe slug."""
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "unknown"


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
    methods: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    scheme: str = "https"
    port: int = 0

    @field_validator("env_var")
    @classmethod
    def _validate_env_var(cls, value: str) -> str:
        if not _ENV_VAR_RE.match(value):
            raise ValueError(
                f"env_var must match [A-Z_][A-Z0-9_]*, got {value!r}"
            )
        return value

    @field_validator("format", mode="before")
    @classmethod
    def _normalize_format(cls, value: str) -> str:
        if value == "value":
            return "header"
        return value

    @field_validator("port")
    @classmethod
    def _validate_port(cls, value: int) -> int:
        if value < 0 or value > 65535:
            raise ValueError(f"Port must be 0-65535, got {value}")
        return value


# ---------------------------------------------------------------------------
# IDE config (user-only)
# ---------------------------------------------------------------------------


class IdeConfig(_Strict):
    preferred: str = ""
    args: list[str] = Field(default_factory=list)
    auto_open_on_attach: bool = False
    auto_git_mode_host: bool = False


# ---------------------------------------------------------------------------
# package bootstrap
# ---------------------------------------------------------------------------


class PackageBootstrap(_Strict):
    pip: str | list[str] | None = None
    uv: str | list[str] | None = None
    apt: list[str] = Field(default_factory=list)
    npm: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# dev profiles
# ---------------------------------------------------------------------------


class DevProfile(_Strict):
    agent: str | None = None
    wd: str | None = None
    ide: str | None = None
    pip_requirements: str | None = None
    packages: PackageBootstrap | None = None
    template: str | None = None


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
    allow_system_packages: bool = False
    ide: IdeConfig | None = None
    profiles: dict[str, DevProfile] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _gate_third_party_mcp(self) -> FoundryConfig:
        if not self.allow_third_party_mcp:
            bad = [s.name for s in self.mcp_servers if s.type == "npm"]
            if bad:
                raise ValueError(
                    f"MCP servers {bad} are type=npm but allow_third_party_mcp is off"
                )
        return self

    @model_validator(mode="after")
    def _gate_system_packages(self) -> FoundryConfig:
        if not self.allow_system_packages:
            for name, profile in self.profiles.items():
                if profile.packages and (
                    profile.packages.apt or profile.packages.npm
                ):
                    parts = []
                    if profile.packages.apt:
                        parts.append(f"apt: {profile.packages.apt}")
                    if profile.packages.npm:
                        parts.append(f"npm: {profile.packages.npm}")
                    raise ValueError(
                        f"Profile '{name}' has system packages ({', '.join(parts)}) "
                        f"but allow_system_packages is off"
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

    # allow_system_packages: AND across layers
    result.allow_system_packages = all(layer.allow_system_packages for layer in layers)

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

    # IDE: last non-None wins (user-only; repo layers are stripped before merge)
    for layer in layers:
        if layer.ide is not None:
            result.ide = layer.ide

    # Profiles: collect all, later layer wins for same name (user wins over repo)
    merged_profiles: dict[str, DevProfile] = {}
    for layer in layers:
        merged_profiles.update(layer.profiles)
    result.profiles = merged_profiles

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
        # ide is user-only — strip from repo config
        if repo.ide is not None:
            logger.warning(
                "Repo foundry.yaml contains 'ide' section — "
                "IDE config is user-only and will be ignored"
            )
            repo = repo.model_copy(update={"ide": None})

        # Strip ide from repo profiles (IDE is user-only)
        if repo.profiles:
            stripped: dict[str, DevProfile] = {}
            for pname, prof in repo.profiles.items():
                if prof.ide is not None:
                    logger.warning(
                        f"Repo foundry.yaml profile '{pname}' contains 'ide' — "
                        "IDE config is user-only and will be ignored"
                    )
                    stripped[pname] = prof.model_copy(update={"ide": None})
                else:
                    stripped[pname] = prof
            repo = repo.model_copy(update={"profiles": stripped})

        layers.append(repo)
        layer_names.append(str(repo_path))

    if not layers:
        return FoundryConfig(version="1")

    config = _merge(layers)
    config._layer_names = layer_names  # type: ignore[attr-defined]
    return config


def load_user_ide_config() -> IdeConfig | None:
    """Load the IDE config from ~/.foundry/foundry.yaml (user-only).

    Returns None if the file does not exist or has no ``ide`` section.
    """
    layer = _load_layer(_USER_CONFIG_PATH)
    if layer is None:
        return None
    return layer.ide


def resolve_profile(config: FoundryConfig, profile_name: str) -> DevProfile:
    """Resolve a named dev profile from merged config.

    Returns the DevProfile if found, or an empty DevProfile() if
    profile_name is "default" and no profiles.default exists.
    Raises ValueError for unknown profile names.
    """
    if profile_name in config.profiles:
        return config.profiles[profile_name]

    if profile_name == "default":
        return DevProfile()

    available = sorted(config.profiles.keys())
    if available:
        raise ValueError(
            f"Unknown profile '{profile_name}'. "
            f"Available profiles: {', '.join(available)}"
        )
    raise ValueError(
        f"Unknown profile '{profile_name}'. "
        f"No profiles are defined in any foundry.yaml config."
    )


def normalize_profile_packages(profile: DevProfile) -> dict[str, object]:
    """Build a packages dict from a profile, bridging legacy pip_requirements."""
    packages: dict[str, object] = {}
    if profile.packages:
        if profile.packages.pip is not None:
            packages["pip"] = profile.packages.pip
        if profile.packages.uv is not None:
            packages["uv"] = profile.packages.uv
        if profile.packages.apt:
            packages["apt"] = profile.packages.apt
        if profile.packages.npm:
            packages["npm"] = profile.packages.npm
    if "pip" not in packages and profile.pip_requirements:
        packages["pip"] = profile.pip_requirements
    return packages


# ---------------------------------------------------------------------------
# Plan renderer
# ---------------------------------------------------------------------------


def render_plan_text(config: FoundryConfig, *, profile_name: str | None = None) -> str:
    lines: list[str] = []
    layer_names = getattr(config, "_layer_names", ["(defaults)"])

    lines.append("Loaded layers:")
    for name in layer_names:
        lines.append(f"  {name}")
    lines.append("")

    # Gates
    lines.append("Gates (AND across layers):")
    lines.append(f"  allow_third_party_mcp: {'true' if config.allow_third_party_mcp else 'false'}")
    lines.append(f"  allow_system_packages: {'true' if config.allow_system_packages else 'false'}")
    lines.append("")

    # Profiles
    if profile_name is not None:
        resolved = resolve_profile(config, profile_name)
        lines.append(f"Profile: {profile_name}")
        has_any = False
        for field_name in ("agent", "wd", "ide", "pip_requirements", "template"):
            value = getattr(resolved, field_name)
            if value is not None:
                lines.append(f"  {field_name}: {value}")
                has_any = True
        if resolved.packages:
            pkgs = normalize_profile_packages(resolved)
            if pkgs:
                lines.append("  packages:")
                for pkg_type, pkg_val in pkgs.items():
                    lines.append(f"    {pkg_type}: {pkg_val}")
                has_any = True
        if not has_any:
            lines.append("  (empty — all defaults from CLI)")
        lines.append("")
    elif config.profiles:
        lines.append(f"Profiles defined ({len(config.profiles)}):")
        for name, prof in sorted(config.profiles.items()):
            fields = []
            for field_name in ("agent", "wd", "ide", "pip_requirements", "template"):
                value = getattr(prof, field_name)
                if value is not None:
                    fields.append(f"{field_name}={value}")
            if prof.packages:
                pkgs = normalize_profile_packages(prof)
                if pkgs:
                    fields.append(f"packages={pkgs}")
            lines.append(f"  {name}: {', '.join(fields) if fields else '(empty)'}")
        lines.append("")

    # Artifacts
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
        n_env += len(config.user_services)
        n_secrets += len(config.user_services)

    # MCP server artifacts (compile to get counts/details)
    mcp_bundle: ArtifactBundle | None = None
    if config.mcp_servers:
        mcp_bundle = compile_mcp_servers(config.mcp_servers)
        n_writes += len(mcp_bundle.file_writes)
        n_env += len(mcp_bundle.env_vars)
        n_secrets += len(mcp_bundle.sbx_secrets)
        n_steps += len(mcp_bundle.post_steps)

    # Claude Code artifacts
    cc_bundle: ArtifactBundle | None = None
    if config.claude_code:
        cc_bundle = compile_claude_code(config.claude_code)
        n_writes += len(cc_bundle.file_writes)
        n_steps += len(cc_bundle.post_steps)

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
    if mcp_bundle:
        for fw in mcp_bundle.file_writes:
            lines.append(f"    {fw.container_path} ({len(fw.content)} bytes, {fw.owner})")
    if cc_bundle:
        for fw in cc_bundle.file_writes:
            lines.append(f"    {fw.container_path} ({len(fw.content)} bytes, {fw.owner})")
    lines.append(f"  env_vars ({n_env}):")
    if config.user_services:
        for svc in config.user_services:
            s = slug(svc.name)
            lines.append(f"    {svc.env_var}=http://host.docker.internal:8083/proxy/{s}")
    if mcp_bundle:
        for k, v in sorted(mcp_bundle.env_vars.items()):
            lines.append(f"    {k}={v}")
    lines.append(f"  sbx_secrets ({n_secrets}):")
    if config.user_services:
        for svc in config.user_services:
            s = slug(svc.name)
            lines.append(f"    {s} (from host ${svc.env_var})")
    if mcp_bundle:
        for slug_name, env_var in mcp_bundle.sbx_secrets:
            lines.append(f"    {slug_name} (from host ${env_var})")
    lines.append(f"  post_steps ({n_steps}):")
    if mcp_bundle:
        for step in mcp_bundle.post_steps:
            lines.append(f"    {' '.join(step.cmd)}")
    if cc_bundle:
        for step in cc_bundle.post_steps:
            lines.append(f"    {' '.join(step.cmd)}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Host-variable substitution
# ---------------------------------------------------------------------------


_FROM_HOST_RE = re.compile(r"\$\{from_host:([A-Za-z_][A-Za-z0-9_]*)\}")


def collect_secret_refs(config: FoundryConfig) -> list[tuple[str, str]]:
    """Return deduplicated sbx secret refs implied by a resolved config."""
    refs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(slug_name: str, env_var: str) -> None:
        item = (slug_name, env_var)
        if item not in seen:
            refs.append(item)
            seen.add(item)

    for svc in config.user_services:
        add(slug(svc.name), svc.env_var)

    for server in config.mcp_servers:
        if server.type == "proxy":
            add(slug(server.name), server.host_env)
            continue

        for value in server.env.values():
            for match in _FROM_HOST_RE.finditer(value):
                env_var = match.group(1)
                add(slug(env_var), env_var)

    return refs


def _resolve_host_refs(value: str) -> tuple[str, bool]:
    """Resolve ${from_host:VAR} references in a string.

    Returns (resolved_value, is_proxy_ref).  When a reference is found the
    value becomes a proxy URL and the caller should emit an sbx_secret.
    Raises ValueError if the host env var is not set.
    """
    match = _FROM_HOST_RE.search(value)
    if not match:
        return value, False

    env_var = match.group(1)
    if not os.environ.get(env_var):
        raise ValueError(
            f"MCP server env references ${{from_host:{env_var}}} "
            f"but {env_var} is not set in the host environment"
        )

    s = slug(env_var)
    proxy_url = f"http://host.docker.internal:8083/proxy/{s}"
    return proxy_url, True


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


def compile_mcp_servers(
    servers: list[McpServer],
    *,
    port: int = 8083,
    host: str = "host.docker.internal",
) -> ArtifactBundle:
    """Compile MCP server declarations into an ArtifactBundle.

    Produces a FileWrite for /workspace/.mcp.json, plus env_vars and
    sbx_secrets for proxy-type servers and from_host references.

    Raises ValueError for unknown builtin names.
    Requires allow_third_party_mcp=True for npm servers (enforced by schema gate).
    """
    if not servers:
        return ArtifactBundle()

    from foundry_sandbox.mcp_builtins import get_builtin, list_builtins

    mcp_servers_json: dict[str, dict[str, Any]] = {}
    env_vars: dict[str, str] = {}
    sbx_secrets: list[tuple[str, str]] = []
    post_steps: list[PostStep] = []

    for server in servers:
        s = slug(server.name)

        if server.type == "builtin":
            spec = get_builtin(server.name)
            if spec is None:
                raise ValueError(
                    f"Unknown builtin MCP server: {server.name!r}. "
                    f"Available: {', '.join(list_builtins())}"
                )
            # Resolve from_host refs in user-supplied env overrides
            resolved_env: dict[str, str] = {}
            for k, v in server.env.items():
                resolved, is_proxy = _resolve_host_refs(v)
                resolved_env[k] = resolved
                if is_proxy:
                    match = _FROM_HOST_RE.search(v)
                    env_var_name = match.group(1)  # type: ignore[union-attr]
                    secret_slug = slug(env_var_name)
                    sbx_secrets.append((secret_slug, env_var_name))
            if resolved_env:
                spec["env"] = resolved_env
            mcp_servers_json[server.name] = spec

        elif server.type == "proxy":
            proxy_url = f"http://{host}:{port}/proxy/{s}"
            mcp_servers_json[server.name] = {
                "url": proxy_url,
            }
            env_vars[f"MCP_PROXY_{s.upper().replace('-', '_')}"] = proxy_url
            sbx_secrets.append((s, server.host_env))

        elif server.type == "npm":
            post_steps.append(PostStep(
                cmd=["npm", "install", "-g", server.package],
                user="root",
            ))
            resolved_env = {}
            for k, v in server.env.items():
                resolved, is_proxy = _resolve_host_refs(v)
                resolved_env[k] = resolved
                if is_proxy:
                    match = _FROM_HOST_RE.search(v)
                    env_var_name = match.group(1)  # type: ignore[union-attr]
                    sbx_secrets.append((slug(env_var_name), env_var_name))
            entry: dict[str, Any] = {
                "command": "npx",
                "args": [server.package],
            }
            if resolved_env:
                entry["env"] = resolved_env
            mcp_servers_json[server.name] = entry

    if not mcp_servers_json:
        return ArtifactBundle(
            env_vars=env_vars,
            sbx_secrets=sbx_secrets,
            post_steps=post_steps,
        )

    import json

    mcp_json_content = json.dumps(
        {"mcpServers": mcp_servers_json},
        indent=2,
    )

    from foundry_sandbox.artifacts import FileWrite

    return ArtifactBundle(
        file_writes=[
            FileWrite(
                container_path="/workspace/.mcp.json",
                content=mcp_json_content.encode(),
                mode=0o644,
                owner="agent",
            )
        ],
        env_vars=env_vars,
        sbx_secrets=sbx_secrets,
        post_steps=post_steps,
    )


def _skill_name_from_source(source: str) -> str:
    return Path(source).name


def _skill_name_from_git(url: str) -> str:
    name = url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name


def compile_claude_code(cfg: ClaudeCodeConfig) -> ArtifactBundle:
    """Compile a ClaudeCodeConfig into an ArtifactBundle.

    Produces:
    - FileWrite for /workspace/.claude/settings.json (hooks + permissions)
    - FileWrites for skills from host source paths
    - PostSteps for skills from git URLs
    - FileWrites for commands from host file paths
    """
    import json

    from foundry_sandbox.artifacts import FileWrite, PostStep

    file_writes: list[FileWrite] = []
    post_steps: list[PostStep] = []

    # -- Skills --
    for skill in cfg.skills:
        if skill.source:
            host_path = Path(skill.source)
            if not host_path.exists():
                raise ValueError(f"Skill source path does not exist: {skill.source}")
            skill_name = _skill_name_from_source(skill.source)
            if host_path.is_dir():
                for child in sorted(host_path.rglob("*")):
                    if child.is_file():
                        rel = child.relative_to(host_path)
                        file_writes.append(FileWrite(
                            container_path=f"/workspace/.claude/skills/{skill_name}/{rel}",
                            content=child.read_bytes(),
                        ))
            else:
                file_writes.append(FileWrite(
                    container_path=f"/workspace/.claude/skills/{skill_name}/{host_path.name}",
                    content=host_path.read_bytes(),
                ))
        elif skill.git:
            skill_name = _skill_name_from_git(skill.git)
            target = f"/workspace/.claude/skills/{skill_name}"
            post_steps.append(PostStep(
                cmd=["git", "clone", "--depth", "1", skill.git, target],
            ))
            if skill.path:
                post_steps.append(PostStep(
                    cmd=["sh", "-c",
                         f"mv '{target}/{skill.path}/*' '{target}/' 2>/dev/null; "
                         f"rm -rf '{target}/{skill.path}'"],
                ))

    # -- Commands --
    for cmd_path in cfg.commands:
        host_file = Path(cmd_path)
        if not host_file.exists():
            raise ValueError(f"Command source file does not exist: {cmd_path}")
        file_writes.append(FileWrite(
            container_path=f"/workspace/.claude/commands/{host_file.name}",
            content=host_file.read_bytes(),
        ))

    # -- Hooks + Permissions → settings.json --
    settings: dict[str, Any] = {}
    if cfg.hooks:
        hooks_json: dict[str, list[dict[str, Any]]] = {}
        for event, rules in cfg.hooks.items():
            hooks_json[event] = [
                {
                    "matcher": rule.match,
                    "hooks": [{"type": "command", "command": rule.command}],
                }
                for rule in rules
            ]
        settings["hooks"] = hooks_json
    if cfg.permissions and (cfg.permissions.allow or cfg.permissions.deny):
        perm_json: dict[str, list[str]] = {}
        if cfg.permissions.allow:
            perm_json["allow"] = list(cfg.permissions.allow)
        if cfg.permissions.deny:
            perm_json["deny"] = list(cfg.permissions.deny)
        settings["permissions"] = perm_json

    if settings:
        file_writes.append(FileWrite(
            container_path="/workspace/.claude/settings.json",
            content=json.dumps(settings, indent=2).encode(),
        ))

    return ArtifactBundle(file_writes=file_writes, post_steps=post_steps)
