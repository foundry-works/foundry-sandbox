# foundry.yaml Plan

## Overview

Add a declarative `foundry.yaml` config so users can specify what goes into a sandbox — MCP servers, Claude Code settings, git-safety policy overlays, and user-defined service proxies — in a single file that is committed to the repo.

Three-layer resolver (built-in defaults → `~/.foundry/foundry.yaml` → repo `foundry.yaml`). Each section compiles to a typed `ArtifactBundle`; bundles merge into one; the applier is the only side-effecting code. `cast new --plan` prints the resolved config and artifact summary without provisioning.

## Motivation

The current extensibility surface is scattered across CLI flags (`--copy`, `--pip-requirements`, `--with-opencode`, `--with-zai`), a separate YAML (`config/user-services.yaml`), and the `--template` flag. There is no way to commit "what this repo's sandbox should contain" to the repo. A declarative config unifies that surface and makes setups reproducible across a team.

Foundry's unique leverage is the AI-agent territory: MCP servers, Claude Code skills/hooks/permissions, and git-safety overlays. The plan focuses primitives there and deliberately skips generic package managers (devcontainer features already handle that).

## Design invariants

1. **Additive-only policy.** Overlays can only tighten, never loosen. This is enforced structurally — the schema has `*_add` fields and no `remove` / `replace` fields.
2. **Monotonic safety gates.** All `allow_*` flags are ANDed across layers. A user layer can forbid something; a repo layer can't override that forbid.
3. **Compile is pure.** Each primitive is a pure function `Config → ArtifactBundle`. `--plan` reuses the compile step and skips the applier.
4. **Credentials never raw.** The only supported secret reference is `${from_host:VAR}`, which resolves to a proxy URL via the existing user-services machinery. No primitive for raw-key injection.
5. **`extra="forbid"` everywhere.** Typos in `foundry.yaml` fail loud.

## Schema

Single module: `foundry_sandbox/foundry_config.py`.

```python
from typing import Annotated, Literal, Union
from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---- git-safety overlay ----------------------------------------------------

class ProtectedBranchesAdd(_Strict):
    add: list[str] = Field(default_factory=list)

class FileRestrictionsAdd(_Strict):
    blocked_patterns_add: list[str] = Field(default_factory=list)

class GitSafetyOverlay(_Strict):
    protected_branches: ProtectedBranchesAdd | None = None
    file_restrictions: FileRestrictionsAdd | None = None
    allow_pr_operations: bool | None = None   # None inherits; True enables; False force-off


# ---- MCP servers (discriminated union) -------------------------------------

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


# ---- Claude Code -----------------------------------------------------------

class SkillSource(_Strict):
    source: str | None = None   # host path
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


# ---- user-defined services (absorbs config/user-services.yaml) -------------

class UserService(_Strict):
    name: str
    env_var: str
    domain: str
    header: str = "Authorization"
    format: Literal["bearer", "header", "query"] = "bearer"


# ---- top level -------------------------------------------------------------

class FoundryConfig(_Strict):
    version: Literal["1"]
    git_safety: GitSafetyOverlay | None = None
    mcp_servers: list[McpServer] = Field(default_factory=list)
    claude_code: ClaudeCodeConfig | None = None
    user_services: list[UserService] = Field(default_factory=list)
    allow_third_party_mcp: bool = False

    @model_validator(mode="after")
    def _gate_third_party_mcp(self) -> "FoundryConfig":
        if not self.allow_third_party_mcp:
            bad = [s.name for s in self.mcp_servers if s.type == "npm"]
            if bad:
                raise ValueError(
                    f"MCP servers {bad} are type=npm but allow_third_party_mcp is off"
                )
        return self
```

## Resolver

```python
def resolve_foundry_config(repo_root: Path) -> FoundryConfig:
    layers: list[FoundryConfig] = []
    for path in (
        _builtin_defaults_path(),                    # bundled with foundry
        Path.home() / ".foundry" / "foundry.yaml",   # user defaults
        repo_root / "foundry.yaml",                  # repo config
    ):
        if path.exists():
            layers.append(FoundryConfig(**yaml.safe_load(path.read_text())))
    if not layers:
        return FoundryConfig(version="1")
    return _merge(layers)
```

Merge semantics:

- **Version:** must agree across layers; mismatch raises.
- **Lists** (`mcp_servers`, `user_services`): concatenate.
- **`*_add` lists** (`protected_branches.add`, `blocked_patterns_add`): union.
- **`allow_*` flags:** ANDed — any `False` in any layer wins. The repo layer cannot weaken a user-layer forbid.
- **`allow_pr_operations: False` in any layer** force-offs the setting.
- **ClaudeCodeConfig hooks:** dict-of-lists; concatenate per-key.

The monotonic-downward rule is the safety invariant. Any new flag added to `FoundryConfig` must have a documented merge rule that preserves it, exercised by a property test.

## Applier

Each primitive compiles to an `ArtifactBundle`. Bundles are merged into one; the applier is the only code with side effects.

```python
@dataclass(frozen=True)
class FileWrite:
    container_path: str
    content: bytes
    mode: int = 0o644
    owner: str = "agent"

@dataclass(frozen=True)
class PolicyPatch:
    op: Literal["add"]                     # only "add" — enforces additive-only at runtime
    path: str                              # e.g. "protected_branches"
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
```

Compilers:

```python
def compile_git_safety(overlay: GitSafetyOverlay) -> ArtifactBundle: ...
def compile_mcp_servers(servers: list[McpServer]) -> ArtifactBundle: ...
def compile_claude_code(cfg: ClaudeCodeConfig) -> ArtifactBundle: ...
def compile_user_services(services: list[UserService]) -> ArtifactBundle: ...
def _compile_cli_flags(*, copies, pip_requirements) -> ArtifactBundle: ...
```

Apply order (fixed):

1. `sbx secrets` — before anything that reads them.
2. Policy patches — merged into the sandbox's git-safety registration file at `~/.foundry/data/git-safety/sandboxes/<name>.json` before the server picks it up.
3. File writes — via the existing base64-through-`sbx exec` pattern in `git_safety.py`.
4. Env vars — merged into the existing `/etc/profile.d/foundry-git-safety.sh` + `/etc/bash.bashrc` + `/var/lib/foundry/git-safety.env` triple via the helpers in `git_safety.py`.
5. Post steps — last; runtime has everything it needs.

## Integration with new_setup.py

Replace the ad-hoc copies/pip/user-services injection (`foundry_sandbox/commands/new_setup.py:215-270`) with a single artifact-apply call, after `provision_git_safety` and before the metadata patch:

```python
config = resolve_foundry_config(Path(repo_root))
bundles = [
    compile_git_safety(config.git_safety) if config.git_safety else ArtifactBundle(),
    compile_mcp_servers(config.mcp_servers),
    compile_claude_code(config.claude_code) if config.claude_code else ArtifactBundle(),
    compile_user_services(config.user_services),
    _compile_cli_flags(copies=copies, pip_requirements=pip_requirements),
]
apply_artifacts(name, _merge_bundles(bundles), sandbox_id=name)
```

The existing `config/user-services.yaml` loader stays as a fallback for one release — dual-read, `foundry.yaml` wins on conflict.

## `cast new --plan`

Same pipeline, render-only terminator:

```
Loaded layers:
  builtin-defaults
  ~/.foundry/foundry.yaml
  /path/to/repo/foundry.yaml

Gates (AND across layers):
  allow_third_party_mcp: false

Artifacts to apply:
  policy_patches (2):
    add protected_branches += ["refs/heads/staging"]
    add blocked_patterns   += ["db/migrations/"]
  file_writes (3):
    /workspace/.mcp.json                            (644, agent)
    /workspace/.claude/settings.json                (644, agent)
    /workspace/.claude/skills/security-review/*     (644, agent)
  env_vars (1):
    TAVILY_API_KEY=http://host.docker.internal:8083/proxy/tavily
  sbx_secrets (1):
    tavily (from host $TAVILY_API_KEY)
  post_steps (0):
```

Build `--plan` before the real applier — it exercises schema + resolver + compile in isolation and is the debugging tool you'll want every time a feature emits unexpected artifacts.

## Ship order

1. Schema + resolver + `--plan`. No real apply.
2. `compile_git_safety` + real apply for policy patches only.
3. `compile_user_services` — migrate existing mechanism into the new pipeline.
4. `compile_mcp_servers` with `builtin` + `proxy` types only.
5. `compile_claude_code` — file synthesis.
6. `type: npm` MCP behind `allow_third_party_mcp`.

## Out of scope (v1)

- Feature dependency graph. If MCP-npm needs node, document it; don't build a scheduler.
- Feature registry / marketplace. The `type: builtin` list is a Python dict in foundry; changes ship with foundry releases.
- Per-feature semver. The `foundry.yaml` schema version is enough until real pain.
- Removing / replacing policy entries via overlay. Additive-only is non-negotiable.
- Template integration. `cast preset save` snapshotting `foundry.yaml` alongside the sbx template is a follow-up.

## Files touched

New:

- `foundry_sandbox/foundry_config.py` — schema, resolver, compilers
- `foundry_sandbox/artifacts.py` — `ArtifactBundle`, `apply_artifacts`, helpers
- `foundry_sandbox/default_config/foundry.yaml` — built-in defaults
- `tests/unit/test_foundry_config.py` — schema + resolver + compile tests
- `tests/unit/test_artifacts.py` — applier (mocked sbx_exec)

Modified:

- `foundry_sandbox/commands/new.py` — add `--plan` flag
- `foundry_sandbox/commands/new_setup.py` — replace ad-hoc injection with `apply_artifacts`
- `foundry_sandbox/user_services.py` — dual-read, deprecate after one release
- `docs/configuration.md` — document `foundry.yaml`
- `docs/usage/commands.md` — document `--plan`
- `README.md` — short pointer to the new config
