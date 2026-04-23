# Local Dev Ergonomics Plan

## Summary

Foundry already has most of the low-level primitives needed for a strong local
developer workflow:

- `cast new` creates a sandbox, worktree, and git-safety wiring.
- `cast preset save` snapshots a running sandbox into an `sbx` template.
- `foundry.yaml` can inject Claude Code config, MCP servers, proxy-backed env
  vars, and git-safety overlays.
- `cast up` already handles the "start, open IDE, attach" part for an existing
  sandbox.

What is missing is a first-class, reproducible "developer environment" concept.
Today the workflow is spread across CLI flags, templates, presets, and
`foundry.yaml`. That makes common setup for "new sandbox on a worktree, with
Claude agent, plus packages, skills, and plugins pre-installed" feel pieced
together instead of intentional.

This plan proposes a new top-level abstraction: a declarative local-dev
profile, plus a higher-level command that uses it.

## Problem Statement

The current workflow is correct but low-level:

1. Create a sandbox with `cast new`.
2. Optionally save or reuse a preset.
3. Optionally snapshot a template.
4. Optionally express Claude/MCP config in `foundry.yaml`.
5. Attach or use `cast up`.

That creates a few ergonomic gaps:

- There is no single command for "open my normal dev environment here."
- Package bootstrap is narrow. Today it is mostly `--pip-requirements` plus MCP
  npm post-steps.
- Presets are useful, but they are partly mutable snapshots rather than a
  stable declarative setup.
- Claude skills, commands, MCP servers, IDE preferences, and agent choice are
  not bundled as one named setup.
- Reuse behavior is not expressed as a user intent such as "reuse my sandbox
  for this repo/profile unless I say fresh."

## Design Goals

- Make the common local-dev flow one command.
- Keep worktree-based isolation as the default.
- Support pre-installed agent tooling, packages, skills, and plugins.
- Preserve current security boundaries around credentials, git safety, and
  network policy.
- Prefer declarative, repeatable setup over imperative one-off shell steps.
- Reuse existing code paths where possible instead of inventing a parallel
  lifecycle.

## Non-Goals

- Replacing `cast new`, `cast attach`, `cast up`, or presets entirely.
- Weakening git-safety or sandbox credential protections.
- Turning templates into the source of truth for secrets or policy.
- Supporting arbitrary unrestricted bootstrap code by default.

## Current Seams To Build On

- `foundry_sandbox/commands/new.py`
  Current sandbox creation entrypoint with repo, branch, agent, template, IDE,
  and pip flags.
- `foundry_sandbox/commands/new_setup.py`
  Current provisioning flow for `sbx create`, git safety, compiled artifacts,
  copies, and pip install.
- `foundry_sandbox/commands/preset.py`
  Snapshotting a running sandbox into a managed template.
- `foundry_sandbox/commands/up.py`
  Existing "start, open IDE, attach" flow for sandboxes that already exist.
- `foundry_sandbox/foundry_config.py`
  Current schema and artifact compilers for Claude Code, MCP, user services,
  and git-safety overlays.
- `foundry_sandbox/sbx.py`
  Existing hooks for `sbx create`, `sbx exec`, templates, and pip install.

## Proposal

### 1. Add A First-Class `cast dev` Command

Add a developer-oriented command that expresses the user intent directly:

```bash
cast dev . --profile claude-python --branch feat/auth
```

Expected behavior:

- resolve repo from `.` by default
- select a named profile
- create a sandbox if none exists for that repo/profile/branch
- otherwise reuse the existing sandbox
- optionally open the IDE
- attach immediately

This should be the ergonomic wrapper around existing primitives, not a parallel
implementation. Internally it should lean on:

- `cast new` behavior for creation
- `cast up` behavior for start/open/attach
- existing metadata/state helpers for reuse

### 2. Introduce Declarative Local-Dev Profiles

Add a new config concept for reusable, named setups. Profiles should be
declarative and portable, unlike mutable snapshots.

Example shape:

```yaml
profiles:
  claude-python:
    agent: claude
    wd: packages/api
    ide: cursor
    packages:
      pip: requirements-dev.txt
      apt: [jq, ripgrep]
      npm: [typescript]
    tooling:
      claude_skills: [team-review]
      claude_commands: [review, explain]
      mcp: [github]
```

The exact schema can differ, but the user-facing intent should be:

- choose an agent
- choose a working directory
- choose package bootstrap
- choose skills/commands/plugins/tooling bundles
- optionally choose IDE defaults

Profiles should be usable from user config and optionally repo config, with
merge rules that remain compatible with the current additive/tightening model.

### 3. Separate Declarative Profiles From Snapshot Presets

Presets should remain, but their role should become clearer:

- profiles: declarative, reviewed, repeatable setup
- presets: user snapshots of runtime state

This lets a developer do both:

- use a stable profile for everyday work
- snapshot a warmed environment into a preset/template when needed

That avoids overloading presets as the main ergonomics surface.

### 4. Add A Typed Bootstrap Model For Packages

Right now package installation is fragmented:

- Python packages via `--pip-requirements`
- some npm packages via MCP `type: npm` post-steps

That is not enough for a smooth local-dev bootstrap. Add a typed package model,
for example:

- `packages.pip`
- `packages.uv`
- `packages.npm`
- `packages.apt`

If an escape hatch is needed, add a clearly gated `bootstrap.commands` or
`post_steps`, but keep it explicit and opt-in.

### 5. Add Tooling Bundles For Skills, Commands, MCP, And Plugins

Foundry already knows how to compile:

- Claude skills and commands into `/workspace/.claude/...`
- MCP servers into `/workspace/.mcp.json`

Expose that through named bundles so developers do not need to hand-author
low-level config every time. This also gives a place to represent the user's
"plugins pre-installed" requirement without inventing several separate flags.

Possible examples:

- `tooling: [github, team-review, python-debug]`
- bundles expand into Claude skills, Claude commands, MCP servers, and package
  dependencies

### 6. Cache Profile Setups As Managed Templates

The first time a profile is used, Foundry can build a managed template for it.
Later sandboxes can reuse that template for a much faster startup.

Important constraint: the template must not become the source of truth for
security-sensitive runtime state.

Safe to bake:

- packages
- editor tooling
- Claude skills/commands copied into the sandbox
- non-secret runtime dependencies

Must remain late-bound at sandbox creation/start:

- git-safety registration
- HMAC secrets
- proxy-backed secret injection
- branch-specific policy overlays
- credentials derived from host env

### 7. Make Reuse Behavior Explicit

For daily local development, auto-numbering sandboxes is useful but not the
best default UX. A developer usually wants one of two intents:

- reuse my normal sandbox for this repo/profile
- give me a fresh sandbox

Add explicit reuse controls such as:

- default reuse by repo + profile + branch
- `--fresh` to force a new sandbox
- `--name` to take full manual control

## Security Constraints

This work should preserve the current threat model:

- Sandboxes remain the boundary, not templates.
- Real credentials stay on the host and continue to resolve through proxy-backed
  injection.
- Git safety continues to be provisioned per sandbox and verified after start.
- Third-party package/plugin installation should follow a user-controlled gate
  comparable to `allow_third_party_mcp`.

In practical terms:

- do not bake raw secrets into templates
- do not treat generated `.mcp.json` or `.claude/settings.json` as user-edited
  control surfaces
- do not let repo config silently loosen user-level restrictions

## Suggested Rollout

### Phase 1: CLI Ergonomics

Ship `cast dev` as an orchestration layer over existing commands.

Scope:

- repo resolution
- profile selection flag
- create-or-reuse decision
- IDE open + attach
- `--fresh`

This delivers the biggest UX win quickly and with low risk.

### Phase 2: Declarative Profiles

Add a profile schema and config resolution rules.

Scope:

- profile models
- state persistence in metadata
- plan output support
- docs for authoring and selecting profiles

### Phase 3: Package Bootstrap Expansion

Add a typed bootstrap model beyond pip requirements.

Scope:

- new package config schema
- bootstrap executor/compiler
- gating for higher-risk install types
- metadata and plan rendering

### Phase 4: Tooling Bundles

Introduce named bundles for Claude skills, commands, MCP, and plugin-like
tooling.

Scope:

- bundle schema
- expansion logic
- conflict handling
- docs and examples

### Phase 5: Managed Template Caching

Add profile-backed template build/reuse.

Scope:

- cache key derivation
- invalidation when profile inputs change
- metadata for template provenance
- commands to inspect/rebuild cached templates

## Open Questions

- Should profiles live only in `~/.foundry/foundry.yaml`, or can repos publish
  safe defaults that users opt into?
- Should package bootstrap compile into artifact post-steps, or be handled by a
  dedicated bootstrap subsystem?
- How much template caching should happen automatically versus explicitly?
- Should "plugin" be modeled as MCP only, or as a broader tooling concept that
  can include Claude assets and packages?
- What is the canonical identity for reuse: repo + profile, or repo + profile +
  branch?

## Success Criteria

- A developer can spin up a normal local-dev sandbox with one command.
- Common agent/tooling/package setup is declarative and reproducible.
- Repeated sandbox creation is materially faster through cached templates.
- Existing security guarantees remain intact.
- The docs describe one obvious default workflow instead of several loosely
  connected primitives.
