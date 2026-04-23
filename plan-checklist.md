# foundry.yaml Implementation Checklist

Execute phases in order. Each phase is independently shippable. See `plan.md` for architectural context.

---

## Phase 1 — Schema + resolver + `--plan` (no real apply)

Goal: exercise the whole data model end-to-end without side effects. Shippable on its own as a dry-run tool.

### Schema

- [ ] Create `foundry_sandbox/foundry_config.py` with all Pydantic models from `plan.md`
- [ ] Use `ConfigDict(extra="forbid")` on every model via the `_Strict` base
- [ ] Add `@model_validator` for `allow_third_party_mcp` gate on `FoundryConfig`
- [ ] Create `foundry_sandbox/default_config/foundry.yaml` with a minimal built-in default (`version: "1"`, no overrides)
- [ ] Wire the default file into the package via `hatch.build.targets.wheel.artifacts` in `pyproject.toml`

### Resolver

- [ ] Implement `resolve_foundry_config(repo_root: Path) -> FoundryConfig` in `foundry_config.py`
- [ ] Implement `_merge(layers)` with documented semantics: lists concat, `*_add` union, `allow_*` ANDed
- [ ] Raise on version mismatch across layers
- [ ] Handle missing user/repo files gracefully — return built-in defaults

### `--plan` flag

- [ ] Add `--plan` to `cast new` in `foundry_sandbox/commands/new.py`
- [ ] When `--plan` is set, skip all sbx calls after repo resolution
- [ ] Implement `_render_plan_text(config, merged_bundle)` — format from `plan.md`
- [ ] `--plan` exits 0 on success, 1 on schema/resolver errors

### Tests

- [ ] `tests/unit/test_foundry_config.py::test_strict_mode_rejects_unknown_keys`
- [ ] `tests/unit/test_foundry_config.py::test_version_mismatch_raises`
- [ ] `tests/unit/test_foundry_config.py::test_merge_lists_concatenate`
- [ ] `tests/unit/test_foundry_config.py::test_merge_allow_flags_anded` — user `False` + repo `True` → `False`
- [ ] `tests/unit/test_foundry_config.py::test_third_party_mcp_gate` — `type: npm` without flag raises
- [ ] `tests/unit/test_foundry_config.py::test_missing_layers_returns_defaults`
- [ ] `tests/unit/test_foundry_config.py::test_additive_only_structural` — assert no `remove`/`replace` fields exist on any overlay model (reflection test)

### Docs

- [ ] Add `docs/configuration.md` section: "foundry.yaml" — schema, layer order, examples
- [ ] Add `docs/usage/commands.md` entry for `cast new --plan`

### Acceptance

- [ ] `cast new owner/repo feature --plan` prints resolved config + empty artifact list for a repo with no `foundry.yaml`
- [ ] Invalid `foundry.yaml` (unknown key, bad version) prints a clear error and exits 1
- [ ] All Phase 1 tests pass under `./scripts/ci-local.sh`

---

## Phase 2 — git-safety policy overlay (first real apply)

Goal: smallest possible real apply. Validates the merge path into `foundry-git-safety`.

### Artifacts scaffolding

- [ ] Create `foundry_sandbox/artifacts.py` with `FileWrite`, `PolicyPatch`, `PostStep`, `ArtifactBundle` dataclasses
- [ ] Implement `_merge_bundles(bundles: list[ArtifactBundle]) -> ArtifactBundle`
- [ ] Implement `apply_artifacts(name, bundle, sandbox_id)` with the 5-step fixed order from `plan.md` (only the policy-patches step lands real changes in this phase; others can raise `NotImplementedError` for now)

### Compiler

- [ ] Implement `compile_git_safety(overlay)` in `foundry_config.py`
- [ ] Emit `PolicyPatch("add", "protected_branches", [...])` for `protected_branches.add`
- [ ] Emit `PolicyPatch("add", "blocked_patterns", [...])` for `file_restrictions.blocked_patterns_add`
- [ ] Emit `PolicyPatch("add", "allow_pr", bool)` when `allow_pr_operations is not None`

### Applier

- [ ] Implement `_patch_sandbox_policy(sandbox_id, patches)` in `artifacts.py`
- [ ] Read existing registration file at `~/.foundry/data/git-safety/sandboxes/<sandbox_id>.json`
- [ ] Apply each `PolicyPatch` additively — never overwrite existing values, only extend lists or set flags that were unset
- [ ] Write atomically (use `atomic_io.py` helpers)

### Integration

- [ ] In `foundry_sandbox/commands/new_setup.py`, after `provision_git_safety` succeeds, call:
  ```python
  config = resolve_foundry_config(Path(repo_root))
  bundle = _merge_bundles([compile_git_safety(config.git_safety)] if config.git_safety else [])
  apply_artifacts(name, bundle, sandbox_id=name)
  ```

### Tests

- [ ] `tests/unit/test_artifacts.py::test_merge_bundles_concatenates_patches`
- [ ] `tests/unit/test_artifacts.py::test_policy_patches_are_additive` — existing entries preserved
- [ ] `tests/unit/test_artifacts.py::test_apply_policy_patches_atomic` — crash mid-write leaves valid JSON
- [ ] `tests/unit/test_foundry_config.py::test_compile_git_safety_empty_overlay` — returns empty bundle
- [ ] `tests/smoke/` — live sbx test: create sandbox with `foundry.yaml` adding `refs/heads/staging` to protected branches, verify push to `staging` is rejected

### Acceptance

- [ ] `cast new` with a `foundry.yaml` that tightens git-safety actually tightens policy in the running sandbox
- [ ] Smoke test confirms rejection of pushes to added protected branches

---

## Phase 3 — user-services migration

Goal: zero new user-visible surface. Migrate the existing mechanism onto the new pipeline and retire the legacy file.

- [ ] Implement `compile_user_services(services)` — emits the env-var injection + sbx-secret that `user_services.py:91-110` does today
- [ ] Update `foundry_sandbox/user_services.py` to dual-read: `foundry.yaml` wins, then `config/user-services.yaml`, then `FOUNDRY_USER_SERVICES_PATH`
- [ ] Emit a `log_warn` when the legacy file is used, pointing to `foundry.yaml` migration
- [ ] Move the file-write + env-injection code out of `new_setup.py:215-240` into `compile_user_services`; keep the sbx-exec call only in `apply_artifacts`
- [ ] Update `config/user-services.yaml.example` comments to recommend `foundry.yaml`
- [ ] Add `CHANGELOG.md` entry documenting the dual-read deprecation window

### Tests

- [ ] `tests/unit/test_foundry_config.py::test_user_services_migration` — same output whether defined in `foundry.yaml` or legacy file
- [ ] `tests/unit/test_foundry_config.py::test_user_services_foundry_yaml_wins`

### Acceptance

- [ ] Existing users on `config/user-services.yaml` see a deprecation warning but still work
- [ ] `foundry.yaml` with a `user_services:` section produces identical sandbox behavior to the legacy file

---

## Phase 4 — MCP servers (`builtin` + `proxy`)

Goal: first net-new user-facing feature.

### Builtin registry

- [ ] Create `foundry_sandbox/mcp_builtins.py` with a dict of curated MCP server specs (start with: `github`, `filesystem`, `memory` — whichever are most commonly used)
- [ ] Each entry is a function `(env: dict) -> dict` that returns the `.mcp.json` fragment

### Compiler

- [ ] Implement `compile_mcp_servers(servers)` in `foundry_config.py`
- [ ] For `type: builtin` — look up in `mcp_builtins.py`, raise on unknown name
- [ ] For `type: proxy` — emit env-var injection (reusing the user-services pattern) + sbx-secret + `.mcp.json` fragment pointing at the proxy URL
- [ ] Skip `type: npm` (Phase 6)

### Applier extensions

- [ ] Implement `_write_file_in_sandbox(name, fw)` in `artifacts.py` — use the base64-through-`sbx exec` pattern from `git_safety.py`
- [ ] Implement `_extend_sandbox_env(name, env_vars)` — merge into the existing `/etc/profile.d/foundry-git-safety.sh`, `/etc/bash.bashrc`, `/var/lib/foundry/git-safety.env` via helpers in `git_safety.py` (extract them into `foundry_sandbox/_sandbox_env.py` first if they're private)

### `${from_host:VAR}` substitution

- [ ] Implement `_resolve_host_refs(value: str) -> tuple[str, bool]` — returns `(resolved_value, is_proxy_ref)`
- [ ] Invoke during `compile_mcp_servers` for `env` values; proxy refs emit both a `sbx_secret` and an env-var pointing at the proxy URL

### Tests

- [ ] `tests/unit/test_foundry_config.py::test_compile_mcp_builtin`
- [ ] `tests/unit/test_foundry_config.py::test_compile_mcp_proxy_emits_secret_and_env`
- [ ] `tests/unit/test_foundry_config.py::test_from_host_ref_resolves_to_proxy_url`
- [ ] `tests/unit/test_foundry_config.py::test_unknown_builtin_mcp_raises`
- [ ] `tests/smoke/` — live sbx test: `foundry.yaml` declaring a `github` builtin MCP server results in a working `.mcp.json` inside the sandbox

### Docs

- [ ] `docs/configuration.md` — "MCP servers" section with builtin list and proxy example

### Acceptance

- [ ] `.mcp.json` appears at `/workspace/.mcp.json` with correct contents
- [ ] For `type: proxy`, the sandbox env var contains a proxy URL, not the raw secret
- [ ] `cast new --plan` shows both the file write and the sbx-secret push

---

## Phase 5 — Claude Code config

Goal: compile `claude_code:` section to `.claude/settings.json` + `.claude/` directory. Pure file synthesis, no runtime.

### Compiler

- [ ] Implement `compile_claude_code(cfg)` in `foundry_config.py`
- [ ] For `skills` with `source:` (host path) — read from host, emit `FileWrite`s into `/workspace/.claude/skills/<name>/`
- [ ] For `skills` with `git:` — emit a `PostStep` that clones the repo into the sandbox (this does use a post step, which is fine — it's the last phase)
- [ ] For `commands` — read host files, emit `FileWrite`s into `/workspace/.claude/commands/`
- [ ] For `hooks` + `permissions` — emit a single `FileWrite` for `/workspace/.claude/settings.json` with the compiled JSON

### Tests

- [ ] `tests/unit/test_foundry_config.py::test_compile_claude_code_settings_json_shape`
- [ ] `tests/unit/test_foundry_config.py::test_compile_claude_code_skill_from_host_path`
- [ ] `tests/unit/test_foundry_config.py::test_compile_claude_code_skill_from_git_emits_post_step`
- [ ] Integration test: create sandbox with sample `claude_code:` block; verify `.claude/settings.json` parses and matches expected shape

### Docs

- [ ] `docs/configuration.md` — "Claude Code" section with examples for each sub-key

### Acceptance

- [ ] `.claude/settings.json` inside the sandbox matches the declared config
- [ ] Skills copied from host appear at `.claude/skills/<name>/`
- [ ] `cast new --plan` shows the full set of file writes without running anything

---

## Phase 6 — `type: npm` MCP behind `allow_third_party_mcp`

Goal: escape hatch for user-installed MCP servers, with a clear supply-chain gate.

- [ ] In `compile_mcp_servers`, handle `type: npm` by emitting a `PostStep(["npm", "install", "-g", server.package], user="root")`
- [ ] Emit the corresponding `.mcp.json` fragment pointing at the installed binary
- [ ] Validate: if any `type: npm` server is declared but `allow_third_party_mcp: false`, the existing Phase 1 validator already raises — add an integration test for the error path
- [ ] Document the gate prominently in `docs/configuration.md` — which layers can set it, and why a repo can't override a user `false`

### Tests

- [ ] `tests/unit/test_foundry_config.py::test_npm_mcp_blocked_without_flag`
- [ ] `tests/unit/test_foundry_config.py::test_npm_mcp_compiles_with_flag` — emits the post step
- [ ] `tests/smoke/` — live sbx test: `allow_third_party_mcp: true` + a trivial npm MCP package installs and runs

### Docs

- [ ] `docs/configuration.md` — "Supply-chain gates" subsection calling out AND-across-layers semantics with an example
- [ ] `docs/security/security-model.md` — add a row for third-party MCP to the Non-Goals table, documenting what this control does and does not give you

### Acceptance

- [ ] Default `foundry.yaml` behavior rejects `type: npm`
- [ ] User `~/.foundry/foundry.yaml` setting `allow_third_party_mcp: true` allows repos to declare npm servers
- [ ] Repo `foundry.yaml` cannot re-enable `allow_third_party_mcp` if the user file sets it to `false`

---

## Cross-phase housekeeping

- [ ] Every new public function has a type annotation (mypy strict compliance — see `pyproject.toml:78-81`)
- [ ] Every phase updates `CHANGELOG.md` under the unreleased section
- [ ] `./scripts/ci-local.sh` passes before each phase's PR
- [ ] Redteam module for `foundry.yaml` tampering: verify that a malicious repo `foundry.yaml` cannot weaken git-safety policy, disable wrapper integrity, or override `allow_third_party_mcp: false` from a user file (add to `tests/redteam/modules/`)
