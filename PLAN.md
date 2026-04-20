# Plan: Native sbx Template Integration for Presets

**Last updated:** 2026-04-20
**Branch:** sbx
**Status:** Implementation planning

---

## 1. Objective

Unify the preset system (CLI argument snapshots) with the sbx template system (filesystem image snapshots) so that a preset can restore both:

- how `cast new` was invoked
- which sandbox image/template should be used to recreate the runtime state

This should cover installed packages, modified sandbox config, and the baked-in wrapper state when the preset points at a managed snapshot template.

## 2. Current State

### Presets (CLI argument snapshots)

- `CastNewPreset` in `foundry_sandbox/models.py` stores repo, agent, branch, working_dir, pip_requirements, etc.
- `save_cast_preset()` and `load_cast_preset()` in `foundry_sandbox/state.py` persist preset JSON under `~/.sandboxes/presets/`
- `save_last_cast_new()` and `load_last_cast_new()` use the same JSON shape for `cast new --last`
- `cast preset list/show/delete` live in `foundry_sandbox/commands/preset.py`
- `cast new --preset <name>` reuses saved args
- `cast new --save-as <name>` saves the resolved creation args after sandbox setup completes

### Templates (filesystem snapshots)

- `sbx_template_save(name, tag)` in `foundry_sandbox/sbx.py` runs `sbx template save`
- `sbx_template_load(tag)` exists
- `FOUNDRY_TEMPLATE_TAG = "foundry-git-wrapper:latest"` is the built-in template
- `ensure_foundry_template()` builds/checks that built-in template
- `cast new --template <tag>` passes a template tag into sandbox creation
- `SbxSandboxMetadata.template` already records which template tag was used

### Current Gaps

1. Presets do not store any template information, so `cast new --preset` can only recreate CLI flags.
2. `cast new` treats `--template` as always-present because Click supplies a default, which means preset-provided template values currently have no clean precedence path.
3. `new_sbx_setup()` assumes any non-empty template should go through `ensure_foundry_template()`, which is only correct for `foundry-git-wrapper:latest`, not arbitrary snapshot tags.
4. Preset names are only validated for path safety today; that is not enough to safely derive sbx template tags like `preset-<name>:latest`.
5. There is no ownership/cleanup model for automatically removing preset-managed snapshot templates.

## 3. Implementation Plan

### Phase 1: Extend the shared data model

**Modified: `foundry_sandbox/models.py`**

Add template metadata to the shared models:

- `CastNewPreset.template: str = ""`
- `CastNewPreset.template_managed: bool = False`
- `SbxSandboxMetadata.template_managed: bool = False`

Rationale:

- `template` is the image tag to reuse on `cast new --preset` or `cast new --last`
- `template_managed` distinguishes preset-owned snapshot templates from user-supplied/custom tags, which is required for safe cleanup

**Modified: `foundry_sandbox/state.py`**

Update:

- `_write_cast_new_json()`
- `save_last_cast_new()`
- `save_cast_preset()`
- `_load_cast_new_json()`

to persist/load `template` and `template_managed`.

This is intentionally shared by both preset JSON and `.last-cast-new.json`, so `--last` gains the same template-awareness as `--preset`.

Backward compatibility: missing fields in existing JSON should default to `""` and `False`.

### Phase 2: Add safe managed-tag helpers and sbx delete support

**Modified: `foundry_sandbox/commands/preset.py` or shared helper module**

Add a helper that derives a safe managed snapshot tag from the preset name, e.g.:

- input preset name: `my setup`
- managed tag: `preset-my-setup:latest`

The helper should normalize or reject characters that are legal for preset filenames but unsafe/awkward for sbx template tags.

**Modified: `foundry_sandbox/sbx.py`**

Add:

- `sbx_template_rm(tag)` wrapper for `sbx template rm <tag>`

This keeps preset cleanup inside the same sbx abstraction layer as save/load/list.

### Phase 3: Add `cast preset save`

**Modified: `foundry_sandbox/commands/preset.py`**

Add a new command:

```bash
cast preset save <name> [--sandbox <sandbox-name>]
```

Behavior:

1. Validate the preset name.
2. Resolve sandbox name:
   - use `--sandbox` if provided
   - otherwise auto-detect from CWD using `commands._helpers.auto_detect_sandbox()`
3. Validate sandbox exists and is currently running (`sbx_sandbox_exists`, `sbx_is_running`).
4. Load sandbox metadata (`load_sandbox_metadata`) for repo/branch/agent/working_dir/pip_requirements/etc.
5. Generate a managed tag via the Phase 2 helper.
6. Run `sbx_template_save(sandbox_name, managed_tag)`.
7. On success, write the preset with:
   - metadata-derived CLI args
   - `template=<managed_tag>`
   - `template_managed=True`

Decision: `cast preset save` is all-or-nothing. If template snapshotting fails, the command should fail and leave the preset untouched. The existing `cast new --save-as` path already covers CLI-only preset saving.

There is no separate `cast preset snapshot` alias in this design; `cast preset save` is the snapshotting command.

### Phase 4: Use preset/last template values during `cast new`

**Modified: `foundry_sandbox/commands/new.py`**

Extend the saved-default plumbing so `cast new --preset` and `cast new --last` can carry:

- `template`
- `template_managed`

Concrete changes:

- Add these fields to `NewDefaults`
- Teach `_apply_saved_new_defaults()` and `_load_and_apply_defaults()` to pass them through
- Track `template` in the explicit-parameter precedence logic

Important precedence rule:

- if `--template` was explicitly passed on the command line, it wins
- otherwise, a preset/last-file template should override the Click default

Without this change, the current Click default (`foundry-git-wrapper:latest`) masks preset templates.

Also write the effective `template` and `template_managed` values into sandbox metadata during creation so later flows (`cast preset save`, `cast new --save-as`) can preserve the right semantics.

### Phase 5: Fix template handling inside `new_sbx_setup()`

**Modified: `foundry_sandbox/commands/new_sbx.py`**

Split built-in-template behavior from arbitrary-template behavior:

- If template is empty or `"none"`, create without a template and fall back to runtime injection.
- If template equals `FOUNDRY_TEMPLATE_TAG`, keep the current `ensure_foundry_template()` behavior.
- If template is any other non-empty tag, pass it directly to `sbx_create()` without calling `ensure_foundry_template()`.

Failure behavior:

- Missing or broken custom/managed templates should surface as setup errors.
- Silent fallback to runtime injection is only acceptable for the built-in foundry template path when template build/check fails.

### Phase 6: Clarify `cast new --save-as`

**Modified: `foundry_sandbox/commands/new.py`**

`cast new --save-as` remains CLI-oriented preset saving. It does **not** call `sbx template save`.

However, because it runs after creation succeeds, it should persist the effective:

- `template`
- `template_managed`

that were actually used to create the sandbox.

Implications:

- `--save-as` can preserve a reference to an existing template
- `--save-as` does not create a fresh runtime snapshot
- runtime snapshot creation remains the responsibility of `cast preset save`

### Phase 7: Safe cleanup on preset delete

**Modified: `foundry_sandbox/commands/preset.py`**

Change `cast preset delete` to:

1. Load the preset before deleting it.
2. Delete the preset JSON.
3. If `template_managed` is `True`, scan remaining presets for the same `template` tag.
4. Only when no remaining preset references that managed tag, attempt `sbx_template_rm(tag)`.

Rules:

- Non-managed templates are never deleted automatically.
- Template cleanup is best-effort; failure should warn but not block preset deletion.
- Hidden aliases (`rm`, `remove`) should reuse the same cleanup path.

### Phase 8: Tests

Use a mix of existing test modules and new targeted command tests.

**Extend existing**

- `tests/unit/test_models.py`
  - defaults and serialization for `template` / `template_managed`
- `tests/unit/test_state.py`
  - preset save/load round-trip with template fields
  - last-command save/load round-trip with template fields
- `tests/unit/test_sbx.py`
  - `sbx_template_rm()` wrapper

**Add new**

- `tests/unit/test_preset_command.py`
  - `cast preset save` with explicit sandbox
  - auto-detect sandbox from CWD
  - failure when sandbox missing or stopped
  - failure when `sbx_template_save` fails
  - delete cleans up managed template only when last reference is removed
  - delete does not remove non-managed templates

- `tests/unit/test_new_template_defaults.py`
  - preset template overrides Click default when `--template` was not explicit
  - explicit `--template` overrides preset/last template
  - `--last` restores template/template_managed
  - built-in template path still uses `ensure_foundry_template()`
  - custom/managed template path does not call `ensure_foundry_template()`

- `tests/unit/test_cli.py`
  - help output updated for `cast preset save` if static help text is changed

### Phase 9: Documentation

**Modified: user-facing docs**

- `foundry_sandbox/commands/help_cmd.py`
- `docs/usage/commands.md`

Document:

- `cast preset save`
- the difference between `cast new --save-as` and `cast preset save`
- template cleanup semantics for managed snapshot presets

**Modified: architecture/security docs**

- `docs/architecture.md`
- `docs/security/security-model.md`

Update the template-persistence guidance so it references the new first-class preset snapshot flow, not only raw `sbx template save`.

**Optional ADR**

- `docs/adr/013-template-preset-integration.md`

Decision record:

- why presets now carry template identity
- why `template_managed` exists
- why `cast preset save` is all-or-nothing
- why cleanup only happens for managed tags with no remaining references

## 4. Key Files

| File | Change |
|------|--------|
| `foundry_sandbox/models.py` | Add `template` / `template_managed` fields |
| `foundry_sandbox/state.py` | Persist/load template metadata for presets and `--last` |
| `foundry_sandbox/commands/preset.py` | Add `save` command and delete cleanup logic |
| `foundry_sandbox/commands/new.py` | Add template precedence handling for preset/last/save-as |
| `foundry_sandbox/commands/new_sbx.py` | Separate built-in template handling from custom tags |
| `foundry_sandbox/sbx.py` | Add `sbx_template_rm()` |
| `tests/unit/test_models.py` | Extend model coverage |
| `tests/unit/test_state.py` | Extend preset/last state coverage |
| `tests/unit/test_sbx.py` | Add `sbx_template_rm()` tests |
| `tests/unit/test_preset_command.py` | New preset command tests |
| `tests/unit/test_new_template_defaults.py` | New template precedence tests |
| `docs/usage/commands.md` | Document new preset-save flow |
| `docs/architecture.md` | Update template persistence guidance |
| `docs/security/security-model.md` | Update wrapper/template mitigation guidance |

## 5. Design Decisions

- **Managed snapshot tag format:** `preset-<normalized-name>:latest`
- **Managed-vs-custom distinction:** `template_managed=True` means the tag was created by `cast preset save` and is eligible for automated cleanup.
- **`cast preset save` semantics:** all-or-nothing; no silent downgrade to CLI-only preset saving.
- **`cast new --save-as` semantics:** remains CLI-only, but may reference an already-existing template; it never creates a new snapshot image.
- **Deletion semantics:** only remove managed templates, and only when the deleted preset was the last remaining reference.
- **No separate `cast preset snapshot` alias:** one canonical subcommand is enough.

## 6. Verification

1. `pytest tests/unit/test_models.py tests/unit/test_state.py tests/unit/test_sbx.py -v`
2. `pytest tests/unit/test_preset_command.py tests/unit/test_new_template_defaults.py tests/unit/test_cli.py -v`
3. `./scripts/ci-local.sh`
4. Manual:
   - create sandbox
   - mutate runtime state inside sandbox
   - `cast preset save mysetup --sandbox <name>`
   - destroy sandbox
   - `cast new --preset mysetup`
   - verify runtime state is restored
5. Manual cleanup:
   - create two presets referencing the same managed template
   - delete the first preset and verify template remains
   - delete the last preset and verify template removal is attempted
