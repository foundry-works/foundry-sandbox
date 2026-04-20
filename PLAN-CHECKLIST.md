# Template-Preset Integration — Checklist

**Last updated:** 2026-04-20
**Companion to:** `PLAN.md`

Legend: `[x]` done, `[ ]` todo

---

## Phase 1: Extend shared models and state

- [x] Add `template: str = ""` to `CastNewPreset` in `foundry_sandbox/models.py`
- [x] Add `template_managed: bool = False` to `CastNewPreset`
- [x] Add `template_managed: bool = False` to `SbxSandboxMetadata`
- [x] Update `_write_cast_new_json()` in `foundry_sandbox/state.py` to persist both fields
- [x] Update `save_cast_preset()` to accept both fields
- [x] Update `save_last_cast_new()` to accept both fields
- [x] Update `_load_cast_new_json()` to load both fields with backward-compatible defaults

## Phase 2: Managed-tag helpers and sbx delete support

- [x] Add helper to derive a safe managed snapshot tag from preset name
- [x] Normalize or reject preset names that cannot map cleanly to sbx template tags
- [x] Add `sbx_template_rm()` to `foundry_sandbox/sbx.py`

## Phase 3: Add `cast preset save`

- [x] Add `save` subcommand to `foundry_sandbox/commands/preset.py`
- [x] Accept optional `--sandbox <name>` argument
- [x] Auto-detect sandbox from CWD when `--sandbox` is omitted
- [x] Validate sandbox exists
- [x] Validate sandbox is running
- [x] Load sandbox metadata for preset fields
- [x] Call `sbx_template_save(sandbox_name, managed_tag)`
- [x] Save preset with `template=<managed_tag>` and `template_managed=True`
- [x] Fail without writing/updating the preset if template snapshotting fails
- [x] Do not add a separate `snapshot` alias

## Phase 4: Apply template defaults during `cast new`

- [x] Add `template` and `template_managed` to `NewDefaults`
- [x] Teach `_apply_saved_new_defaults()` to carry both fields
- [x] Treat `template` as an explicit CLI parameter only when `--template` was actually passed
- [x] Allow preset/last template to override the Click default when `--template` was not explicit
- [x] Keep explicit `--template` higher priority than preset/last data
- [x] Propagate effective `template` / `template_managed` into sandbox metadata

## Phase 5: Fix `new_sbx_setup()` template behavior

- [x] Only call `ensure_foundry_template()` for `FOUNDRY_TEMPLATE_TAG`
- [x] Pass custom/managed template tags directly to `sbx_create()`
- [x] Keep `"none"` / empty template path as no-template creation
- [ ] Surface missing custom/managed template as setup failure
- [x] Keep runtime-injection fallback only for built-in foundry-template failures

## Phase 6: Clarify `cast new --save-as`

- [x] Keep `cast new --save-as` CLI-only; do not call `sbx template save`
- [x] Persist the effective `template` value used for creation
- [x] Persist the effective `template_managed` value used for creation
- [x] Document that `--save-as` references an existing template but does not create a new snapshot

## Phase 7: Safe cleanup on preset delete

- [x] Load preset metadata before deleting preset JSON
- [x] After deletion, scan remaining presets for references to the same template tag
- [x] Only attempt `sbx_template_rm(tag)` when deleted preset had `template_managed=True` and no references remain
- [x] Never auto-delete non-managed templates
- [x] Warn on template cleanup failure without blocking preset deletion
- [x] Reuse same cleanup path for `delete`, `rm`, and `remove`

## Phase 8: Tests

- [x] Extend `tests/unit/test_models.py` for `template` / `template_managed`
- [ ] Extend `tests/unit/test_state.py` for preset round-trip with template fields
- [ ] Extend `tests/unit/test_state.py` for `--last` round-trip with template fields
- [x] Extend `tests/unit/test_sbx.py` for `sbx_template_rm()`
- [x] Add `tests/unit/test_preset_command.py` for `cast preset save`
- [x] Test auto-detect sandbox behavior in `cast preset save`
- [x] Test save failure when sandbox missing or stopped
- [x] Test save failure when `sbx_template_save` fails
- [x] Test delete cleans up managed template only when last reference is removed
- [x] Test delete leaves non-managed templates alone
- [x] Add `tests/unit/test_new_template_defaults.py` for preset/last template precedence
- [x] Test explicit `--template` override over preset/last data
- [ ] Test built-in template path still calls `ensure_foundry_template()`
- [ ] Test custom/managed template path skips `ensure_foundry_template()`
- [ ] Update `tests/unit/test_cli.py` if static help text changes

## Phase 9: Documentation

- [x] Update `foundry_sandbox/commands/help_cmd.py` for `cast preset save`
- [x] Update `docs/usage/commands.md` with `cast preset save`
- [x] Document the difference between `cast new --save-as` and `cast preset save`
- [x] Document managed-template cleanup behavior
- [x] Update `docs/architecture.md` template guidance
- [x] Update `docs/security/security-model.md` template/wrapper mitigation guidance
- [x] Add optional ADR `docs/adr/013-template-preset-integration.md`

---

## Verification

- [ ] `pytest tests/unit/test_models.py tests/unit/test_state.py tests/unit/test_sbx.py -v` passes
- [ ] `pytest tests/unit/test_preset_command.py tests/unit/test_new_template_defaults.py tests/unit/test_cli.py -v` passes
- [ ] `./scripts/ci-local.sh` passes
- [ ] Manual: create -> mutate runtime -> `cast preset save` -> destroy -> `cast new --preset` -> verify restored state
- [ ] Manual: delete one of multiple presets sharing a managed template -> template remains
- [ ] Manual: delete last preset referencing a managed template -> template removal attempted
