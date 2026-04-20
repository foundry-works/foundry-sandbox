# ADR-013: Template-Preset Integration

## Status

Accepted

Date: 2026-04-20

## Context

Presets (`cast new --save-as`) store CLI argument snapshots, enabling reuse of `cast new` flags. Templates (`sbx template save`) store filesystem image snapshots, enabling reuse of runtime state (installed packages, config changes, wrapper scripts). These two systems were independent — a preset could not carry template identity, so `cast new --preset` could only recreate CLI flags, not the runtime state.

This gap meant users who modified sandbox state (e.g., installing packages) had to reapply those changes manually each time they recreated from a preset.

Additional problems:
- `--template` always had a Click default (`foundry-git-wrapper:latest`), which masked any preset-provided template value
- `new_sbx_setup()` called `ensure_foundry_template()` for any template, even custom/managed tags
- No ownership model existed for cleaning up template snapshots when presets were deleted

## Decision

1. **Presets now carry template identity.** `CastNewPreset` and `SbxSandboxMetadata` gain `template` and `template_managed` fields. Presets and `--last` persist these fields.

2. **`cast preset save` is the snapshot command.** It snapshots a running sandbox into a managed template (`preset-<name>:latest`) and saves a preset referencing it. The operation is all-or-nothing — if the snapshot fails, no preset is written.

3. **`cast new --save-as` remains CLI-only.** It references the effective template but does not create a new snapshot. `cast preset save` is the only path that creates managed templates.

4. **Template precedence is explicit.** Explicit `--template` on the CLI wins over preset/last template values, which in turn override the Click default.

5. **Only built-in template uses `ensure_foundry_template()`.** Custom and managed template tags are passed directly to `sbx create`, surfacing missing templates as setup failures rather than silently falling back.

6. **Managed templates are auto-cleaned on delete.** When a preset with `template_managed=True` is deleted, the managed template is removed only if no other preset references it. Non-managed templates are never auto-deleted.

## Consequences

### Positive

- `cast new --preset` now restores full runtime state, not just CLI flags
- Clear ownership model: managed templates are created and cleaned up by the preset system
- Explicit `--template` override gives users control over the precedence chain
- `cast new --save-as` vs `cast preset save` distinction is clear: CLI flags vs full snapshot

### Negative

- Additional complexity in the preset data model (two new fields)
- Managed templates consume disk space until explicitly deleted or all referencing presets are removed
- `cast preset save` requires the sandbox to be running (cannot snapshot a stopped sandbox)

### Neutral

- The `template_managed` field is a boolean flag that changes cleanup behavior but not creation behavior
- Existing presets without template fields continue to work (backward-compatible defaults)
- The `rm` and `remove` aliases share the same cleanup logic as `delete`

## Alternatives Considered

1. **Separate `cast preset snapshot` command:** Rejected — one canonical subcommand is sufficient and avoids user confusion about which command to use.

2. **Auto-snapshot on every `--save-as`:** Rejected — would create unnecessary template snapshots for presets that only need CLI flags. Users should opt in to snapshots via `cast preset save`.

3. **Reference counting for templates:** Rejected as over-engineering — scanning presets on delete is simple and sufficient for the expected number of presets per user.

## References

- `foundry_sandbox/models.py` — `CastNewPreset` and `SbxSandboxMetadata` field definitions
- `foundry_sandbox/commands/preset.py` — `save` command and managed-template cleanup
- `foundry_sandbox/commands/new.py` — template precedence in `NewDefaults`
- `foundry_sandbox/commands/new_sbx.py` — template routing in `new_sbx_setup`
