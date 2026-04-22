# Legacy And Dead Code Cleanup Plan

Date: 2026-04-22

## Goal

Remove stale compatibility code, dead modules, obsolete installer behavior, and old test/doc references left after the 0.21.0 migration to Docker `sbx`, while preserving the documented 0.20.x migration path until its planned removal in 0.23.0.

## Ground Rules

- Do not remove the 0.20.x migration commands before the deprecation window ends.
- Keep security behavior fail-closed while deleting compatibility code.
- Prefer deleting unused compatibility shims over keeping aliases without a current caller.
- Update tests and docs in the same change that removes code.
- Run focused unit tests after each cleanup phase, then a broader test/lint pass before release.

## 0.23.0 Migration Removal Requirement

The 0.20.x migration path is not just general cleanup; it is a scheduled breaking removal for 0.23.0. The release that removes it must delete the user-facing commands, the parser/conversion/rollback implementation, the tests that assert old metadata importability, and the docs that describe rollback to 0.20.x.

Removal is complete only when:

- `cast migrate-to-sbx` and `cast migrate-from-sbx` are unknown commands.
- 0.20.x `metadata.env` and old `metadata.json` are no longer parsed or imported.
- Migration snapshots and rollback locks are no longer created or restored.
- The docs no longer instruct users to migrate from 0.20.x using current commands.
- The changelog clearly calls out the breaking removal.

## Phase 1: Immediate Low-Risk Cleanup

These items appear stale or broken and do not need to wait for 0.23.0.

1. Fix or remove shell completion installation.
   - `install.sh` adds `source '$INSTALL_DIR/completion.bash'`, but no `completion.bash` exists in the repo.
   - Decide whether to add generated Click completion support or remove the installer claim and rc-file mutation.
   - Update `README.md`, `docs/getting-started.md`, and `uninstall.sh` wording if completion is removed.

2. Remove no-op installer compatibility flags if no longer needed.
   - Candidates: `--no-build`, `--no-cache`, `--without-opencode`.
   - If retained for one more release, emit a deprecation warning instead of silently accepting them.

3. Remove compose-era Docker image cleanup from `uninstall.sh`.
   - The prompt to remove `foundry-sandbox:latest` appears to belong to the old Docker image workflow.
   - Replace it with current sbx-specific cleanup only if there is a real current artifact to remove.

4. Clean red-team runner examples.
   - `tests/redteam/runner.sh` still shows `03-dns-filtering`, which is retired.
   - Replace with an active module such as `04-git-security`.

5. Remove ignored stale Python bytecode and caches from local working trees.
   - Examples observed: removed modules such as `compose`, `proxy`, `claude_settings`, `new_setup`, and old gateway test pyc files.
   - This is local hygiene, not tracked code, but it prevents false positives during audits.

## Phase 2: Dead-Code Review And Deletion

These require a small reference check before deletion.

1. Review and likely remove `foundry_sandbox/errors.py`.
   - It defines `SandboxError`, `ValidationError`, and `SetupError`, but no tracked code imports them.
   - Existing command code uses local exceptions or direct process exits.

2. Shrink `foundry_sandbox/tui.py`.
   - Only `_is_noninteractive` appears to be used by tracked code.
   - Either move `_is_noninteractive` to a small utility module and delete the unused prompt helpers, or wire the prompt helpers into real command flows.

3. Remove backward-compatible re-exports from `foundry_sandbox/commands/_helpers.py`.
   - Keep only the UI helpers currently imported by commands: auto-detect, fzf selection, and sandbox listing.
   - Update any tests that patch via `_helpers` if direct imports become cleaner.

4. Decide the fate of `foundry-git-safety/foundry_git_safety/wrapper.sh`.
   - The installed sbx wrapper is `foundry_sandbox/assets/git-wrapper-sbx.sh`.
   - If `foundry-git-safety` is meant to be standalone, package and test `wrapper.sh`.
   - If not, delete it and update the standalone README/security docs accordingly.

5. Remove compatibility re-exports from `foundry_git_safety.branch_isolation`.
   - Output filtering now lives in `branch_output_filter.py`; shared constants/types live in `branch_types.py`.
   - Update imports in `operations.py` and tests to use canonical modules.
   - Delete `_REF_ENUM_CMDS` alias if no caller remains.

## Phase 3: Red-Team Deferred Modules

The disabled modules under `tests/redteam/modules/disabled/` still encode old unified-proxy, MITM, or Docker-container assumptions.

1. Rewrite `08-credential-injection` for sbx-native credential checks.
   - Validate `sbx secret set` behavior and user-services proxy signing where applicable.

2. Rewrite `10-container-escape` as VM boundary tests.
   - Remove checks tied to `unified-proxy` DNS names and Docker container networking.

3. Delete or replace `12-tls-filesystem`.
   - MITM CA tests are obsolete because sbx does not use MITM.
   - Keep only filesystem/capability checks that apply to the current microVM model.

4. Delete or replace `16-readonly-fs`.
   - Proxy HTTPS and custom CA assumptions are obsolete.
   - Keep tmpfs and protected-path checks only if they map to current sbx guarantees.

5. Update `tests/redteam/README.md` after deciding which modules are rewritten, deleted, or permanently retired.

## Phase 4: Scheduled 0.23.0 Migration Removal

This should happen when the documented deprecation window ends: target October 2026.

1. Remove CLI command registrations.
   - Delete `migrate-to-sbx` and `migrate-from-sbx` from `_LAZY_COMMANDS` in `foundry_sandbox/cli.py`.
   - Update CLI tests so these commands are expected to fail as unknown.

2. Delete migration command and library code.
   - Remove `foundry_sandbox/commands/migrate.py`.
   - Remove `foundry_sandbox/migration.py`.
   - Remove `path_metadata_legacy_file()` if no non-migration caller remains.
   - Remove imports of `CastNewPreset` or legacy mapping helpers that only existed for conversion.

3. Remove migration tests.
   - Delete or rewrite `tests/unit/test_migration.py`.
   - Delete or rewrite `tests/smoke/test_migration_smoke.py`.
   - Check for duplicated migration smoke tests under `foundry-git-safety/tests/smoke/`.
   - Add negative CLI coverage proving the migration commands are gone.

4. Remove migration docs.
   - Delete `docs/migration/0.20-to-0.21.md` or move it to archived release notes.
   - Remove migration sections from `docs/usage/commands.md`.
   - Update `docs/README.md`, `CHANGELOG.md`, and any command index references.
   - Remove the migration command links from any quick-reference command lists.

5. Remove old metadata import support.
   - Drop `metadata.env` parsing.
   - Drop old JSON metadata classification.
   - Drop rollback snapshot/lock support for migration.
   - Remove migration snapshot constants and any `.migration-in-progress` handling.

6. Release validation for the breaking change.
   - Run `cast migrate-to-sbx` and `cast migrate-from-sbx` manually and confirm both fail with the normal unknown-command message.
   - Run `cast help` and confirm no migration commands are listed.
   - Verify package metadata and changelog identify the removal as part of 0.23.0.

## Phase 5: Documentation Cleanup

1. Update ADR references that point at deleted implementation paths.
   - ADRs can remain historical, but references to removed files should be clearly marked historical.
   - `docs/adr/012-dns-filtering-deferred.md` mentions `PLAN §5.8`; replace with a stable doc reference or remove it.

2. Check user-facing docs for stale unified-proxy, mitmproxy, Squid, docker-compose, gateway token, and custom CA language.
   - Preserve historical ADR context.
   - Remove or rewrite current-architecture docs that imply those systems still exist.

3. Align `README.md` install/uninstall claims with the actual installer behavior after Phase 1.

## Validation Strategy

After each phase:

- Run targeted unit tests for touched modules.
- Run `python -m ruff check foundry_sandbox foundry-git-safety/foundry_git_safety`.
- Run `python -m compileall -q foundry_sandbox foundry-git-safety/foundry_git_safety`.

Before merging the full cleanup:

- Run the full default test suite with `pytest`.
- Run security-focused tests for `foundry-git-safety`.
- Run red-team modules in a live sbx sandbox if red-team tests were changed.
- Confirm `cast help` no longer lists removed commands.
