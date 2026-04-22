# Post-sbx-Migration Cleanup Checklist

## Phase 1: Finish the Prior Migration (Release Blocker)

- [x] ~~Synthesize a pre-migration sandbox~~ (SKIP: legacy out of scope)
- [x] ~~Run `cast destroy` against synthesized legacy~~ (SKIP: legacy out of scope)
- [x] ~~Codify legacy destroy as unit test~~ (SKIP: new-layout destroy already covered by 3 tests in `TestDestroyImplNewLayout`)
- [x] `cast git-mode --mode host` — verified by `TestApplyGitMode::test_host_mode_sets_core_worktree`
- [x] `cast git-mode --mode sandbox` — verified by `TestApplyGitMode::test_sandbox_mode_sets_core_worktree`
- [x] ~~Repeat git-mode against legacy~~ (SKIP: legacy out of scope)
- [x] `git status --short` is clean (verified 2026-04-22)

## Phase 2: Mechanical Ergonomic Wins

### 2.1 Dedup `_install_pip_requirements_sbx`

- [x] Move function to `foundry_sandbox/sbx.py`
- [x] Delete copy at `commands/new_sbx.py:40`
- [x] Delete copy at `commands/start.py:32`
- [x] Update import at `tests/unit/test_start_sbx.py:101`
- [x] Run `python -m pytest tests/unit/ -x`

### 2.2 Extract `resolve_sandbox_name()` to `_helpers.py`

- [x] Add `resolve_sandbox_name(name, *, use_last, allow_fzf)` to `commands/_helpers.py`
- [x] Replace in-command helper at `commands/attach.py:47-74`
- [x] Replace in `commands/git_mode.py`
- [x] Replace in `commands/refresh_creds.py`
- [x] Replace in `commands/preset.py`
- [x] Add unit test for the shared helper
- [x] Verify `cast attach --last`, `cast attach` (auto-detect), `cast attach` (fzf) all still work

### 2.3 Rename `workspace_path` → `host_worktree_path`

- [x] Rename field in `models.py:SbxSandboxMetadata`
- [x] Update `state.py:write_sandbox_metadata()` to write the new name
- [x] `state.py:load_sandbox_metadata()` reads either `host_worktree_path` or `workspace_path` (compat shim)
- [x] Update all in-code references (`paths.py`, `_helpers.py`, `commands/destroy.py`, `commands/attach.py`, `commands/git_mode.py`)
- [x] Update tests that reference `workspace_path` in metadata fixtures
- [x] Document the rename in `CHANGELOG.md`

## Phase 3: Command Structure Cleanup

### 3.1 Collapse `new_*.py` fan-out

- [ ] Fold `new_validation.py` helpers into `new_sbx.py` as private functions
- [ ] Fold `new_resolver.py` helpers into `new.py` (or split between `new.py` and `new_sbx.py` by concern)
- [ ] Delete `new_validation.py` and `new_resolver.py`
- [ ] Update imports
- [ ] Update/move related tests in `tests/unit/`
- [ ] Run `cast new --agent shell --skip-key-check --template none .` and verify success

### 3.2 Replace `ctx.invoke()` cross-command calls

- [ ] Replace `attach.py:31` (`list_cmd` invocation) with inline listing or a pointer message
- [ ] Extract startup logic from `start.py` into a plain function; call it from both `start.py` and `attach.py:44`
- [ ] Replace `info.py:46,48,62` (`config` + `status` chain) — inline or drop the `info` command
- [ ] Verify `cast attach <name>` against a stopped sandbox still auto-starts
- [ ] Verify `cast info` output is preserved (if kept)

### 3.3 CLI alias cleanup

- [ ] Decide: promote aliases to canonical, or drop aliases entirely
- [ ] Apply the decision in `cli.py:24-28`
- [ ] Document the rename in `CHANGELOG.md`
- [ ] Update `docs/usage/` and `README.md` for any renamed commands

## Phase 4: Delete Legacy Code (Next Release)

**Prerequisite:** at least one release has shipped with Phase 1-3; release notes instruct users to destroy and recreate any pre-migration sandbox.

### 4.1 Delete `git_worktree.py`

- [ ] Move `cleanup_sandbox_branch_repo()` (git_worktree.py:484-538) into `git.py`
- [ ] Delete `foundry_sandbox/git_worktree.py`
- [ ] Remove imports from `commands/destroy.py`

### 4.2 Delete legacy helpers

- [ ] `ensure_bare_repo()` in `git.py`
- [ ] `fetch_bare_branch()` in `git.py`
- [ ] `_ensure_fetch_refspec()` in `git.py`
- [ ] `repo_url_to_bare_path()` in `paths.py`
- [ ] `get_worktrees_dir()` in `constants.py`
- [ ] `path_worktree()` in `paths.py` (verify no remaining callers first)
- [ ] Remove the `workspace_path` read-compat shim in `state.py` from Phase 2.3

### 4.3 Simplify dual-dispatch code paths

- [ ] `commands/destroy.py`: drop the `host_worktree_path == ""` branch; delete `remove_worktree` / `cleanup_sandbox_branch` calls
- [ ] `commands/git_mode.py`: delete `_validate_legacy_layout_paths()` and path-shape fallback
- [ ] `commands/_helpers.py:auto_detect_sandbox()`: drop the legacy `worktrees/` fallback (current lines 54-65)
- [ ] `paths.py:resolve_workspace_path()`: drop the `path_worktree(name)` fallback
- [ ] Drop legacy-sandbox tests that are no longer meaningful

### 4.4 Final validation

- [ ] `./scripts/ci-local.sh --all`
- [ ] `./tests/redteam-sandbox.sh` inside a freshly created sandbox — all pass
- [ ] `python -m ruff check foundry_sandbox foundry-git-safety/foundry_git_safety`
- [ ] `python -m compileall -q foundry_sandbox foundry-git-safety/foundry_git_safety`

## Phase 5: Minor Cleanups (Optional)

- [ ] Remove `SetupError` (`new_sbx.py:36`); replace with `RuntimeError`
- [ ] Simplify `NewDefaults` + `_apply_saved_new_defaults()` (`new.py:38-100`)
- [ ] Reduce `write_sandbox_metadata` arg list (`state.py:81-147`) — pass `SbxSandboxMetadata` directly
- [ ] Inline or delete `SandboxPaths` NamedTuple (`paths.py:34`)

## Cross-Phase Gates

Before every commit:

- [ ] `./scripts/ci-local.sh`
- [ ] `python -m pytest tests/unit/ -x`
- [ ] `python -m ruff check foundry_sandbox foundry-git-safety/foundry_git_safety`

Before every release tag:

- [ ] All Phase 1 items checked
- [ ] `CHANGELOG.md` updated with user-visible changes
- [ ] `pyproject.toml` version bumped
