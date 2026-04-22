# sbx Worktree Migration Checklist

## Phase 0: Open Questions — RESOLVED

- [x] Experimentally verify whether `sbx rm` deletes the feature branch from the shared repo (not just the worktree). Record finding in PLAN.md.
  - **Answer: No.** Branch ref, worktree registration, and `.sbx/` dir all persist after `sbx rm`. Cast must keep its own branch cleanup.
- [x] Decide source of truth for `workspace_path`: deterministic formula stored, parsed stdout used as post-create sanity check. Document in PLAN.md §1.2/§1.3.
  - **Answer: Deterministic formula as primary, parsed stdout as post-create sanity check.** Fail-closed on mismatch.
- [x] Confirm locking strategy for concurrent `cast new` on the same remote URL (per-repo file lock in `ensure_repo_checkout()`).
  - **Answer: Reuse `file_lock()` from `atomic_io.py` (fcntl.flock, 30s timeout, `.castlock` sidecar).** No new dependency needed. Lock covers clone + `sbx create` (serializes `git worktree add`).

## Phase 1: Fix `cast new`

- [ ] Add `workspace_path: str = ""` field to `SbxSandboxMetadata` in `models.py`
- [ ] Add `sbx_worktree_path(repo_root, name, branch)` to `sbx.py` (deterministic path)
- [ ] Add `sbx_get_workspace_info()` to parse sbx create stdout for worktree/branch
- [ ] Rewrite `new_sbx_setup()` — remove `bare_path`/`worktree_path` params, use `repo_root`
- [ ] Remove `ensure_bare_repo()` and `create_worktree()` calls from `new_sbx.py`
- [ ] Pass `repo_root` (not worktree) to `sbx_create()`, keep `--branch`
- [ ] Store `workspace_path` in metadata after sbx create
- [ ] Update `provision_git_safety()` call to use sbx worktree path
- [ ] Update `new.py` — remove `bare_path` computation, derive `repo_root` from input
- [ ] Simplify `rollback_new_sbx()` — remove `worktree_path` param
- [ ] Update `write_sandbox_metadata()` / `patch_sandbox_metadata()` in `state.py`
- [ ] Refactor `sandbox_name()` to take `repo_name: str` (not `bare_path`); update callers to pass the derived name
- [ ] Add `ensure_repo_checkout(repo_url) -> str` with per-repo file lock for remote URL inputs
- [ ] Re-acquire the per-repo lock around `sbx create` to serialize concurrent `git worktree add`
- [ ] Rollback leaves cached repo checkout intact (cache semantics)
- [ ] Update `tests/unit/test_new_sbx.py` — replace bare_path/worktree mocks with repo_root
- [ ] Add a parse-vs-deterministic mismatch test for `sbx_get_workspace_info()` (fail-closed behavior)
- [ ] Run `cast new --agent shell --skip-key-check --template none .` and verify success
- [ ] Verify sbx worktree created at `<repo>/.sbx/<name>-worktrees/<branch>/`
- [ ] Verify git wrapper injected and HMAC secret provisioned
- [ ] Run two `cast new` processes in parallel against the same remote URL; both succeed

**Note:** sbx applies its own internal name truncation that diverges from our deterministic formula. The mismatch check in `new_sbx.py` now uses parsed stdout as ground truth (commit cd83092).

## Phase 2: Update destroy, attach, helpers, paths

- [x] `destroy.py` — gate cleanup on `metadata.workspace_path`: new layout skips `remove_worktree` + `cleanup_sandbox_branch`; legacy layout keeps both
- [x] `destroy.py` — retain `repo_url_to_bare_path` import for the legacy branch
- [x] `destroy.py` — if Phase 0 Q1 determines sbx does not delete the branch, add a new-layout branch-delete helper that honors protected-branch patterns
- [x] `attach.py` — use `resolve_workspace_path()` for existence check and IDE launch
- [x] `_helpers.py` — rewrite `auto_detect_sandbox()` to match cwd against metadata workspace_path (plus legacy `worktrees/` fallback)
- [x] `_helpers.py` — rewrite `list_sandbox_names()` to scan `claude-config/` dirs (authoritative registry; covers both old and new sandboxes)
- [x] `_helpers.py` — rewrite `fzf_select_sandbox()` to use metadata listing
- [x] Confirm `git_mode.py` sandbox resolution still works (it uses the updated `_helpers.py` shared functions)
- [x] `paths.py` — keep `path_worktree()` pure (legacy formula); do NOT add metadata I/O to it
- [x] `paths.py` — add `resolve_workspace_path(name)` that reads metadata and falls back to `path_worktree(name)`
- [x] `paths.py` — update `find_next_sandbox_name()` to only check `claude-config/`
- [x] Deprecate `repo_url_to_bare_path()` (keep until all legacy sandboxes are gone)
- [x] Verify `cast destroy <name>` cleans up sbx sandbox + config (no orphan worktrees, no leaked branch in shared repo)
- [ ] Verify `cast destroy` against a synthesized pre-migration sandbox (metadata `workspace_path=""`) still cleans up fully
- [ ] Verify `cast list` shows correct status for new sandboxes AND legacy sandboxes
- [ ] Verify `cast attach <name>` connects and opens IDE at correct path for both layouts
- [x] Run unit tests: `python -m pytest tests/unit/ -x`

## Phase 3: Update git_mode (Deferred)

- [x] Inspect sbx worktree `.git` file → gitdir → commondir chain
- [x] Rewrite `_resolve_git_paths()` for sbx worktree layout
- [x] `_validate_git_paths()` dispatches on layout: accept BOTH legacy (`~/.sandboxes/...`) and new (`<repo>/.git/...`); fail closed if neither matches
- [x] Layout dispatch prefers `metadata.workspace_path`; falls back to path-shape detection when metadata is absent
- [x] Update `_apply_git_mode()` — config file locations may differ
- [ ] Verify `cast git-mode <name> --mode host` sets correct core.worktree (new layout)
- [ ] Verify `cast git-mode <name> --mode sandbox` sets `/git-workspace` (new layout)
- [ ] Verify `cast git-mode` still works against a legacy sandbox (regression)

## Phase 4: Deprecate Dead Code

- [x] Add deprecation warnings to `git_worktree.py` functions
- [x] Add deprecation warnings to bare repo functions in `git.py`
- [x] Mark `get_worktrees_dir()` as deprecated in `constants.py`
- [ ] After one release: remove `git_worktree.py` entirely
- [ ] After one release: remove `ensure_bare_repo()`, `fetch_bare_branch()`

## Final Validation

- [x] Run `python -m ruff check foundry_sandbox foundry-git-safety/foundry_git_safety`
- [x] Run `python -m compileall -q foundry_sandbox foundry-git-safety/foundry_git_safety`
- [x] Run `python -m pytest` (full suite) — 563 passed, 10 deselected
- [x] Run redteam tests in a live sandbox created with the new flow — 70 passed, 17 failed (template-dependent, not migration-related)
- [ ] Check `git status --short` for only intended changes
