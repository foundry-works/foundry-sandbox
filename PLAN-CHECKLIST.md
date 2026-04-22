# sbx Worktree Migration Checklist

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
- [ ] Update sandbox name generation to not require `bare_path`
- [ ] Handle remote URL inputs (no local repo_root) — ensure local clone exists for sbx
- [ ] Update `tests/unit/test_new_sbx.py` — replace bare_path/worktree mocks with repo_root
- [ ] Run `cast new --agent shell --skip-key-check --template none .` and verify success
- [ ] Verify sbx worktree created at `<repo>/.sbx/<name>-worktrees/<branch>/`
- [ ] Verify git wrapper injected and HMAC secret provisioned

## Phase 2: Update destroy, attach, helpers, paths

- [ ] `destroy.py` — remove `remove_worktree()` and `cleanup_sandbox_branch()` calls
- [ ] `destroy.py` — remove `repo_url_to_bare_path` import
- [ ] `attach.py` — replace `worktree_path.is_dir()` check with metadata check
- [ ] `attach.py` — use `workspace_path` from metadata for IDE launch
- [ ] `_helpers.py` — rewrite `auto_detect_sandbox()` to match cwd against metadata workspace_path
- [ ] `_helpers.py` — rewrite `list_sandbox_names()` to scan `claude-config/` dirs
- [ ] `_helpers.py` — rewrite `fzf_select_sandbox()` to use metadata listing
- [ ] `paths.py` — update `path_worktree()` to read from metadata, fall back to old path
- [ ] `paths.py` — update `find_next_sandbox_name()` to only check `claude-config/`
- [ ] Deprecate `repo_url_to_bare_path()` (keep for backward compat)
- [ ] Verify `cast destroy <name>` cleans up sbx sandbox + config (no orphan worktrees)
- [ ] Verify `cast list` shows correct status for new sandboxes
- [ ] Verify `cast attach <name>` connects and opens IDE at correct path
- [ ] Run unit tests: `python -m pytest tests/unit/ -x`

## Phase 3: Update git_mode (Deferred)

- [ ] Inspect sbx worktree `.git` file → gitdir → commondir chain
- [ ] Rewrite `_resolve_git_paths()` for sbx worktree layout
- [ ] Update `_validate_git_paths()` — allow paths under repo root (not just `~/.sandboxes/`)
- [ ] Update `_apply_git_mode()` — config file locations may differ
- [ ] Verify `cast git-mode <name> --mode host` sets correct core.worktree
- [ ] Verify `cast git-mode <name> --mode sandbox` sets `/git-workspace`

## Phase 4: Deprecate Dead Code

- [ ] Add deprecation warnings to `git_worktree.py` functions
- [ ] Add deprecation warnings to bare repo functions in `git.py`
- [ ] Mark `get_worktrees_dir()` as deprecated in `constants.py`
- [ ] After one release: remove `git_worktree.py` entirely
- [ ] After one release: remove `ensure_bare_repo()`, `fetch_bare_branch()`

## Final Validation

- [ ] Run `python -m ruff check foundry_sandbox foundry-git-safety/foundry_git_safety`
- [ ] Run `python -m compileall -q foundry_sandbox foundry-git-safety/foundry_git_safety`
- [ ] Run `python -m pytest` (full suite)
- [ ] Run redteam tests in a live sandbox created with the new flow
- [ ] Check `git status --short` for only intended changes
