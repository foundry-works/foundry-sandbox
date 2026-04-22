# Migrate to sbx Worktree Management

Date: 2026-04-22

## Goal

Replace cast's custom bare-repo + worktree system with sbx's built-in `--branch` worktree management. Currently `cast new` creates a bare repo at `~/.sandboxes/repos/` and a git worktree at `~/.sandboxes/worktrees/<name>/`, then passes both the worktree path AND `--branch` to `sbx create`. sbx rejects this because the cast-created worktree is a detached checkout, not a git repo root.

## Root Cause

`new_sbx.py:86-121` does three things:
1. `ensure_bare_repo()` — clones bare repo to `~/.sandboxes/repos/`
2. `create_worktree()` — creates git worktree at `~/.sandboxes/worktrees/<name>/`
3. `sbx_create(name, agent, worktree_path, branch=branch)` — passes cast worktree as workspace AND `--branch`

sbx's `--branch` flag creates its own worktree under `<repo>/.sbx/<name>-worktrees/<branch>/`. The double worktree creation conflicts. The fix: pass the repo root (not a worktree) to sbx and let sbx manage worktrees entirely.

## Ground Rules

- Cast delegates ALL worktree/git-branch management to sbx.
- Cast retains: git safety server, HMAC provisioning, wrapper injection, metadata, IDE attach, destroy coordination.
- Support existing sandboxes created before this change (backward compat). Legacy teardown paths stay active for any sandbox whose metadata has `workspace_path == ""`.
- Fail closed on security; no weakening of git safety or isolation.
- Update tests in the same change that modifies code.

## Open Questions (Resolve Before Phase 1)

1. **Does `sbx rm` delete the feature branch, or only the worktree?** `git_worktree.cleanup_sandbox_branch()` is flagged security-critical today. Under the new layout the branch lives in the user's *real* repo `.git`, so a leak is user-visible. Verify experimentally and either rely on sbx or keep a cast-side fallback that respects the protected-branch patterns.
2. **Source of truth for `workspace_path`.** Both a deterministic formula (`sbx_worktree_path()`) and a stdout parser (`sbx_get_workspace_info()`) are proposed. Decision: store the **deterministic** path in metadata, use the parsed value as a post-create sanity check. If they disagree, fail the create — sbx's layout changed and the assumption is stale.
3. **Remote-URL concurrency.** Under the new flow, multiple sandboxes for the same remote share one `.git`. Concurrent `cast new` will race on `git worktree add`. Add a per-repo lock in `ensure_repo_checkout()` (file lock on the repo root).

## sbx Worktree Facts (Verified)

- `sbx create --name X --branch <branch> shell <repo-root>` creates worktree at `<repo-root>/.sbx/<name>-worktrees/<branch>/`
- sbx stdout includes the worktree path: `Worktree: /path/to/.sbx/<name>-worktrees/<branch>`
- `sbx ls --json` returns `workspaces` array with the git root (not the worktree path directly)
- `sbx rm` cleans up worktrees automatically
- sbx worktrees use standard `git worktree` layout: `.git` points to `<repo>/.git/worktrees/<branch>/`
- sbx runtime spec at `~/.local/state/sandboxes/sandboxes/sandboxd/runtimes/<name>.json` has `WorkspaceDir` (git root)
- The worktree path is deterministic: `<repo_root>/.sbx/<sandbox_name>-worktrees/<branch>/`

## Phase 1: Fix `cast new` (Unblock Sandbox Creation)

Make `cast new <repo>` produce a working sandbox by delegating worktree creation to sbx.

### 1.1 Add `workspace_path` to metadata (`models.py`)

Add field to `SbxSandboxMetadata`:

```python
workspace_path: str = ""
"""Host-side path to the sbx-managed worktree (set after sbx create)."""
```

### 1.2 Add `sbx_get_workspace_info()` to `sbx.py`

Parse sbx create stdout to extract worktree path and branch. sbx stdout lines:
```
  Worktree: /home/user/repo/.sbx/<name>-worktrees/<branch>
  Branch: <branch>
```

```python
def sbx_get_workspace_info(sbx_create_stdout: str) -> dict[str, str]:
    """Extract worktree path and branch from sbx create stdout."""
```

Also add a function to compute the expected worktree path deterministically:
```python
def sbx_worktree_path(repo_root: str, sandbox_name: str, branch: str) -> str:
    """Compute the expected sbx worktree path."""
    return f"{repo_root}/.sbx/{sandbox_name}-worktrees/{branch}"
```

### 1.3 Rewrite `new_sbx_setup()` (`new_sbx.py`)

**Remove**: imports of `ensure_bare_repo`, `create_worktree`; parameters `bare_path`, `worktree_path`; steps 2-3 (bare repo clone, worktree creation).

**Change signature**: `bare_path, worktree_path` → `repo_root: str`

**Change `sbx_create` call**: pass `repo_root` instead of `worktree_path`:
```python
result = sbx_create(name, agent, repo_root, branch=branch, template=use_template)
workspace_path = sbx_worktree_path(repo_root, name, branch)
```

**Store workspace_path in metadata** after sbx create succeeds.

**Update `provision_git_safety` call**: use `workspace_path` as `repo_root`.

### 1.4 Update `new.py`

- Remove `repo_url_to_bare_path` import and `bare_path` computation.
- `repo_root` comes from `_resolve_repo_input()` (already returns it for local repos).
- For remote URLs (no local `repo_root`): add `ensure_repo_checkout(repo_url) -> str` that clones a regular (non-bare) checkout to `~/.sandboxes/repos/<owner>/<repo>/` if missing, takes a file lock on the repo root during the operation, and returns the path. The same lock is re-acquired for the subsequent `sbx create` call so concurrent `cast new` invocations on the same remote serialize their `git worktree add` steps. Leave the cached checkout in place on rollback (cache semantics, same as the old bare-repo cache).
- Refactor `sandbox_name()` to take `repo_name: str` directly instead of `bare_path`. Caller derives `repo_name` from `repo_url` (basename of the URL path, stripped of `.git`). No fallback inference inside the helper.
- Simplify `rollback_new_sbx()` — remove `worktree_path` param; sbx handles worktree cleanup.

### 1.5 Update `write_sandbox_metadata()` (`state.py`)

Pass through the new `workspace_path` field to `SbxSandboxMetadata`.

### 1.6 Update tests

- `tests/unit/test_new_sbx.py`: replace `bare_path`/`worktree_path` mocks with `repo_root`.
- Update any test that asserts on worktree-related paths.

## Phase 2: Update `destroy`, `attach`, `_helpers`, `paths`

Make all core commands work with sbx-managed worktrees.

### 2.1 Simplify `destroy.py`

- Branch on metadata: if `metadata.workspace_path` is set, the sandbox uses the new layout and `sbx rm` owns worktree cleanup — skip `remove_worktree()` and `cleanup_sandbox_branch()`.
- If `workspace_path == ""` (legacy sandbox), keep the current calls to `remove_worktree()` and `cleanup_sandbox_branch()` so existing installs still clean up fully. `repo_url_to_bare_path` import stays for this path.
- Branch deletion under the new layout: if Open Question (1) concludes that `sbx rm` does *not* delete the feature branch, add a new-layout cleanup helper that deletes the branch from the shared repo `.git` (enforcing the same protected-branch patterns). If sbx handles it, drop cast's fallback entirely for new sandboxes.
- Keep: `sbx_rm`, git safety unregister, claude-config cleanup.

### 2.2 Update `attach.py`

- Replace `worktree_path.is_dir()` existence check with metadata check.
- For IDE launch: use `workspace_path` from metadata instead of derived worktree path.

### 2.3 Update `_helpers.py`

- `auto_detect_sandbox()`: iterate all sandboxes via metadata, match cwd against `workspace_path`.
- `list_sandbox_names()`: scan `~/.sandboxes/claude-config/` dirs (the authoritative registry) instead of `~/.sandboxes/worktrees/`.
- `fzf_select_sandbox()`: same metadata-based listing.

### 2.4 Update `paths.py`

- **Keep `path_worktree()` pure.** Do NOT make it read JSON — `paths.py` is a pure-path module and every call becoming I/O is a regression. Keep the existing `get_worktrees_dir() / name` formula for legacy sandboxes.
- Add a new helper `resolve_workspace_path(name: str) -> Path` that reads metadata, returns `workspace_path` if set, otherwise falls back to `path_worktree(name)`. Callers that need the live path (attach, git_mode, IDE launch) use the new helper; pure-path consumers stay on `path_worktree()`.
- `find_next_sandbox_name()`: only check `claude-config/` for collisions (not `worktrees/`). `claude-config/<name>/` is the authoritative registry.
- `repo_url_to_bare_path()`: deprecate but keep for legacy destroy path (see §2.1).

## Phase 3: Update `git_mode` (Deferred)

Most complex change — defer until Phase 1-2 are stable.

### 3.1 Rewrite `_resolve_git_paths()` (`git_mode.py`)

sbx worktrees use `<repo>/.git/worktrees/<branch>/` as gitdir. The `.git` file in the worktree at `<repo>/.sbx/<name>-worktrees/<branch>/.git` points there. The `commondir` in the gitdir points to the main repo's `.git`. This is the standard git worktree layout.

The path traversal chain:
```
worktree/.git → gitdir: <repo>/.git/worktrees/<branch>
gitdir/commondir → ../.. (→ <repo>/.git)
```

### 3.2 Update `_validate_git_paths()`

Must accept **both** layouts — do not replace the old check:

- Legacy: worktree under `~/.sandboxes/worktrees/`, gitdir + bare under `~/.sandboxes/repos/`.
- New: worktree under `<repo_root>/.sbx/<name>-worktrees/<branch>/`, gitdir under `<repo_root>/.git/worktrees/<branch>/`, commondir = `<repo_root>/.git`.

Dispatch on which layout the worktree path matches, then apply the corresponding trust-boundary check. Fail closed if neither matches. Determine the layout by checking `metadata.workspace_path` first; fall back to path-based detection only if metadata is missing.

### 3.3 Update `_apply_git_mode()`

The core toggle (host path ↔ `/git-workspace`) still applies. The config files are at:
- `gitdir/config.worktree` — per-worktree config
- Main repo `.git/config` — shared config

## Phase 4: Deprecate Dead Code

After all callers are migrated.

### 4.1 Deprecate `git_worktree.py`

Mark for removal: `create_worktree()`, `remove_worktree()`, `cleanup_sandbox_branch()`, `configure_sparse_checkout()`. Keep module with deprecation warnings for one release.

### 4.2 Deprecate bare repo functions in `git.py`

`ensure_bare_repo()`, `fetch_bare_branch()`, `_ensure_fetch_refspec()` — no longer called after Phase 1.

### 4.3 Clean up `constants.py`

`get_worktrees_dir()` returns old path for backward compat. `get_repos_dir()` may still be needed if remote URL cloning is retained.

## Critical Files

| File | Change Size | Description |
|------|-------------|-------------|
| `foundry_sandbox/commands/new_sbx.py` | MAJOR | Remove bare_repo + worktree, pass repo_root to sbx |
| `foundry_sandbox/commands/new.py` | MODERATE | Remove bare_path, simplify params |
| `foundry_sandbox/sbx.py` | MINOR | Add workspace info helpers |
| `foundry_sandbox/models.py` | MINOR | Add workspace_path field |
| `foundry_sandbox/commands/destroy.py` | MODERATE | Remove worktree/branch cleanup |
| `foundry_sandbox/commands/attach.py` | MINOR | Use metadata workspace_path |
| `foundry_sandbox/commands/_helpers.py` | MODERATE | Metadata-based sandbox discovery |
| `foundry_sandbox/paths.py` | MODERATE | Update path_worktree, find_next_sandbox_name |
| `foundry_sandbox/commands/git_mode.py` | MAJOR (Phase 3) | Rewrite path discovery |

## Validation

After each phase:

1. Run `cast new --agent shell --skip-key-check --template none .` — verify sandbox creation succeeds.
2. Run `sbx ls` — verify sandbox is running with correct worktree.
3. Run `sbx exec <name> -- ls /workspace/tests/redteam/` — verify repo is mounted.
4. Run `cast destroy <name>` — verify full cleanup (sbx sandbox, config dir, no orphan worktrees, **no leaked branch in the shared repo**).
5. Run `cast list` — verify sandbox listing works.
6. Run `python -m pytest tests/unit/ -x` — verify unit tests pass.
7. Run `python -m ruff check foundry_sandbox` — verify lint passes.

**Backward-compat spot-checks (after Phase 2):**

- Create a sandbox with `workspace_path = ""` in its metadata (simulate a pre-migration sandbox). Confirm `cast destroy`, `cast attach`, `cast list`, and `cast git-mode --mode host` all still work against the legacy `~/.sandboxes/worktrees/<name>/` layout.
- Run `cast new` twice in parallel against the same remote URL; confirm both succeed (the per-repo lock serializes `git worktree add`).
