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
- Support existing sandboxes created before this change (backward compat).
- Fail closed on security; no weakening of git safety or isolation.
- Update tests in the same change that modifies code.

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
- For remote URLs (no local `repo_root`): clone a regular checkout to `~/.sandboxes/repos/<owner>/<repo>/` (non-bare), then pass that path to sbx. Add `ensure_repo_checkout()` if needed, or keep using the existing bare repo as a mirror and clone from it.
- Sandbox name generation: keep `sandbox_name()` but change input from `bare_path` to a similar deterministic string derived from `repo_url`.
- Simplify `rollback_new_sbx()` — remove `worktree_path` param; sbx handles worktree cleanup.

### 1.5 Update `write_sandbox_metadata()` (`state.py`)

Pass through the new `workspace_path` field to `SbxSandboxMetadata`.

### 1.6 Update tests

- `tests/unit/test_new_sbx.py`: replace `bare_path`/`worktree_path` mocks with `repo_root`.
- Update any test that asserts on worktree-related paths.

## Phase 2: Update `destroy`, `attach`, `_helpers`, `paths`

Make all core commands work with sbx-managed worktrees.

### 2.1 Simplify `destroy.py`

- Remove `remove_worktree()` call — `sbx rm` handles worktree cleanup.
- Remove `cleanup_sandbox_branch()` call — sbx manages branches.
- Remove `repo_url_to_bare_path` import.
- Keep: `sbx_rm`, git safety unregister, claude-config cleanup.

### 2.2 Update `attach.py`

- Replace `worktree_path.is_dir()` existence check with metadata check.
- For IDE launch: use `workspace_path` from metadata instead of derived worktree path.

### 2.3 Update `_helpers.py`

- `auto_detect_sandbox()`: iterate all sandboxes via metadata, match cwd against `workspace_path`.
- `list_sandbox_names()`: scan `~/.sandboxes/claude-config/` dirs (the authoritative registry) instead of `~/.sandboxes/worktrees/`.
- `fzf_select_sandbox()`: same metadata-based listing.

### 2.4 Update `paths.py`

- `path_worktree(name)`: add fallback — check metadata `workspace_path` first, fall back to old `get_worktrees_dir() / name` for pre-migration sandboxes.
- `find_next_sandbox_name()`: only check `claude-config/` for collisions (not `worktrees/`).
- `repo_url_to_bare_path()`: deprecate but keep for now.

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

Relax trust boundary: allow paths anywhere under the repo root (not just `~/.sandboxes/`). Validate that gitdir is under the repo's `.git/` directory.

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
4. Run `cast destroy <name>` — verify full cleanup (sbx sandbox, config dir, no orphan worktrees).
5. Run `cast list` — verify sandbox listing works.
6. Run `python -m pytest tests/unit/ -x` — verify unit tests pass.
7. Run `python -m ruff check foundry_sandbox` — verify lint passes.
