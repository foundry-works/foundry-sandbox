# Post-sbx-Migration Cleanup & Ergonomics

Date: 2026-04-22

## Goal

The sbx worktree migration (prior PLAN.md) is substantially complete — cast delegates worktree management to sbx, dual-layout dispatch works for destroy/attach/git_mode, and deprecation warnings are in place. This plan covers the remaining release blockers, a short list of low-risk ergonomic wins, and the eventual removal of the legacy fallback paths.

## Rationale

A review of `foundry_sandbox/` surfaced three kinds of work:

1. **Loose ends from the prior migration** — four checklist items are still unvalidated. They gate a clean release.
2. **Mechanical ergonomic wins** — duplicated helpers, inconsistent naming (`workspace_path` vs `worktree_path` vs `workspace_dir`), and a cross-command invocation pattern (`ctx.invoke()`) that couples commands in unusual ways.
3. **Dead-code removal, deferred** — `git_worktree.py`, `ensure_bare_repo()`, `fetch_bare_branch()`, `repo_url_to_bare_path()`, `get_worktrees_dir()` are live only for sandboxes with `workspace_path == ""` in metadata. After one grace release, they come out.

## Ground Rules

- Each phase is self-contained; land as separate PRs.
- No change weakens git safety or isolation. Legacy destroy/git-mode paths stay intact until Phase 4.
- Update tests in the same change that modifies code.
- Run `./scripts/ci-local.sh` before every commit (per CLAUDE.md).

## Phase 1: Finish the Prior Migration (Release Blocker)

Four checklist items from the sbx-worktree migration are still unchecked. Close them out before any refactor work.

### 1.1 Legacy destroy regression test

Create a synthesized pre-migration sandbox by writing `metadata.json` with `workspace_path = ""` and a legacy worktree at `~/.sandboxes/worktrees/<name>/`. Run `cast destroy <name>` and verify: bare repo branch cleaned, worktree removed, claude-config removed, sbx container removed. Codify as a unit test in `tests/unit/test_destroy.py` (mocked filesystem) if no coverage exists.

### 1.2 Live git-mode validation

Against a real new-layout sandbox:

- `cast git-mode <name> --mode host` → verify `core.worktree` in `<repo>/.git/worktrees/<branch>/config.worktree` matches the host path.
- `cast git-mode <name> --mode sandbox` → verify `core.worktree` == `/git-workspace`.
- Against a synthesized legacy sandbox, verify the same toggle still works (dual-dispatch regression).

### 1.3 Final `git status` spot-check

Before tagging the next release, ensure no stray changes remain in the working tree.

## Phase 2: Mechanical Ergonomic Wins

Three small refactors, all low-risk, land in one PR.

### 2.1 Dedup `_install_pip_requirements_sbx`

The same function lives at `foundry_sandbox/commands/new_sbx.py:40` and `foundry_sandbox/commands/start.py:32`. Move it to `foundry_sandbox/sbx.py` (which already hosts the `sbx_*` helper family). Update both call sites and the test at `tests/unit/test_start_sbx.py:101`.

### 2.2 Extract `resolve_sandbox_name()` to `_helpers.py`

The `--last` + auto-detect + fzf + validate pattern is duplicated in:

- `commands/attach.py:47-74`
- `commands/git_mode.py` (sandbox resolution)
- `commands/refresh_creds.py` (sandbox resolution)
- `commands/preset.py` (sandbox resolution)

Pull a single `resolve_sandbox_name(name: str | None, *, use_last: bool = False, last_key: str) -> str` into `commands/_helpers.py`. Each caller passes its own `last_key` (e.g. `"attach"`, `"git_mode"`) to pick the right `load_last_*` function. Replace per-command copies.

### 2.3 Rename `workspace_path` → `host_worktree_path`

Three overlapping terms exist today:

| Term | Meaning | Where |
|------|---------|-------|
| `workspace_path` | Host-side sbx-managed worktree | `SbxSandboxMetadata`, `state.py`, `paths.py`, `_helpers.py` |
| `worktree_path` | Legacy `~/.sandboxes/worktrees/<name>/` formula | `paths.py:path_worktree()` |
| `workspace_dir` | Container-side mount (`/workspace`) | `models.py`, sbx invocations |

Rename the metadata field and all in-code references to `host_worktree_path`. Keep on-disk JSON backward-compat: in `state.py`, read either `host_worktree_path` or `workspace_path` during load; only write the new name. Drop the read-compat shim in Phase 4.

## Phase 3: Command Structure Cleanup

Medium-impact. Land after Phase 2 settles.

### 3.1 Collapse the `new_*.py` fan-out

Four files (`new.py` 458, `new_sbx.py` 277, `new_resolver.py` 198, `new_validation.py` 84 — total 1,017 lines) for one command. Target two files:

- `new.py` — Click CLI glue, defaults, user interaction.
- `new_sbx.py` — all imperative setup + rollback.

Fold `new_validation.py` (3 helpers, 84 lines) into `new_sbx.py` as private helpers. Fold `new_resolver.py` (5 helpers, 198 lines) into `new.py` — those helpers only feed the CLI's defaulting logic.

### 3.2 Replace `ctx.invoke()` cross-command calls

Cases:

- `attach.py:31` invokes `list_cmd` when resolution fails. Either inline a small listing (just print `list_sandbox_names()`) or drop in favor of `click.echo("Run 'cast list' to see sandboxes.")`.
- `attach.py:44` invokes `start_cmd`. Factor the startup logic out of `start.py` into a plain function in `sbx.py` (or `commands/_helpers.py`) that both commands call.
- `info.py:46,48,62` chains `config` + `status`. Either inline their implementations or drop `info` as a redundant macro.

### 3.3 CLI alias cleanup (`cli.py:24-28`)

`repeat`, `reattach`, `refresh-creds` are aliases layered on canonical names. Pick one of:

- Promote aliases to canonical (drop the long forms `refresh-credentials` etc).
- Drop the aliases entirely.

Don't keep both. Document the rename in `CHANGELOG.md`.

## Phase 4: Delete Legacy Code (Next Release)

After the Phase 1-3 release ships and users have had one cycle to upgrade, remove the legacy fallback paths. Assume no sandboxes with `workspace_path == ""` remain; document "destroy and recreate any sandbox created before v0.XX" in the release notes.

### 4.1 Delete `git_worktree.py`

- Move `cleanup_sandbox_branch_repo()` (git_worktree.py:484-538, the new-layout helper) into `git.py`.
- Delete the rest of `git_worktree.py` entirely.
- Remove imports from `commands/destroy.py`.

### 4.2 Delete legacy helpers

| Symbol | File |
|--------|------|
| `ensure_bare_repo()` | `git.py` |
| `fetch_bare_branch()` | `git.py` |
| `_ensure_fetch_refspec()` | `git.py` |
| `repo_url_to_bare_path()` | `paths.py` |
| `get_worktrees_dir()` | `constants.py` |
| `path_worktree()` (if only legacy uses remain) | `paths.py` |

### 4.3 Simplify dual-dispatch code paths

- `commands/destroy.py`: drop the `workspace_path == ""` branch; delete the `remove_worktree` / `cleanup_sandbox_branch` calls.
- `commands/git_mode.py`: delete `_validate_legacy_layout_paths()` and the path-shape fallback; metadata becomes the sole source of truth.
- `commands/_helpers.py:auto_detect_sandbox()`: drop the legacy `worktrees/` fallback (lines 54-65).
- `paths.py:resolve_workspace_path()`: drop the `path_worktree(name)` fallback.
- `state.py`: drop the `workspace_path` read-compat shim added in Phase 2.3.

## Phase 5 (Optional): Minor Cleanups

Low-impact polish. Land individually as desired.

- **Remove `SetupError`** (`new_sbx.py:36`) — raised once, caught generically; use `RuntimeError`.
- **Simplify `NewDefaults` + `_apply_saved_new_defaults()`** (`new.py:38-100`) — replace the `explicit_params` set + nested `_saved()` closure with a plain loop over parameter names.
- **Reduce `write_sandbox_metadata` arg list** (`state.py:81-147`) — it takes 13+ kwargs. Have callers construct `SbxSandboxMetadata` directly and pass one object.
- **Inline or delete `SandboxPaths` NamedTuple** (`paths.py:34`, `derive_sandbox_paths()`) — used in ~3 places; most code goes through individual `path_*()` helpers.

## Critical Files

| File | Phase | Change |
|------|-------|--------|
| `tests/unit/test_destroy.py` | 1 | Add legacy regression test |
| `foundry_sandbox/sbx.py` | 2.1 | Host `_install_pip_requirements_sbx` |
| `foundry_sandbox/commands/_helpers.py` | 2.2 | Host `resolve_sandbox_name` |
| `foundry_sandbox/models.py`, `state.py`, `paths.py`, `_helpers.py` | 2.3 | Rename `workspace_path` → `host_worktree_path` |
| `foundry_sandbox/commands/new*.py` | 3.1 | Collapse 4 files → 2 |
| `foundry_sandbox/commands/attach.py`, `info.py` | 3.2 | Remove `ctx.invoke()` pattern |
| `foundry_sandbox/cli.py` | 3.3 | Alias cleanup |
| `foundry_sandbox/git_worktree.py` | 4.1 | Delete (move one helper out first) |
| `foundry_sandbox/git.py`, `paths.py`, `constants.py` | 4.2 | Delete legacy helpers |
| `foundry_sandbox/commands/destroy.py`, `git_mode.py` | 4.3 | Drop dual dispatch |

## Validation

After each phase:

1. `./scripts/ci-local.sh` — full local CI.
2. `python -m pytest tests/unit/ -x` — unit tests pass.
3. `python -m ruff check foundry_sandbox foundry-git-safety/foundry_git_safety` — lint clean.
4. `cast new --agent shell --skip-key-check --template none .` — smoke test.
5. `cast destroy <name>` — clean teardown (no orphan worktrees, no leaked branch).
6. `./tests/redteam-sandbox.sh` (Phase 4 only, inside a sandbox) — security regression check.

## Out of Scope

- Replacing the unified-proxy with Docker sbx's credential injection (sbx-analysis.md Option A) — deferred pending Docker Sandboxes GA.
- Adding Docker sbx templates, port publishing, resource limits — separate feature work.
- `cli.py` broader UX redesign — only the alias cleanup is in this plan.
