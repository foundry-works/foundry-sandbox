# Cleanup Plan: post-sbx-migration residue

**Goal:** finish the sbx migration cleanup. Remove vestigial docker-era code, drop naming that made sense when two backends coexisted, fix one user-facing bug, and refresh docs. Each phase is independently committable and independently revertable.

**Out of scope:** behavior changes, new features, and any changes to the git safety package (`foundry-git-safety/`). The sbx backend continues to be the only backend.

**Verification per phase:**
- `./scripts/ci-local.sh` passes
- `cast --help`, `cast new --help`, `cast list`, `cast status` still render
- Existing sandbox metadata (`SbxSandboxMetadata`) deserializes as before (schema-compatible changes only)

---

## Phase 1 — Delete unused functions

Pure deletions of functions with zero non-test callers. Nothing here changes CLI behavior.

### `foundry_sandbox/api_keys.py`
Keep: `check_claude_key_required`, `has_opencode_key`, `has_zai_key` (the only imports).
Delete: `check_any_ai_key`, `has_gemini_key`, `has_codex_key`, `opencode_enabled`, `check_any_search_key`, `warn_claude_auth_conflict`, `get_optional_cli_warnings`, `get_cli_status`, `show_cli_status`, `get_missing_keys_warning`, `check_api_keys_status`, `export_gh_token`, `AI_PROVIDER_KEYS`.
Also remove the `CREDENTIAL_PROXY_PLACEHOLDER` / `CRED_PROXY_` prefix filters in `has_gemini_key` and `has_zai_key` — those placeholders don't exist under sbx.

### `foundry_sandbox/validate.py`
Delete: `validate_ssh_mode`, `validate_environment`, `require_command`, `validate_git_remotes`, `_SSH_HOST_PATTERN` guard usage only in deleted funcs (keep if still referenced).

### `foundry_sandbox/sbx.py`
Delete: `sbx_ports_publish`, `sbx_ports_unpublish`, `sbx_template_load`, `sbx_policy_set_default`, `sbx_policy_allow`, `sbx_policy_deny`, `VALID_NETWORK_PROFILES`.

### `foundry_sandbox/constants.py`
Delete: `CONTAINER_READY_ATTEMPTS`, `CONTAINER_READY_DELAY`, `TIMEOUT_PIP_INSTALL`, `get_sandbox_debug`, `get_sandbox_assume_yes`, `VALID_NETWORK_MODES`, `get_sandbox_network_mode`, `get_sandbox_sync_on_attach`, `get_sandbox_sync_ssh`, `get_sandbox_ssh_mode`, `get_sandbox_opencode_disable_npm_plugins`, `get_sandbox_opencode_plugin_dir`, `get_sandbox_opencode_prefetch_npm_plugins`, `get_sandbox_opencode_default_model`, `get_sandbox_tmux_scrollback`, `get_sandbox_tmux_mouse`.
Keep: `get_sandbox_home`, `get_repos_dir`, `get_claude_configs_dir`, `get_sandbox_verbose`, `SANDBOX_NAME_MAX_LENGTH`, `TIMEOUT_GIT_TRANSFER`, `TIMEOUT_GIT_QUERY`, `TIMEOUT_LOCAL_CMD`.

### `foundry_sandbox/paths.py`
Delete: `path_opencode_plugins_marker`, `resolve_ssh_agent_sock`, `path_claude_home` (only tests use it), `safe_remove` (only tests use it).

### `foundry_sandbox/config.py`
Delete: `deep_merge`, `deep_merge_no_overwrite`, `json_escape`, `json_array_from_lines`.
Keep: `load_json`, `write_json`.

### `foundry_sandbox/utils.py`
Delete: `flag_enabled`, `generate_sandbox_id`, `environment_scope` (only tests).

### `foundry_sandbox/git.py`
Delete: `branch_exists` (only tests).

### Test cleanup
Delete tests that exclusively exercise deleted functions: sections of `tests/unit/test_foundation.py` covering `environment_scope`, `path_claude_home`, `safe_remove`, `get_sandbox_debug`, `get_sandbox_assume_yes`; `test_git.py` sections for `branch_exists`; anything in `test_sbx.py` testing the deleted `sbx_*` wrappers.

**Commit:** `refactor: Phase 1 delete unused helpers`

---

## Phase 2 — Delete obsolete files

Full-file deletes. No code references remain.

### Scripts
- `scripts/build-foundry-template.sh` (116 lines) — duplicates `ensure_foundry_template()` in `git_safety.py:513`; the Python version is the one `cast new` invokes.

### Config
- `config/allowlist.yaml` (259 lines) — unified-proxy allowlist; sbx network policy replaces it. No code references.
- `config/firewall-allowlist.txt` — same story.
- `config/policy.yaml.example` — legacy proxy policy example.
Keep: `config/user-services.yaml.example`, `config/push-file-restrictions.yaml` (both still referenced).

### Repo root
- `sbx-analysis.md` (832 lines) — pre-migration analysis doc from 2026-04-18. The migration it analyzed is now done (ADR-008). Either delete or move to `docs/archive/`.

**Commit:** `refactor: Phase 2 delete obsolete configs and scripts`

---

## Phase 3 — Drop vestigial `network_profile`

This field is written, read, round-tripped through presets and `--last`, serialized in metadata, and tested — but never applied to sbx. `cast new` has no `--network` flag, and the `sbx_policy_*` wrappers (being removed in Phase 1) were never called from cast.

### Changes
- `foundry_sandbox/models.py`: remove `network_profile` from `SbxSandboxMetadata` and `CastNewPreset`.
- `foundry_sandbox/state.py`: drop `network_profile` param from `_build_command_line`, `_write_cast_new_json`, `save_last_cast_new`, `save_cast_preset`, and `_load_cast_new_json` fallback dict.
- `foundry_sandbox/commands/preset.py:143`: drop `network_profile=metadata.get(...)` from `save`.
- Tests: update `test_models.py`, `test_state.py`, `test_preset_command.py` — remove `network_profile` assertions.

### Backward-compat
Metadata written by older versions will still have `network_profile`; Pydantic will ignore unknown fields (the `extra_forbidden` fallback in `_load_metadata_from_json` already tolerates this). No migration needed.

**Commit:** `refactor: Phase 3 drop vestigial network_profile field`

---

## Phase 4 — User-facing fixes

Small but visible correctness fixes.

### `foundry_sandbox/version_check.py:158`
Currently prints `Run cast upgrade to update`. `cast upgrade` was removed in ADR-008. Change to `Run pip install -U foundry-sandbox to update`.

### Docker-era wording
- `foundry_sandbox/cli.py:111`: docstring `"""Cast - Docker sandbox manager for Claude Code."""` → `"""Cast - microVM sandbox manager for Claude Code."""`.
- `foundry_sandbox/commands/destroy.py:154`: `"Sandbox container (sbx rm)"` → `"Sandbox microVM (sbx rm)"`.
- `foundry_sandbox/commands/help_cmd.py:38`: `--copy, -c src:dst ... Copy host path into container` → `Copy host path into sandbox`.
- Wording in `--copy` help in `new.py:300`.

**Commit:** `fix: Phase 4 correct post-sbx user-facing wording and upgrade hint`

---

## Phase 5 — Naming cleanup: drop `_sbx` suffix

Historical suffix from when both docker-compose and sbx backends coexisted. There is no other backend now; the suffix is noise.

### Code renames
- `foundry_sandbox/commands/new_sbx.py` → `foundry_sandbox/commands/new_setup.py` (intent: "parameter resolution in `new.py`, setup logic here").
- `foundry_sandbox/assets/git-wrapper-sbx.sh` → `foundry_sandbox/assets/git-wrapper.sh`.
- `foundry_sandbox/sbx.py::install_pip_requirements_sbx` → `install_pip_requirements`.

### Test renames
- `tests/unit/test_attach_sbx.py` → `test_attach.py`
- `tests/unit/test_chaos_sbx.py` → `test_chaos.py`
- `tests/unit/test_destroy_sbx.py` → `test_destroy.py`
- `tests/unit/test_list_sbx.py` → `test_list.py`
- `tests/unit/test_new_sbx.py` → `test_new.py`
- `tests/unit/test_refresh_creds_sbx.py` → `test_refresh_creds.py`
- `tests/unit/test_sbx_identity.py` → `test_identity.py`
- `tests/unit/test_start_sbx.py` → `test_start.py`
- `tests/unit/test_status_sbx.py` → `test_status.py`
- `tests/unit/test_stop_sbx.py` → `test_stop.py`

Keep `test_sbx.py` (tests the sbx CLI wrapper module) and `test_new_sbx.py` test contents but rename imports/paths.

### Fold `tui.py`
17-line file containing only `_is_noninteractive()`. Name is misleading (no TUI). Move the function into `utils.py`, update the one import in `ide.py:17`, delete `tui.py`.

### `pyproject.toml::hatch.build.targets.wheel.artifacts`
Asset pattern is `foundry_sandbox/assets/*.sh` — rename alone suffices.

**Commit:** `refactor: Phase 5 drop _sbx naming suffix and fold tui.py`

---

## Phase 6 — Command consolidation

Remove duplication between commands and with Click's built-in help.

### Merge `list` and `status`
Both scan `sbx_ls()` + metadata; both support `--json`; `list` adds a wrapper-drift marker; `status NAME` shows detail. Consolidate:
- **Keep `cast list`** as the all-sandbox view (with drift marker, as today).
- **Keep `cast status NAME`** as the single-sandbox detail view.
- **Drop `cast status` with no argument** — redirect to `cast list` with a one-line notice, or just make `status` require a name.
- Extract the shared `(sbx_ls + metadata merge)` loop into `foundry_sandbox/state.py::list_sandboxes_with_status()` or similar.

### Delete `cast help`
`commands/help_cmd.py` hand-maintains a 50-line help string that duplicates Click's auto-generated `--help`. Delete the file, drop from `_LAZY_COMMANDS`, and rely on `cast --help`. Update any docs that say `cast help`.

### Delete `commands/tui.py`
Already covered in Phase 5.

**Commit:** `refactor: Phase 6 consolidate status/list and drop custom help`

---

## Phase 7 — Docs refresh

### Architecture paths
- `docs/architecture.md:95-102, 241-262`: worktree layout shows `~/.sandboxes/worktrees/<name>/` with internal `.foundry/`. Actual path is `<repo_root>/.sbx/<name>-worktrees/<branch>/`. HMAC secret lives at `/run/foundry/hmac-secret` (tmpfs) + `/var/lib/foundry/hmac-secret` (persistent), not in the worktree. Rewrite the Host State Layout section.
- `docs/architecture.md:127-132`: the `sbx_policy_*` and `sbx_template_load` rows describe functions being removed in Phase 1. Delete those rows from the "Supported Operations" table.
- `docs/architecture.md:164`: `GH_TOKEN` placeholder claim is wrong — delete.

### Operations
- `docs/operations.md:297`: `ls -la ~/.sandboxes/worktrees/<name>` → `ls -la <repo_root>/.sbx/<name>-worktrees/`.

### Top-level guidance
- `AGENTS.md` (repo root) structure description is out of sync with `CLAUDE.md`. Align the "Development" section on `CLAUDE.md`'s version.

### Superseded ADRs
ADRs 001, 002, 003, 004, 005, 006, 007 are all superseded by 008. Add a single-line status banner at the top of each:
```markdown
> **Status:** Superseded by [ADR-008](008-sbx-migration.md). Kept for historical context.
```

### Help text
`commands/help_cmd.py` deleted in Phase 6 — no more maintenance burden here. But docs in `docs/usage/commands.md` should still be reviewed for accuracy against current flags.

**Commit:** `docs: Phase 7 refresh architecture, operations, and ADR supersession notes`

---

## Phase 8 (optional) — `new.py` refactor

`foundry_sandbox/commands/new.py` is 576 lines and mixes three concerns. This phase extracts helpers; it changes structure but not behavior. Skip if appetite is low — everything above stands on its own.

### Extract `foundry_sandbox/repo.py`
Move these pure helpers (currently in `new.py`) into a new module:
- `_resolve_repo_input` → `resolve_repo_input`
- `_branch_exists_on_remote` → `branch_exists_on_remote`
- `_detect_remote_default_branch` → `detect_remote_default_branch`
- `_generate_branch_name` → `generate_branch_name`
- `_ensure_repo_root` → `ensure_repo_root`

Add a `git_query(repo_root, *args) -> str | None` helper to `git.py` and use it inside these functions so they stop doing `subprocess.run(["git", "-C", ...])` inline.

### Simplify saved-defaults merge
`_apply_saved_new_defaults` (lines 68-109) + `_STR_FIELDS`/`_BOOL_FIELDS` tables + `NewDefaults` dataclass reimplement a `caller > saved > default` merge. Replace with a `CastNewPreset(...).model_copy(update={...})` pattern, driven from `CastNewPreset.model_fields`. Target: ~40 lines → ~15.

### Extract name claim loop
`new.py:470-493` is a `for...else` with nested collision handling. Extract to `_claim_unique_name(base_name, allow_increment: bool) -> (name, branch)` in `state.py` or `paths.py`.

**Commit:** `refactor: Phase 8 extract repo.py and simplify new.py defaults`

---

## Phase 9 (optional) — `git_safety.py` split

927 lines mixing server lifecycle, HMAC, registration, wrapper injection, template build, tamper events, connectivity check, and provisioning orchestration. Split into a package:

```
foundry_sandbox/git_safety/
├── __init__.py          # re-exports for backward compat
├── server.py            # start/stop/status/health/readiness
├── hmac.py              # generate_hmac_secret, write_hmac_* 
├── wrapper.py           # inject_git_wrapper, verify_*, compute_wrapper_checksum
├── template.py          # ensure_foundry_template, is_template_stale, digest
├── provisioning.py      # provision_git_safety, repair_git_safety, ProvisioningResult
└── tamper.py            # emit_wrapper_tamper_event
```

`__init__.py` re-exports everything other modules import, so `from foundry_sandbox.git_safety import ...` continues to work. This is a risky-ish refactor because the current module is tightly tested; do last.

**Commit:** `refactor: Phase 9 split git_safety into submodules`

---

## Risk summary

| Phase | Risk | Reversibility |
|---|---|---|
| 1 Delete unused funcs | Low (tests catch) | `git revert` |
| 2 Delete obsolete files | Low | `git revert` |
| 3 Drop `network_profile` | Low (metadata is forward-compat) | `git revert` + re-add field |
| 4 User-facing wording | Trivial | `git revert` |
| 5 Renames | Medium (import churn) | `git revert` |
| 6 Command consolidation | Medium (changes UX) | `git revert` + restore command |
| 7 Docs | None | `git revert` |
| 8 `new.py` refactor | Medium-high (behavioral paths) | Careful `git revert` |
| 9 `git_safety` split | High (wide import surface) | Full rollback of phase |

## Estimated impact

- Phases 1–7 complete: ~1,500 lines of Python deleted, ~325 lines of config deleted, ~832 lines of analysis doc removed or archived, one user-facing bug fixed, doc accuracy restored. Zero behavior changes visible to users other than Phase 4's wording fixes and Phase 6's help/status UX.
- Phases 8–9 optional: further ~200 line reduction in `new.py`, ~900 line reshuffle of `git_safety.py` for maintainability.
