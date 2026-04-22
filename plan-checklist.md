# Cleanup Plan Checklist

See `plan.md` for rationale and detail. Check items off as they land. Commit after each phase.

## Phase 1 — Delete unused functions

### `foundry_sandbox/api_keys.py`
- [ ] Delete `check_any_ai_key`
- [ ] Delete `has_gemini_key`
- [ ] Delete `has_codex_key`
- [ ] Delete `opencode_enabled`
- [ ] Delete `check_any_search_key`
- [ ] Delete `warn_claude_auth_conflict`
- [ ] Delete `get_optional_cli_warnings`
- [ ] Delete `get_cli_status`
- [ ] Delete `show_cli_status`
- [ ] Delete `get_missing_keys_warning`
- [ ] Delete `check_api_keys_status`
- [ ] Delete `export_gh_token`
- [ ] Delete `AI_PROVIDER_KEYS`
- [ ] Remove `CREDENTIAL_PROXY_PLACEHOLDER` / `CRED_PROXY_` filters from remaining functions

### `foundry_sandbox/validate.py`
- [ ] Delete `validate_ssh_mode`
- [ ] Delete `validate_environment`
- [ ] Delete `require_command`
- [ ] Delete `validate_git_remotes`

### `foundry_sandbox/sbx.py`
- [ ] Delete `sbx_ports_publish`
- [ ] Delete `sbx_ports_unpublish`
- [ ] Delete `sbx_template_load`
- [ ] Delete `sbx_policy_set_default`
- [ ] Delete `sbx_policy_allow`
- [ ] Delete `sbx_policy_deny`
- [ ] Delete `VALID_NETWORK_PROFILES`

### `foundry_sandbox/constants.py`
- [ ] Delete `CONTAINER_READY_ATTEMPTS`
- [ ] Delete `CONTAINER_READY_DELAY`
- [ ] Delete `TIMEOUT_PIP_INSTALL`
- [ ] Delete `get_sandbox_debug`
- [ ] Delete `get_sandbox_assume_yes`
- [ ] Delete `VALID_NETWORK_MODES`
- [ ] Delete `get_sandbox_network_mode`
- [ ] Delete `get_sandbox_sync_on_attach`
- [ ] Delete `get_sandbox_sync_ssh`
- [ ] Delete `get_sandbox_ssh_mode`
- [ ] Delete `get_sandbox_opencode_disable_npm_plugins`
- [ ] Delete `get_sandbox_opencode_plugin_dir`
- [ ] Delete `get_sandbox_opencode_prefetch_npm_plugins`
- [ ] Delete `get_sandbox_opencode_default_model`
- [ ] Delete `get_sandbox_tmux_scrollback`
- [ ] Delete `get_sandbox_tmux_mouse`

### `foundry_sandbox/paths.py`
- [ ] Delete `path_opencode_plugins_marker`
- [ ] Delete `resolve_ssh_agent_sock`
- [ ] Delete `path_claude_home`
- [ ] Delete `safe_remove` + `_rmtree_no_follow_symlinks`

### `foundry_sandbox/config.py`
- [ ] Delete `deep_merge`
- [ ] Delete `deep_merge_no_overwrite`
- [ ] Delete `json_escape`
- [ ] Delete `json_array_from_lines`

### `foundry_sandbox/utils.py`
- [ ] Delete `flag_enabled`
- [ ] Delete `generate_sandbox_id`
- [ ] Delete `environment_scope`

### `foundry_sandbox/git.py`
- [ ] Delete `branch_exists`

### Tests
- [ ] Remove `environment_scope` tests from `test_foundation.py`
- [ ] Remove `path_claude_home` tests from `test_foundation.py`
- [ ] Remove `safe_remove` tests from `test_foundation.py`
- [ ] Remove `get_sandbox_debug` / `get_sandbox_assume_yes` tests from `test_foundation.py`
- [ ] Remove `branch_exists` tests from `test_git.py`
- [ ] Remove tests in `test_sbx.py` for deleted `sbx_ports_*`, `sbx_template_load`, `sbx_policy_*` wrappers

### Verify
- [ ] `./scripts/ci-local.sh` passes
- [ ] `git commit -m "refactor: Phase 1 delete unused helpers"`

---

## Phase 2 — Delete obsolete files

- [ ] Delete `scripts/build-foundry-template.sh`
- [ ] Delete `config/allowlist.yaml`
- [ ] Delete `config/firewall-allowlist.txt`
- [ ] Delete `config/policy.yaml.example`
- [ ] Delete or archive `sbx-analysis.md`
- [ ] Grep for any remaining references to the deleted files
- [ ] Verify `./scripts/ci-local.sh` passes
- [ ] `git commit -m "refactor: Phase 2 delete obsolete configs and scripts"`

---

## Phase 3 — Drop `network_profile` field

### `foundry_sandbox/models.py`
- [ ] Remove `network_profile` from `SbxSandboxMetadata`
- [ ] Remove `network_profile` from `CastNewPreset`

### `foundry_sandbox/state.py`
- [ ] Remove `network_profile` param from `_build_command_line`
- [ ] Remove `network_profile` param from `_write_cast_new_json`
- [ ] Remove `network_profile` param from `save_last_cast_new`
- [ ] Remove `network_profile` param from `save_cast_preset`
- [ ] Remove `network_profile` from `_load_cast_new_json` fallback dict

### `foundry_sandbox/commands/preset.py`
- [ ] Remove `network_profile=metadata.get(...)` from `save` at line 143

### Tests
- [ ] Update `tests/unit/test_models.py` — drop `network_profile` assertions (lines ~37, 60, 70, 120, 161, 173, 200, etc.)
- [ ] Update `tests/unit/test_state.py` — drop `network_profile` from test metadata
- [ ] Update `tests/unit/test_preset_command.py:66` — drop `network_profile` from fixture

### Verify
- [ ] Existing metadata files with `network_profile` still load (forward-compat via Pydantic `extra` handling)
- [ ] `./scripts/ci-local.sh` passes
- [ ] `git commit -m "refactor: Phase 3 drop vestigial network_profile field"`

---

## Phase 4 — User-facing fixes

- [ ] `foundry_sandbox/version_check.py:158` — replace `cast upgrade` with `pip install -U foundry-sandbox`
- [ ] `foundry_sandbox/cli.py:111` — docstring "Docker sandbox manager" → "microVM sandbox manager"
- [ ] `foundry_sandbox/commands/destroy.py:154` — "Sandbox container (sbx rm)" → "Sandbox microVM (sbx rm)"
- [ ] `foundry_sandbox/commands/help_cmd.py:38` — `--copy` help: "into container" → "into sandbox" (until Phase 6 deletes this file)
- [ ] `foundry_sandbox/commands/new.py:300` — `--copy` help: "into container" → "into sandbox"
- [ ] Verify `./scripts/ci-local.sh` passes
- [ ] `git commit -m "fix: Phase 4 correct post-sbx user-facing wording and upgrade hint"`

---

## Phase 5 — Drop `_sbx` naming suffix + fold `tui.py`

### Code renames
- [ ] `foundry_sandbox/commands/new_sbx.py` → `foundry_sandbox/commands/new_setup.py`
- [ ] Update import in `foundry_sandbox/commands/new.py:24`
- [ ] `foundry_sandbox/assets/git-wrapper-sbx.sh` → `foundry_sandbox/assets/git-wrapper.sh`
- [ ] Update reference in `foundry_sandbox/git_safety.py::_wrapper_script_path` (line 262)
- [ ] Rename `sbx.py::install_pip_requirements_sbx` → `install_pip_requirements`
- [ ] Update callers in `commands/new_setup.py` and `commands/start.py`

### Test renames
- [ ] `tests/unit/test_attach_sbx.py` → `test_attach.py`
- [ ] `tests/unit/test_chaos_sbx.py` → `test_chaos.py`
- [ ] `tests/unit/test_destroy_sbx.py` → `test_destroy.py`
- [ ] `tests/unit/test_list_sbx.py` → `test_list.py`
- [ ] `tests/unit/test_new_sbx.py` → `test_new.py`
- [ ] `tests/unit/test_refresh_creds_sbx.py` → `test_refresh_creds.py`
- [ ] `tests/unit/test_sbx_identity.py` → `test_identity.py`
- [ ] `tests/unit/test_start_sbx.py` → `test_start.py`
- [ ] `tests/unit/test_status_sbx.py` → `test_status.py`
- [ ] `tests/unit/test_stop_sbx.py` → `test_stop.py`
- [ ] Keep `tests/unit/test_sbx.py` (tests the `sbx.py` wrapper module)

### Fold `tui.py`
- [ ] Move `_is_noninteractive()` from `foundry_sandbox/tui.py` into `foundry_sandbox/utils.py`
- [ ] Update import in `foundry_sandbox/ide.py:17`
- [ ] Delete `foundry_sandbox/tui.py`

### Verify
- [ ] `./scripts/ci-local.sh` passes
- [ ] `git commit -m "refactor: Phase 5 drop _sbx naming suffix and fold tui.py"`

---

## Phase 6 — Command consolidation

### Delete `cast help`
- [ ] Delete `foundry_sandbox/commands/help_cmd.py`
- [ ] Remove `"help"` entry from `_LAZY_COMMANDS` in `foundry_sandbox/cli.py:26`
- [ ] Remove `test_cli.py` assertions that reference `cast help` (if any)
- [ ] Update `docs/usage/commands.md` if it mentions `cast help`

### Merge `list` + `status` overlap
- [ ] Extract shared `(sbx_ls + metadata merge)` logic to `state.py::list_sandboxes_with_status()` (or similar)
- [ ] Update `commands/list_cmd.py` to use the shared function
- [ ] Update `commands/status.py` to use the shared function
- [ ] Make `cast status` (no args) either redirect to `cast list` or require a name (choose one — recommend requiring a name)
- [ ] Update help strings on both commands

### Verify
- [ ] `./scripts/ci-local.sh` passes
- [ ] Manual check: `cast --help`, `cast list`, `cast status` (and `cast status <name>`) all work as expected
- [ ] `git commit -m "refactor: Phase 6 consolidate status/list and drop custom help"`

---

## Phase 7 — Docs refresh

### `docs/architecture.md`
- [ ] Rewrite "Host State Layout" section (lines ~232-295) — correct worktree path to `<repo_root>/.sbx/<name>-worktrees/<branch>/` and HMAC location to `/run/foundry/hmac-secret`
- [ ] Remove `sbx_policy_*` and `sbx_template_load` rows from "Supported Operations" table (lines ~127-132)
- [ ] Remove/correct `GH_TOKEN` placeholder claim at line ~164
- [ ] Remove ASCII worktree diagram at lines 85-103 (or update to reflect new layout)

### `docs/operations.md`
- [ ] Fix `ls -la ~/.sandboxes/worktrees/<name>` at line 297

### `AGENTS.md` (repo root)
- [ ] Align "Development" section structure with `CLAUDE.md`'s version

### ADR supersession banners
Add to each of these ADRs, at the top:
```markdown
> **Status:** Superseded by [ADR-008](008-sbx-migration.md). Kept for historical context.
```
- [ ] `docs/adr/001-consolidation.md`
- [ ] `docs/adr/002-container-identity.md`
- [ ] `docs/adr/003-policy-engine.md`
- [ ] `docs/adr/004-dns-integration.md`
- [ ] `docs/adr/005-failure-modes.md`
- [ ] `docs/adr/006-allowlist-layering.md`
- [ ] `docs/adr/007-api-gateways.md`

### `docs/usage/commands.md`
- [ ] Re-read against current flag set; fix any drift
- [ ] Remove `cast help` reference (Phase 6)

### Verify
- [ ] `./scripts/ci-local.sh` passes
- [ ] `git commit -m "docs: Phase 7 refresh architecture, operations, and ADR supersession notes"`

---

## Phase 8 (optional) — `new.py` refactor

### Extract `foundry_sandbox/repo.py`
- [ ] Create `foundry_sandbox/repo.py`
- [ ] Move `_resolve_repo_input` → `resolve_repo_input`
- [ ] Move `_branch_exists_on_remote` → `branch_exists_on_remote`
- [ ] Move `_detect_remote_default_branch` → `detect_remote_default_branch`
- [ ] Move `_generate_branch_name` → `generate_branch_name`
- [ ] Move `_ensure_repo_root` → `ensure_repo_root`
- [ ] Add `git_query(repo_root, *args) -> str | None` to `git.py`
- [ ] Switch `repo.py` helpers to use `git_query` instead of inline subprocess.run

### Simplify defaults merge
- [ ] Replace `NewDefaults` + `_STR_FIELDS` + `_BOOL_FIELDS` + `_apply_saved_new_defaults` with a `CastNewPreset.model_copy(update=...)` pattern
- [ ] Delete the dataclass and tables; target ~15 lines total

### Extract name claim loop
- [ ] Extract `new.py:470-493` to `_claim_unique_name(base_name, allow_increment: bool) -> tuple[str, str]`
- [ ] Home it in `state.py` or `paths.py`

### Verify
- [ ] `./scripts/ci-local.sh` passes
- [ ] `git commit -m "refactor: Phase 8 extract repo.py and simplify new.py defaults"`

---

## Phase 9 (optional) — `git_safety.py` split

- [ ] Create `foundry_sandbox/git_safety/` package directory
- [ ] Split into `server.py`, `hmac.py`, `wrapper.py`, `template.py`, `provisioning.py`, `tamper.py`
- [ ] Write `__init__.py` that re-exports all names callers currently import
- [ ] Delete original `foundry_sandbox/git_safety.py`
- [ ] Run full test suite; fix any import or circular-import issues
- [ ] Verify `./scripts/ci-local.sh` passes
- [ ] `git commit -m "refactor: Phase 9 split git_safety into submodules"`

---

## Done-done

- [ ] All phases complete
- [ ] `CHANGELOG.md` updated with user-visible changes (Phase 4 wording, Phase 6 command behavior)
- [ ] Delete `plan.md` and `plan-checklist.md` (or move to `docs/archive/`)
