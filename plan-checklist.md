# Post-sbx cleanup round 2 — checklist

Actionable checklist for the phases described in `plan.md`. Check items as
they land. Run `./scripts/ci-local.sh` before each commit.

## Phase 1 — Doc correctness

### 1.1 Replace "bare repo" references

- [x] `docs/usage/commands.md:115` — rewrite "Clones repository as bare repo"
- [x] `docs/usage/commands.md:268` — rewrite "Cleans up sandbox branch from bare repo"
- [x] `docs/getting-started.md:81` — rewrite "Clone the repository as a bare repo"
- [x] `docs/operations.md:65` — update "bare repo branch"
- [x] `docs/operations.md:346` — update "stale lock files in the bare repo"
- [x] `docs/architecture.md:97,101,109` — fix worktree diagram annotations
- [x] `docs/architecture.md:192` — update `repos/ (bare repos)` label
- [x] `docs/architecture.md:203,245,343` — update narrative and diagrams
- [x] `docs/adr/008-sbx-migration.md:56` — revise "bare repos + worktrees" line

### 1.2 Fix README.md drift

- [x] `README.md:50` — replace `cast repeat` with `cast new --last`
- [x] `README.md:130` — fix or remove `docs/migration/0.20-to-0.21.md` link

### 1.3 Sync `cast new` docs with actual flags

- [x] `docs/usage/commands.md` — add `--template <tag>` row to options table

### 1.4 Orphan doc file

- [x] `docs/security/audit-5.6.md` — already indexed from `docs/README.md` and `docs/operations.md`; no action needed

## Phase 2 — User-visible consistency

### 2.1 Unify "microVM" vs "sandbox" wording

- [ ] `foundry_sandbox/commands/destroy.py:154` — change to `"  - Sandbox (sbx rm)"`
- [ ] `foundry_sandbox/cli.py:111` — update group docstring
- [ ] `pyproject.toml:8` — update package description
- [ ] `pyproject.toml:15` — swap `"docker"` for `"sbx"` in keywords

### 2.2 Trim migration-era docstring breadcrumbs

- [ ] `foundry_sandbox/commands/stop.py:3`
- [ ] `foundry_sandbox/commands/new_setup.py:3`
- [ ] `foundry_sandbox/models.py:9`
- [ ] `foundry_sandbox/commands/refresh_creds.py:4`
- [ ] `foundry_sandbox/constants.py:3`
- [ ] `foundry_sandbox/commands/help_cmd.py:3`
- [ ] `foundry_sandbox/utils.py:3`

### 2.3 Collapse dead branches in `install.sh`

- [ ] Delete `install.sh:200-203` (source `lib/api_keys.sh` branch)
- [ ] Delete `install.sh:282-284` (probe for `check_api_keys_with_prompt`)
- [ ] Verify `install.sh` still runs end-to-end against a local checkout

## Phase 3 — Dead code removal

### 3.1 Unused symbols

- [ ] Delete `inspect_sandbox()` at `foundry_sandbox/state.py:211`
- [ ] Delete its test block in `tests/unit/test_state.py` (around line 281)
- [ ] Delete `log_step()` at `foundry_sandbox/utils.py:81`
- [ ] Delete `RED`, `BLUE`, `GREEN` at `foundry_sandbox/utils.py:28,30,31`
- [ ] Run `./scripts/ci-local.sh`

### 3.2 Dead tamper-event counter

- [ ] Decide: wire into `cast diagnose` or delete
- [ ] If wiring in: surface `get_tamper_event_fallback_count()` via `commands/diagnose.py`
- [ ] If deleting: remove counter, accessor, and `tests/unit/test_git_safety.py:955` test class

### 3.3 `SbxSandboxMetadata.backend` field

- [ ] Delete `backend: str = "sbx"` at `foundry_sandbox/models.py:13`
- [ ] Remove from any `model_dump` assertions in tests
- [ ] Confirm `load_sandbox_metadata` still loads old JSON (Pydantic ignores extra fields only if configured; may need `model_config = ConfigDict(extra="ignore")`)

### 3.4 Drop `SCRIPT_DIR` from `cast config`

- [ ] Remove `SCRIPT_DIR` constant at `foundry_sandbox/commands/config.py:20`
- [ ] Remove `script_dir` JSON field (`config.py:40`)
- [ ] Remove `SCRIPT_DIR` human row (`config.py:52`)
- [ ] Update `tests/unit/test_cli.py` assertions that check for the field

### 3.5 Hidden preset aliases

- [ ] Delete `@preset.command("rm", hidden=True)` at `preset.py:203`
- [ ] Delete `@preset.command("remove", hidden=True)` at `preset.py:210`
- [ ] Update `tests/unit/test_preset_command.py` if it exercises the aliases

## Phase 4 — `cast help` consolidation

- [ ] Decide: delete `help_cmd` or rewrite as a dispatch to `cli.main(["--help"])`
- [ ] If rewriting: update `foundry_sandbox/commands/help_cmd.py` to call Click
- [ ] Remove the hand-maintained HEREDOC in `help_cmd.py:11-60`
- [ ] Update `tests/unit/test_cli.py` help-command tests

## Phase 5 — Structural simplification

### 5.1 Consolidate `cast list` and `cast status`

- [ ] Extract `collect_sandbox_list()` helper into `foundry_sandbox/state.py`
- [ ] Refactor `commands/status.py:_collect_all_sandboxes` to call it
- [ ] Refactor `commands/list_cmd.py:_collect_sandbox_info` to call it
- [ ] Decide: remove `cast list` entirely, or keep as thin alias to `cast status`
- [ ] Update `commands.md` and CHANGELOG accordingly

### 5.2 Factor triple env-var write in `inject_git_wrapper`

- [ ] Build single `env_vars: dict[str, str]` in `git_safety.py:inject_git_wrapper`
- [ ] Extract `_emit_profile_d(sandbox_name, env_vars)`
- [ ] Extract `_emit_bashrc_block(sandbox_name, env_vars)`
- [ ] Extract `_emit_plain_env(sandbox_name, env_vars)`
- [ ] Verify wrapper reads env from `/var/lib/foundry/git-safety.env` unchanged (`assets/git-wrapper.sh:40-50`)
- [ ] Run integration test via `./scripts/ci-local.sh --all`

### 5.3 `destroy-all` should see orphaned registry entries

- [ ] In `commands/destroy_all.py:27`, union `sbx_ls()` names with `list_sandbox_names()` from `commands/_helpers.py`
- [ ] Add a test that exercises the orphan case
- [ ] Update `commands.md` description

### 5.4 Re-evaluate `git-mode` shim

- [ ] Run `git log --all --oneline -- foundry_sandbox/commands/git_mode.py` to find the shim's origin
- [ ] Confirm no real consumer (search `gh` source or issue tracker if uncertain)
- [ ] If removing: drop `[project.scripts]` entry in `pyproject.toml:47`
- [ ] If removing: drop `git_mode_shim` function at `git_mode.py:216`
- [ ] If keeping: document the rationale in the docstring

### 5.5 Command-name suggestions (optional)

- [ ] Evaluate `click-didyoumean` dependency weight
- [ ] If adopting: add to `pyproject.toml` deps and wire into `CastGroup`

## Phase 6 — Rename `claude-config/` (breaking, 0.22.x)

### 6.1 Symbol renames

- [ ] `foundry_sandbox/constants.py:51` — `get_claude_configs_dir` → `get_sandbox_configs_dir`
- [ ] `foundry_sandbox/paths.py:49` — `path_claude_config` → `path_sandbox_config`
- [ ] Update all callers: `commands/_helpers.py`, `state.py`, `commands/config.py`, `commands/destroy.py`, `commands/new.py`, `paths.py`
- [ ] Update `cast config` label `CLAUDE_CONFIGS_DIR` → `SANDBOX_CONFIGS_DIR` (both human + JSON)

### 6.2 On-disk migration

- [ ] Add one-shot rename `$SANDBOX_HOME/claude-config/` → `$SANDBOX_HOME/sandboxes/` on first run
- [ ] Create compatibility symlink for one minor release
- [ ] Update tests that hardcode `claude-config` paths

### 6.3 Release

- [ ] Add "Breaking" entry to `CHANGELOG.md`
- [ ] Add migration notes to release body (not a separate `docs/migration/` file — CHANGELOG + release notes only)
- [ ] Bump minor version in `pyproject.toml`
