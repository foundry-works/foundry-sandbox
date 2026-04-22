# Post-sbx cleanup — round 2

Follow-up work identified after the five-phase post-migration cleanup. Evidence
for every item is linked with `file:line` references so each phase can be
executed without re-doing the audit.

Six phases, ordered by reversibility and blast radius.

---

## Phase 1 — Doc correctness

Docs are currently the least-reliable source of truth in the repo. They
describe the pre-sbx bare-repo architecture and have broken links/commands.
This phase is pure documentation; no runtime risk.

### 1.1 Replace "bare repo" references

`ensure_repo_checkout` at `foundry_sandbox/git.py:180` does a regular clone
(`git clone --branch <branch> <url> <path>`), not `git clone --bare`.
`foundry_sandbox/paths.py:173` explicitly documents this. Multiple docs still
claim bare-repo behavior:

- `docs/usage/commands.md:115` ("Clones repository as bare repo")
- `docs/usage/commands.md:268` ("Cleans up sandbox branch from bare repo")
- `docs/getting-started.md:81`
- `docs/operations.md:65`, `docs/operations.md:346`
- `docs/architecture.md:97`, `:101`, `:109`, `:192`, `:203`, `:245`, `:343`
  (including the ASCII diagram labels pointing at `repos/ (bare repos)`)
- `docs/adr/008-sbx-migration.md:56` ("Still uses bare repos + worktrees")

Replace with the actual behavior: sbx owns the worktree layout under
`<repo_root>/.sbx/<sandbox-name>-worktrees/<branch>/`; cast only ensures a
regular working checkout exists.

### 1.2 Fix README.md drift

- `README.md:50` advertises `cast repeat`. Alias was removed (see
  `CHANGELOG.md:20`). Replace with `cast new --last`.
- `README.md:130` links `docs/migration/0.20-to-0.21.md`. File was deleted
  per `CHANGELOG.md:23`; the directory no longer exists. Either link to the
  release branch that still hosts the guide or drop the row from the
  documentation table.

### 1.3 Sync `cast new` docs with actual flags

`docs/usage/commands.md` options table (around `:43`) is missing
`--template <tag>` (defined in `foundry_sandbox/commands/new.py:309`). Add it
with the same default/behavior the Click option declares.

### 1.4 Orphan doc file

`docs/security/audit-5.6.md` is not referenced from `docs/README.md` or the
main `README.md`. Either index it or move it under `docs/adr/` if it records
a decision.

---

## Phase 2 — User-visible consistency

Small code changes to make the CLI speak with one voice. All changes are
local to a single file each.

### 2.1 Unify "microVM" vs "sandbox" wording

Pick one term. "sandbox" is already the dominant choice in CLI output and
docstrings. Touch points:

- `foundry_sandbox/commands/destroy.py:154` — confirmation line reads
  `"  - Sandbox microVM (sbx rm)"`. Change to `"  - Sandbox (sbx rm)"`.
- `foundry_sandbox/cli.py:111` — group docstring `"""Cast - microVM sandbox
  manager for Claude Code."""` is shown in `--help`. Change to `"""Cast -
  sandbox manager for Claude Code."""`.
- `pyproject.toml:8` — `description = "MicroVM-based sandbox environment..."`.
  Match the chosen wording.
- `pyproject.toml:15` — `keywords` still lists `"docker"`. Replace with `"sbx"`.

### 2.2 Trim migration-era docstring breadcrumbs

Each of these docstrings describes what the module *replaces* rather than
what it does. Rewrite each as a one-line description of the current
behavior:

- `foundry_sandbox/commands/stop.py:3` — drop `"instead of docker-compose"`.
- `foundry_sandbox/commands/new_setup.py:3` — rewrite without the "replaces
  new_setup.py" backward reference.
- `foundry_sandbox/models.py:9` — drop `"Replaces the docker-compose-based
  SandboxMetadata."`.
- `foundry_sandbox/commands/refresh_creds.py:4` — drop `"No more
  direct/isolation mode distinction."`.
- `foundry_sandbox/constants.py:3` — drop the `"replaces lib/constants.sh"`
  reference.
- `foundry_sandbox/commands/help_cmd.py:3` — drop `"Migrated from
  commands/help.sh (60 lines)."`.
- `foundry_sandbox/utils.py:3` — drop the `"replace the shell scripts
  lib/utils.sh, lib/format.sh, and lib/runtime.sh."` reference.

### 2.3 Collapse dead branches in `install.sh`

The script tries to source `lib/api_keys.sh` at `install.sh:200-203` and
probes for `check_api_keys_with_prompt` at `install.sh:282-284`. `lib/` no
longer exists in the repo; only the inline `_check_api_keys_inline` path at
`install.sh:207` ever runs. Delete the two dead branches.

---

## Phase 3 — Dead code removal

Safe deletions once Phases 1–2 land. Each removal should be verified by
running `./scripts/ci-local.sh`.

### 3.1 Unused symbols

- `foundry_sandbox/state.py:211` — `inspect_sandbox()` has no non-test
  callers (`grep -R inspect_sandbox foundry_sandbox/` shows only the
  definition). Delete the function and its test(s) in
  `tests/unit/test_state.py`.
- `foundry_sandbox/utils.py:81` — `log_step()` has zero callers anywhere.
  Delete.
- `foundry_sandbox/utils.py:28,30,31` — `RED`, `BLUE`, `GREEN` ANSI
  constants are unused (only `YELLOW`, `BOLD`, `RESET` are referenced).
  Delete the three constants.

### 3.2 Dead tamper-event counter

`foundry_sandbox/git_safety.py:626` defines the module-level
`_tamper_event_fallback_count`; `git_safety.py:697` exposes
`get_tamper_event_fallback_count()`. Only tests read it. Either:

- wire it into `cast diagnose` (`commands/diagnose.py`) so it surfaces
  alongside the server-side counter, **or**
- delete the counter, the accessor, and the test in
  `tests/unit/test_git_safety.py:955`.

Recommendation: wire into `diagnose` — it's the observability story the
counter was created for.

### 3.3 `SbxSandboxMetadata.backend` field

`foundry_sandbox/models.py:13` declares `backend: str = "sbx"`. No non-test
code reads it. Two options:

- Delete the field (simplest; there is only one backend).
- Promote to `backend: Literal["sbx-v1"]` and gate future schema migrations
  on it.

Recommendation: delete now; add back as a schema-version sentinel when a
real migration is queued.

### 3.4 Drop `SCRIPT_DIR` from `cast config`

`foundry_sandbox/commands/config.py:20` computes
`SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent` and prints it
in both human and JSON output. In pipx or wheel installs this resolves
inside site-packages and conveys nothing. Remove from:

- `commands/config.py:30` (variable definition)
- `commands/config.py:40` (JSON field `script_dir`)
- `commands/config.py:52` (human row `SCRIPT_DIR`)

Update any asserts in `tests/unit/test_cli.py` / wherever it's tested.

### 3.5 Hidden preset aliases

`foundry_sandbox/commands/preset.py:203,210` define hidden `rm` and
`remove` aliases for `delete`. If the project is trending toward fewer
aliases (per `CHANGELOG.md:20` which removed `repeat`/`reattach`), remove
these too. Otherwise, make them visible so help stays honest.

Recommendation: remove both. The canonical verb is `delete`.

---

## Phase 4 — `cast help` consolidation

`foundry_sandbox/commands/help_cmd.py` is a 60-line HEREDOC enumerating
commands and flags. It already drifts from the real Click tree: no mention
of `--template`, `watchdog`, or `diagnose`. Click generates correct help
from the command definitions.

Options, in order of preference:

1. Delete `help_cmd.py`, drop it from `_LAZY_COMMANDS` in `cli.py:26`, and
   rely on `cast --help` / `cast <subcommand> --help`.
2. Make `cast help` dispatch to `cli.main(["--help"])` so it stays in
   sync but the command name is preserved.

Recommendation: option 2 — users already type `cast help`, keep the verb
but let Click generate the content.

---

## Phase 5 — Structural simplification

Higher-impact refactors. Each is a self-contained change but touches
multiple files.

### 5.1 Consolidate `cast list` and `cast status`

`commands/list_cmd.py:_collect_sandbox_info` and
`commands/status.py:_collect_all_sandboxes` differ by one field
(`wrapper_checksum`). `cast list` and `cast status` without a name
argument produce near-identical output.

Plan:

- Extract one `collect_sandbox_list()` helper into `state.py`.
- Make `cast status [name]` list-when-bare, detail-when-named (it almost
  is today).
- Either remove `cast list` or keep it as a thin alias that calls
  `cast status` with no args. Preference: remove; it's one less command to
  explain.

### 5.2 Factor the triple env-var write in `inject_git_wrapper`

`foundry_sandbox/git_safety.py:339-396` writes the same six env vars to
three destinations (`/etc/profile.d/foundry-git-safety.sh`,
`/etc/bash.bashrc` block, `/var/lib/foundry/git-safety.env`) via three
base64-encoded `sbx exec` calls. Changes must be made in all three places.

Plan:

- Extract a single `dict[str, str]` of env vars near the top of
  `inject_git_wrapper`.
- Add three small helpers — `_emit_profile_d`, `_emit_bashrc_block`,
  `_emit_plain_env` — that each consume the dict.
- Keep the three destinations (they serve distinct shell modes, as the
  existing comments explain); only the source of truth consolidates.

### 5.3 `destroy-all` should see orphaned registry entries

`commands/destroy_all.py:27` enumerates sandboxes only via `sbx_ls()`. The
`claude-config/` registry is treated as authoritative elsewhere
(`commands/_helpers.py:88`, `state.py:195`). Sandboxes that exist in the
registry but not in sbx (the exact drift `commands/start.py:151` warns
about) can't be cleaned up via `destroy-all`.

Plan:

- Union `sbx_ls()` names with `list_sandbox_names()` from `_helpers.py`.
- Pass the unioned names to `destroy_impl`, which is already best-effort
  and handles missing sbx entries gracefully.

### 5.4 Re-evaluate `git-mode` shim entry point

`pyproject.toml:47` installs a second binary `git-mode` whose
implementation is `git_mode_shim()` at
`foundry_sandbox/commands/git_mode.py:216`. The rationale in the
docstring — "GitHub CLI may call `git mode`" — is uncorroborated; `gh`
does not shell out to `git mode`.

Plan:

- Confirm with `git log --all --oneline -- foundry_sandbox/commands/git_mode.py`
  why the shim was added.
- If no concrete consumer, remove the `[project.scripts]` entry and the
  `git_mode_shim` function; keep only the Click command registered via
  `_LAZY_COMMANDS`.

### 5.5 Command-name suggestions

`cli.py:95` (`CastGroup.resolve_command`) fails hard on unknown commands
with no "did you mean" hint. Click-didyoumean is a small, well-scoped
dependency. Optional quality-of-life win; skip if avoiding new deps.

---

## Phase 6 — Rename `claude-config/` (breaking)

The directory `$SANDBOX_HOME/claude-config/` is the authoritative sandbox
registry for **every** agent — claude, codex, gemini, opencode, shell — yet
the name implies Claude-only scope.

Files and symbols to rename:

- `foundry_sandbox/constants.py:51` — `get_claude_configs_dir()` →
  `get_sandbox_configs_dir()`
- `foundry_sandbox/paths.py:49` — `path_claude_config()` →
  `path_sandbox_config()`
- Every caller (`commands/_helpers.py`, `state.py`, `commands/config.py`,
  `commands/destroy.py`, `commands/new.py`, `paths.py`)
- `cast config` output labels (`CLAUDE_CONFIGS_DIR` → `SANDBOX_CONFIGS_DIR`)

On-disk migration:

- One-shot rename of `$SANDBOX_HOME/claude-config/` →
  `$SANDBOX_HOME/sandboxes/` on first run of the new version.
- Keep a symlink for one minor release for forgiving rollback.

This is a 0.22.x-scope change; ship after Phases 1–5 land. Include a
CHANGELOG "Breaking" entry and a migration note in the release body.

---

## Ordering and sequencing

Phases 1–3 are independent and can land as three PRs in any order.

Phase 4 should follow Phase 1 (so regenerated help matches the fixed
docs).

Phase 5 should follow Phases 2 and 3 (fewer distractions when touching
structural code).

Phase 6 gates on all prior phases and ships in a minor release bump.
