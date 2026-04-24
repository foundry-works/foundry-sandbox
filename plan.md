# Testing Gap Remediation Plan

## Summary

The current test suite has strong coverage in several areas, especially
foundry-git-safety policy behavior, but the review found gaps in three
categories:

1. Some tests and local scripts are stale or not wired into CI.
2. Several tests are not hermetic and accidentally depend on host filesystem
   state such as `~/.foundry`.
3. Security-sensitive and workflow-sensitive code paths are under-tested or only
   tested indirectly.

This plan turns those findings into implementation tasks. It is written so a
junior developer can work through it without needing to re-run the whole review.

## Goals

- Make the default and CI test commands reliable from a clean checkout.
- Remove accidental dependencies on the developer's real home directory, sbx
  state, and git-safety log paths.
- Fix stale test entry points before adding new coverage.
- Add targeted tests for validation, version checking, CLI command registration,
  and smoke-runner behavior.
- Make security validation expectations visible in CI or documented as an
  explicit manual gate.
- Raise coverage standards gradually without blocking unrelated work on a large
  one-time coverage push.

## Non-Goals

- Do not refactor production command implementations unless a test gap cannot be
  fixed cleanly otherwise.
- Do not require live sbx/KVM tests on ordinary GitHub-hosted PR jobs unless the
  environment can actually support them.
- Do not weaken security behavior to make tests easier.
- Do not rewrite the full red-team or chaos suites.

## Current Problems

### 1. Stale Smoke Gate

`.github/workflows/test.yml` currently runs:

```bash
pytest tests/smoke/test_migration_smoke.py -v --tb=short
```

That file does not exist. The current smoke test file is
`tests/smoke/test_live_sbx.py`, and those tests require a real `sbx` runtime.

Expected outcome:

- CI no longer references missing files.
- There is a clear distinction between:
  - installed-wheel smoke checks that can run on GitHub-hosted CI
  - live sbx smoke checks that require a capable machine

### 2. Non-Hermetic Tests

The root unit suite failed locally because `cast up` tests patched
`foundry_sandbox.state.save_last_attach`, but `commands/up.py` imports
`save_last_attach` directly. The test therefore wrote through the real function
and hit a read-only host path.

The nested foundry-git-safety integration suite also used the default decision
log path under `~/.foundry/logs` unless the singleton had been explicitly
configured.

Expected outcome:

- Unit and integration tests should run with all state under `tmp_path` or
  `tmp_path_factory`.
- Tests should not write to the developer's real `~/.foundry`.
- Tests should reset singleton state that can leak across cases.

### 3. Security Suites Are Manual But Described As Active Verification

`docs/security/security-model.md` lists these as security verification:

- `tests/unit/`
- `tests/smoke/`
- `tests/chaos/`
- `tests/redteam/`

CI runs unit and foundry-git-safety security/integration tests, but not the
root red-team, chaos, or live sbx smoke tests.

Expected outcome:

- Either add explicit jobs for these suites where the runner supports them, or
  document them as manual/self-hosted gates.
- Do not leave docs implying that all listed checks are part of the ordinary CI
  gate if they are not.

### 4. Weak Coverage Gates

Root package coverage is enforced at only 60%. The nested foundry-git-safety
jobs do not enforce coverage.

Observed weak spots from the review:

- `foundry_sandbox/validate.py`
- `foundry_sandbox/version_check.py`
- `foundry_sandbox/commands/new.py`
- `foundry_sandbox/commands/up.py`
- `foundry_sandbox/ide.py`
- `foundry-git-safety/foundry_git_safety/cli.py`
- `foundry-git-safety/foundry_git_safety/subprocess_env.py`
- `foundry-git-safety/foundry_git_safety/operations.py`
- `foundry-git-safety/foundry_git_safety/branch_isolation.py`

Expected outcome:

- Add targeted tests for the highest-value gaps.
- Raise thresholds only after the new tests land.
- Use separate thresholds for root and nested packages.

### 5. Input Validation Is Mostly Tested Indirectly

`foundry_sandbox/validate.py` checks sandbox names and repository inputs. These
checks are security-relevant because they reject path traversal, embedded
credentials, sensitive local paths, malformed SSH hosts, and invalid sandbox
names.

Many command tests patch these validators instead of exercising the validators
directly.

Expected outcome:

- Add table-driven unit tests for accepted and rejected sandbox names.
- Add table-driven unit tests for accepted and rejected repository URLs.
- Include local path edge cases, shorthand GitHub repos, HTTPS URLs, SSH URLs,
  credential-bearing URLs, traversal attempts, and sensitive filesystem paths.

### 6. Local Test Helper Drift

`tests/run.sh` invokes `cast info --json`, but the Click CLI has no `info`
command.

Expected outcome:

- Update `tests/run.sh` to only call supported commands.
- Add a test that fails if `tests/run.sh` references unknown CLI commands.
- Keep the script useful as a fast local smoke check.

## Implementation Plan

### Phase 1: Fix Broken Test Entry Points

Start here because these are clear failures and reduce confusion for everyone
else.

Tasks:

1. Open `.github/workflows/test.yml`.
2. Replace the missing `tests/smoke/test_migration_smoke.py` invocation with a
   real installed-wheel smoke check.
3. Do not point GitHub-hosted CI at `tests/smoke/test_live_sbx.py` unless the job
   has sbx and KVM.
4. Open `tests/run.sh`.
5. Remove or replace the stale `cast info --json` check.
6. Add a unit test that parses `tests/run.sh` for `cast <command>` or
   `$CLI <command>` calls and verifies each command is known to
   `foundry_sandbox.cli.cli`.

Suggested replacement for the installed-wheel smoke gate:

```bash
cast --help >/dev/null
cast config --json | python3 -c "import json,sys; json.load(sys.stdin)"
cast diagnose --json | python3 -c "import json,sys; json.load(sys.stdin)"
```

Acceptance criteria:

- `pytest tests/unit/test_cli.py -q` passes.
- `./tests/run.sh` no longer fails because of an unknown `info` command.
- `.github/workflows/test.yml` does not reference missing files.

### Phase 2: Make Tests Hermetic

Fix test isolation before adding a lot of new tests. Otherwise new tests may
inherit the same host-state problems.

Root package tasks:

1. Add or update an autouse fixture in `tests/conftest.py` or
   `tests/unit/conftest.py`.
2. Use `monkeypatch` to set `SANDBOX_HOME` to a temp directory.
3. If any code uses `HOME`, set it to a temp directory too.
4. Patch direct imports at the place they are used. For example, tests for
   `commands/up.py` should patch `foundry_sandbox.commands.up.save_last_attach`,
   not `foundry_sandbox.state.save_last_attach`.
5. Re-run the root unit suite.

Nested foundry-git-safety tasks:

1. Add or update autouse fixtures under `foundry-git-safety/tests/conftest.py`
   or the relevant sub-suite conftest.
2. Set `GIT_SAFETY_DECISION_LOG_DIR` to a temp directory.
3. Set `FOUNDRY_DATA_DIR` to a temp directory where relevant.
4. Reset `foundry_git_safety.decision_log._writer` before and after tests that
   create Flask apps or write decisions.
5. Prefer configuring the decision log through public helpers when possible.

Acceptance criteria:

```bash
python -m pytest tests/unit -q
cd foundry-git-safety && python -m pytest tests/unit tests/security tests/integration -q
```

Both commands should pass without writing to the real `~/.foundry`.

### Phase 3: Add Direct Validation Tests

Add a new root unit test file:

```text
tests/unit/test_validate.py
```

Test `validate_sandbox_name`:

- accepts simple names like `abc`, `repo-1`, `repo_1`, `repo.1`
- rejects empty string
- rejects names longer than 128 chars
- rejects `.` and `..`
- rejects `/` and `\`
- rejects whitespace
- rejects names starting with punctuation
- rejects control characters if applicable

Test `validate_existing_sandbox_name`:

- accepts older names that are less strict but still safe
- rejects empty string
- rejects names longer than 255 chars
- rejects `.` and `..`
- rejects path separators
- rejects control characters

Test `validate_git_url`:

- accepts `https://github.com/org/repo`
- accepts `http://example.com/org/repo`
- accepts `git@github.com:org/repo.git`
- accepts `org/repo`
- accepts `org/repo.git`
- accepts safe local paths such as `.` and `./repo`
- rejects empty string
- rejects path traversal containing `..`
- rejects embedded credentials such as
  `https://token@github.com/org/repo`
- rejects URLs with missing hosts or paths
- rejects suspicious SSH hosts
- rejects sensitive local paths such as `/etc`, `/proc`, `/sys`, `/dev`,
  `/root`, `/boot`, and `/var/lib/docker`

Implementation guidance:

- Use `pytest.mark.parametrize`.
- Keep assertions specific enough to confirm both the boolean and useful error
  message category.
- Use `tmp_path` for local path cases when useful.

Acceptance criteria:

```bash
python -m pytest tests/unit/test_validate.py -q
```

### Phase 4: Add Version Check Tests

Add or expand tests for `foundry_sandbox/version_check.py`.

Focus on pure and mockable behavior:

- `_should_check` returns false when `CAST_DISABLE_UPDATE_CHECK=1`
- `_should_check` returns false when `SANDBOX_NONINTERACTIVE=1`
- `_should_check` returns false when `CI=1` or `CI=true`
- `_cache_is_fresh` handles missing, corrupt, expired, and valid cache data
- `_parse_version` handles normal versions and suffixes
- `_is_newer` compares versions correctly
- `_fetch_latest_version` handles valid PyPI JSON, malformed JSON, missing
  version fields, and URL errors
- `check_for_update` never raises when helpers fail

Implementation guidance:

- Patch `urllib.request.urlopen`; do not use the network.
- Patch `path_version_check` to point at `tmp_path`.
- Patch time where needed for cache age tests.
- Patch `foundry_sandbox.__version__` or test lower-level helpers directly.

Acceptance criteria:

```bash
python -m pytest tests/unit/test_version_check.py -q
```

### Phase 5: Add CLI And Script Drift Tests

Extend `tests/unit/test_cli.py` or add `tests/unit/test_test_scripts.py`.

Tests to add:

1. Every command in `_LAZY_COMMANDS` imports and resolves to a Click command.
2. `tests/run.sh` does not reference unknown CLI commands.
3. The expected fast smoke commands produce JSON when mocked or invoked in a
   hermetic environment.
4. Removed commands such as `info`, `build`, `migrate-to-sbx`, and
   `migrate-from-sbx` remain rejected unless intentionally restored.

Implementation guidance:

- Import `_LAZY_COMMANDS` from `foundry_sandbox.cli`.
- For `tests/run.sh`, parse conservatively. It is fine to look for commands in
  lines containing `$CLI` or `python3 -m foundry_sandbox.cli`.
- If parsing becomes too brittle, move the command list into a small Python
  helper or comment block that the test can read.

Acceptance criteria:

```bash
python -m pytest tests/unit/test_cli.py -q
./tests/run.sh
```

### Phase 6: Clarify Red-Team, Chaos, And Live Smoke Gates

Decide how these suites should be run.

Option A: Manual documented gate

- Update `tests/README.md`.
- Update `docs/security/security-model.md`.
- Say clearly that red-team, chaos, and live sbx smoke checks require a prepared
  sandbox or self-hosted runner.
- Document exact commands and prerequisites.

Option B: Self-hosted or scheduled CI gate

- Add a separate workflow job with labels that actually provide sbx/KVM.
- Run `pytest tests/smoke -m requires_sbx`.
- Run `./tests/redteam/runner.sh`.
- Run `./tests/chaos/runner.sh`.
- Upload JUnit or TAP artifacts when available.

Recommended first step:

- Implement Option A now.
- Open a follow-up issue or TODO for Option B if the project has a suitable
  runner.

Acceptance criteria:

- Docs no longer imply that red-team, chaos, and live smoke tests run in ordinary
  PR CI.
- The exact manual command sequence is documented.

### Phase 7: Raise Coverage Gradually

After phases 1-5 land, re-run coverage.

Commands:

```bash
python -m pytest tests/unit --cov=foundry_sandbox --cov-report=term-missing -q
cd foundry-git-safety
python -m pytest tests/unit tests/security tests/integration \
  --cov=foundry_git_safety --cov-report=term-missing -q
```

Tasks:

1. Record the new coverage numbers.
2. Raise root `--cov-fail-under` from 60 to a value the suite already exceeds
   with margin.
3. Add a nested foundry-git-safety coverage gate if the maintainers want it in
   CI.
4. Do not set thresholds higher than current measured coverage in the same PR.

Recommended thresholds after the first pass:

- Root package: 70% or 75%, depending on the measured result.
- foundry-git-safety: start at 70% if the full nested suite is stable.

Acceptance criteria:

- CI fails if coverage regresses below the chosen threshold.
- The threshold is realistic and does not require unrelated test work.

## Suggested Work Order

1. Fix stale workflow and `tests/run.sh`.
2. Add hermetic fixtures and fix direct-import patching issues.
3. Add validation tests.
4. Add version-check tests.
5. Add CLI/script drift tests.
6. Update docs for manual security suites.
7. Raise coverage thresholds.

## Verification Commands

Run these before opening the PR:

```bash
python -m pytest tests/unit -q
python -m pytest tests/unit --cov=foundry_sandbox --cov-report=term-missing -q
cd foundry-git-safety && python -m pytest tests/unit tests/security tests/integration -q
./tests/run.sh
```

If the machine has sbx/KVM and a prepared environment, also run:

```bash
python -m pytest tests/smoke -m requires_sbx -q
./tests/redteam/runner.sh
./tests/chaos/runner.sh
```

## Definition Of Done

- No CI job points at a missing test file.
- Fast local tests pass from a clean checkout without touching real host state.
- `tests/run.sh` passes or clearly skips unavailable external dependencies.
- Direct validation and version-check tests exist.
- CLI/script drift is covered by tests.
- Security-suite docs match what CI actually runs.
- Coverage thresholds are raised only after tests support the new bar.
