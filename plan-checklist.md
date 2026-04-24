# Testing Gap Remediation Checklist

## Phase 1: Broken Entry Points

- [x] Open `.github/workflows/test.yml`.
- [x] Remove the `pytest tests/smoke/test_migration_smoke.py` invocation.
- [x] Replace it with installed-wheel smoke commands that work without live sbx.
- [x] Confirm no workflow references missing files.
- [x] Open `tests/run.sh`.
- [x] Remove or replace the stale `cast info --json` check.
- [x] Run `./tests/run.sh` and record any remaining failures.
- [x] Add a unit test that catches unknown commands referenced by `tests/run.sh`.

## Phase 2: Hermetic Root Tests

- [x] Inspect `tests/conftest.py` and `tests/unit/conftest.py`.
- [x] Add an autouse fixture that sets `SANDBOX_HOME` to a temp directory.
- [x] Set `HOME` to a temp directory if tests or code paths expand `~`.
- [x] Ensure the temp directories are created before tests run.
- [x] Fix `tests/unit/test_up.py` to patch `foundry_sandbox.commands.up.save_last_attach`.
- [x] Check for other tests that patch a module where the function is defined instead of where it is imported.
- [x] Run `python -m pytest tests/unit/test_up.py -q`.
- [x] Run `python -m pytest tests/unit -q`.

## Phase 3: Hermetic foundry-git-safety Tests

- [x] Inspect `foundry-git-safety/tests/conftest.py`.
- [x] Inspect `foundry-git-safety/tests/integration/conftest.py`.
- [x] Add or update an autouse fixture for `GIT_SAFETY_DECISION_LOG_DIR`.
- [x] Add or update an autouse fixture for `FOUNDRY_DATA_DIR` where needed.
- [x] Reset `foundry_git_safety.decision_log._writer` before tests that depend on log state.
- [x] Reset or close `foundry_git_safety.decision_log._writer` after those tests.
- [x] Ensure Flask app fixtures configure writable decision-log paths.
- [x] Run `cd foundry-git-safety && python -m pytest tests/integration -q`.
- [x] Run `cd foundry-git-safety && python -m pytest tests/unit tests/security tests/integration -q`.

## Phase 4: Validator Tests

- [x] Create `tests/unit/test_validate.py`.
- [x] Add table-driven tests for valid new sandbox names.
- [x] Add table-driven tests for invalid new sandbox names.
- [x] Add table-driven tests for valid existing sandbox names.
- [x] Add table-driven tests for invalid existing sandbox names.
- [x] Add table-driven tests for valid HTTPS repo URLs.
- [x] Add table-driven tests for valid SSH repo URLs.
- [x] Add table-driven tests for valid GitHub shorthand repo inputs.
- [x] Add table-driven tests for safe local repo paths.
- [x] Add rejection tests for empty repo input.
- [x] Add rejection tests for path traversal with `..`.
- [x] Add rejection tests for embedded credentials.
- [x] Add rejection tests for missing host or missing path.
- [x] Add rejection tests for suspicious SSH hosts.
- [x] Add rejection tests for sensitive local paths: `/etc`, `/proc`, `/sys`, `/dev`, `/root`, `/boot`, `/var/lib/docker`.
- [x] Run `python -m pytest tests/unit/test_validate.py -q`.

## Phase 5: Version Check Tests

- [x] Create `tests/unit/test_version_check.py` if it does not exist.
- [x] Test `_should_check` with no disabling environment variables.
- [x] Test `_should_check` with `CAST_DISABLE_UPDATE_CHECK=1`.
- [x] Test `_should_check` with `SANDBOX_NONINTERACTIVE=1`.
- [x] Test `_should_check` with `CI=1`.
- [x] Test `_should_check` with `CI=true`.
- [x] Test `_cache_is_fresh` for missing cache.
- [x] Test `_cache_is_fresh` for corrupt or malformed cache.
- [x] Test `_cache_is_fresh` for expired cache.
- [x] Test `_cache_is_fresh` for fresh cache.
- [x] Test `_parse_version` with normal versions.
- [x] Test `_parse_version` with suffixes such as `1.2.3rc1`.
- [x] Test `_is_newer` for newer, equal, and older versions.
- [x] Mock `urllib.request.urlopen` and test valid PyPI JSON.
- [x] Mock `urllib.request.urlopen` and test malformed JSON.
- [x] Mock `urllib.request.urlopen` and test missing version fields.
- [x] Mock `urllib.request.urlopen` and test URL errors.
- [x] Test `check_for_update` swallows helper exceptions.
- [x] Run `python -m pytest tests/unit/test_version_check.py -q`.

## Phase 6: CLI And Script Drift Tests

- [ ] Import `_LAZY_COMMANDS` in a CLI test.
- [ ] Assert every `_LAZY_COMMANDS` entry imports successfully.
- [ ] Assert every `_LAZY_COMMANDS` entry resolves to a Click command.
- [ ] Assert `info` is rejected unless intentionally restored.
- [ ] Assert `build` is rejected.
- [ ] Assert `migrate-to-sbx` is rejected.
- [ ] Assert `migrate-from-sbx` is rejected.
- [ ] Add a test that checks `tests/run.sh` only references known commands.
- [ ] Keep parsing simple and document any assumptions in the test.
- [ ] Run `python -m pytest tests/unit/test_cli.py -q`.
- [ ] Run `./tests/run.sh`.

## Phase 7: Security Suite Documentation

- [x] Open `tests/README.md`.
- [x] Document which tests run in ordinary CI.
- [x] Document that live sbx smoke tests require sbx and supported virtualization.
- [x] Document red-team prerequisites.
- [x] Document chaos prerequisites.
- [x] Open `docs/security/security-model.md`.
- [x] Clarify whether red-team, chaos, and live smoke tests are manual or CI-gated.
- [x] Include exact commands for manual security validation.
- [x] Avoid implying that manual suites run on every PR if they do not.

## Phase 8: Optional Self-Hosted Security Gate

- [ ] Confirm whether the project has access to a runner with sbx and KVM.
- [ ] If yes, add a separate workflow job for `pytest tests/smoke -m requires_sbx`.
- [ ] If yes, add a separate workflow job for `./tests/redteam/runner.sh`.
- [ ] If yes, add a separate workflow job for `./tests/chaos/runner.sh`.
- [ ] Upload JUnit, TAP, or log artifacts from those jobs.
- [ ] Mark the job as scheduled or self-hosted only if it cannot run on normal PR infrastructure.
- [ ] If no runner exists, leave this as documented manual validation.

## Phase 9: Coverage Gates

- [ ] Run root coverage: `python -m pytest tests/unit --cov=foundry_sandbox --cov-report=term-missing -q`.
- [ ] Record the root coverage percentage.
- [ ] Raise root `--cov-fail-under` only to a value the suite already exceeds.
- [ ] Run nested coverage from `foundry-git-safety/`.
- [ ] Record the nested coverage percentage.
- [ ] Decide whether nested coverage should be enforced in CI.
- [ ] If enforcing nested coverage, start with a realistic threshold.
- [ ] Re-run both coverage commands after threshold changes.

## Final Verification

- [ ] `python -m pytest tests/unit -q`
- [ ] `python -m pytest tests/unit --cov=foundry_sandbox --cov-report=term-missing -q`
- [ ] `cd foundry-git-safety && python -m pytest tests/unit tests/security tests/integration -q`
- [ ] `./tests/run.sh`
- [ ] `git status --short` shows only intentional changes.

## Manual Verification When sbx Is Available

- [ ] `python -m pytest tests/smoke -m requires_sbx -q`
- [ ] `./tests/redteam/runner.sh`
- [ ] `./tests/chaos/runner.sh`

## Definition Of Done

- [ ] No stale workflow references remain.
- [ ] Fast tests are hermetic and do not write to real `~/.foundry`.
- [ ] Direct validator tests exist.
- [ ] Version-check tests exist and do not use the network.
- [ ] CLI/script drift tests exist.
- [ ] Security-suite docs match actual CI behavior.
- [ ] Coverage thresholds are realistic and enforced where chosen.
