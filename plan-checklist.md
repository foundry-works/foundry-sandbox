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

- [ ] Inspect `tests/conftest.py` and `tests/unit/conftest.py`.
- [ ] Add an autouse fixture that sets `SANDBOX_HOME` to a temp directory.
- [ ] Set `HOME` to a temp directory if tests or code paths expand `~`.
- [ ] Ensure the temp directories are created before tests run.
- [ ] Fix `tests/unit/test_up.py` to patch `foundry_sandbox.commands.up.save_last_attach`.
- [ ] Check for other tests that patch a module where the function is defined instead of where it is imported.
- [ ] Run `python -m pytest tests/unit/test_up.py -q`.
- [ ] Run `python -m pytest tests/unit -q`.

## Phase 3: Hermetic foundry-git-safety Tests

- [ ] Inspect `foundry-git-safety/tests/conftest.py`.
- [ ] Inspect `foundry-git-safety/tests/integration/conftest.py`.
- [ ] Add or update an autouse fixture for `GIT_SAFETY_DECISION_LOG_DIR`.
- [ ] Add or update an autouse fixture for `FOUNDRY_DATA_DIR` where needed.
- [ ] Reset `foundry_git_safety.decision_log._writer` before tests that depend on log state.
- [ ] Reset or close `foundry_git_safety.decision_log._writer` after those tests.
- [ ] Ensure Flask app fixtures configure writable decision-log paths.
- [ ] Run `cd foundry-git-safety && python -m pytest tests/integration -q`.
- [ ] Run `cd foundry-git-safety && python -m pytest tests/unit tests/security tests/integration -q`.

## Phase 4: Validator Tests

- [ ] Create `tests/unit/test_validate.py`.
- [ ] Add table-driven tests for valid new sandbox names.
- [ ] Add table-driven tests for invalid new sandbox names.
- [ ] Add table-driven tests for valid existing sandbox names.
- [ ] Add table-driven tests for invalid existing sandbox names.
- [ ] Add table-driven tests for valid HTTPS repo URLs.
- [ ] Add table-driven tests for valid SSH repo URLs.
- [ ] Add table-driven tests for valid GitHub shorthand repo inputs.
- [ ] Add table-driven tests for safe local repo paths.
- [ ] Add rejection tests for empty repo input.
- [ ] Add rejection tests for path traversal with `..`.
- [ ] Add rejection tests for embedded credentials.
- [ ] Add rejection tests for missing host or missing path.
- [ ] Add rejection tests for suspicious SSH hosts.
- [ ] Add rejection tests for sensitive local paths: `/etc`, `/proc`, `/sys`, `/dev`, `/root`, `/boot`, `/var/lib/docker`.
- [ ] Run `python -m pytest tests/unit/test_validate.py -q`.

## Phase 5: Version Check Tests

- [ ] Create `tests/unit/test_version_check.py` if it does not exist.
- [ ] Test `_should_check` with no disabling environment variables.
- [ ] Test `_should_check` with `CAST_DISABLE_UPDATE_CHECK=1`.
- [ ] Test `_should_check` with `SANDBOX_NONINTERACTIVE=1`.
- [ ] Test `_should_check` with `CI=1`.
- [ ] Test `_should_check` with `CI=true`.
- [ ] Test `_cache_is_fresh` for missing cache.
- [ ] Test `_cache_is_fresh` for corrupt or malformed cache.
- [ ] Test `_cache_is_fresh` for expired cache.
- [ ] Test `_cache_is_fresh` for fresh cache.
- [ ] Test `_parse_version` with normal versions.
- [ ] Test `_parse_version` with suffixes such as `1.2.3rc1`.
- [ ] Test `_is_newer` for newer, equal, and older versions.
- [ ] Mock `urllib.request.urlopen` and test valid PyPI JSON.
- [ ] Mock `urllib.request.urlopen` and test malformed JSON.
- [ ] Mock `urllib.request.urlopen` and test missing version fields.
- [ ] Mock `urllib.request.urlopen` and test URL errors.
- [ ] Test `check_for_update` swallows helper exceptions.
- [ ] Run `python -m pytest tests/unit/test_version_check.py -q`.

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

- [ ] Open `tests/README.md`.
- [ ] Document which tests run in ordinary CI.
- [ ] Document that live sbx smoke tests require sbx and supported virtualization.
- [ ] Document red-team prerequisites.
- [ ] Document chaos prerequisites.
- [ ] Open `docs/security/security-model.md`.
- [ ] Clarify whether red-team, chaos, and live smoke tests are manual or CI-gated.
- [ ] Include exact commands for manual security validation.
- [ ] Avoid implying that manual suites run on every PR if they do not.

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
