# foundry-sandbox — Phase 8 Checklist: Code Remediation + CI Pipeline

**Last updated:** 2026-04-21
**Companion to:** `PLAN.md`

Legend: `[ ]` todo, `[x]` done, `[~]` partial / accepted risk

---

## 2.1 Config-Driven Decision Log Path

- [x] Add `decision_log_dir` field to `GitSafetyServerConfig` (default `~/.foundry/logs`) — pre-existing in ObservabilityConfig
- [x] Thread configured `decision_log_dir` through `create_git_api()` to `DecisionLogWriter`
- [x] Reset `_writer` singleton when config path differs from active writer path
- [x] Add test: `foundry.yaml` with custom `decision_log_dir` writes to that path

## 2.2 Degraded Observability in Health/Readiness

- [x] Add decision-log writability check to `/ready` endpoint
- [x] Return 200 (not 503) when only the decision log is degraded
- [x] Add `logging` section to `/health` response with path and writability
- [x] Add test: `/ready` reports `decision_log: {ok: false}` with unwritable dir
- [x] Add test: `/health` includes logging status

## 2.3 Integration Test: Blocked Commands → 422

- [x] Write integration test: server with registered sandbox, blocked command → 422
- [x] Include at least one push-blocked and one command-blocked scenario
- [x] Verify response body is JSON with an `error` key

## 2.4 Integration Tests: Denial Paths with Broken Logging

- [x] Test: unwritable decision-log dir + bad signature → 401 (not 500)
- [x] Test: unwritable decision-log dir + blocked command → 422 (not 500)
- [x] Test: unwritable decision-log dir + rate limit → 429 (not 500)
- [x] Verify decision-log directory stays empty/unwritable (best-effort proven)

## 2.5 CI Pipeline for `foundry-git-safety`

- [x] Add `git-safety-unit` job to `.github/workflows/test.yml`
- [x] Add `git-safety-security` job to `.github/workflows/test.yml`
- [x] Add `git-safety-integration` job to `.github/workflows/test.yml`
- [x] Update `all-pass` gate to require all test jobs
- [x] Add comment documenting pytest isolation rule
- [x] Update `scripts/ci-local.sh` with `foundry-git-safety` test steps
- [ ] Verify CI passes on a test push

---

## Phase 7 Carry-Over (previously done, verified)

These items from the post-review plan are complete:

- [x] Choose how `foundry-git-safety` is shipped with the main product
- [x] Update root packaging for default install path
- [x] Update `install.sh` for working sandbox
- [x] `cast new` / `cast start` fail closed on missing git safety
- [x] Smoke test: fresh install → create sandbox → proxied `git status`
- [x] Replace privileged default paths with user-writable defaults
- [x] Plumb `secrets_path` into `SecretStore`
- [x] Plumb `data_dir` into registration/runtime code paths
- [x] Fix readiness checks for real secret-store path
- [x] Add tests covering non-default configured paths
- [x] Persist host-side `repo_root` during registration
- [x] Remove `/git-workspace` fallback
- [x] Fail closed when `repo_root` missing
- [x] Integration test: registered sandbox → proxied `git status`
- [x] Integration test: missing `repo_root` → controlled error
- [x] Make decision-log writes best-effort
- [x] Prevent logging failures from changing 401/422 → 500
- [x] Keep metrics emission non-fatal
- [x] Unit tests for unwritable decision-log directory

## 2.6 Move HMAC Secret Outside Worktree

- [x] Rename `write_hmac_secret_to_worktree()` → `write_hmac_secret_to_sandbox()`, write to `/run/foundry/hmac-secret`
- [x] Update `inject_git_wrapper()` env var to `/run/foundry/hmac-secret`
- [x] Update `stubs/git-wrapper-sbx.sh` auto-discovery to `/run/foundry/hmac-secret`
- [x] Update `foundry-git-safety/foundry_git_safety/wrapper.sh` auto-discovery to `/run/foundry/hmac-secret`
- [x] Update watchdog rotation to write to new path
- [x] Update `tests/unit/test_git_safety.py` assertions
- [x] Update `tests/unit/test_new_sbx.py` mocks
- [x] Update `tests/unit/test_watchdog.py` mocks
- [x] Grep for remaining references to `.foundry/hmac-secret` in code — none found

---

## Phase 7 Carry-Over (previously done, verified)

These items from the post-review plan are complete:

- [x] Choose how `foundry-git-safety` is shipped with the main product
- [x] Update root packaging for default install path
- [x] Update `install.sh` for working sandbox
- [x] `cast new` / `cast start` fail closed on missing git safety
- [x] Smoke test: fresh install → create sandbox → proxied `git status`
- [x] Replace privileged default paths with user-writable defaults
- [x] Plumb `secrets_path` into `SecretStore`
- [x] Plumb `data_dir` into registration/runtime code paths
- [x] Fix readiness checks for real secret-store path
- [x] Add tests covering non-default configured paths
- [x] Persist host-side `repo_root` during registration
- [x] Remove `/git-workspace` fallback
- [x] Fail closed when `repo_root` missing
- [x] Integration test: registered sandbox → proxied `git status`
- [x] Integration test: missing `repo_root` → controlled error
- [x] Make decision-log writes best-effort
- [x] Prevent logging failures from changing 401/422 → 500
- [x] Keep metrics emission non-fatal
- [x] Unit tests for unwritable decision-log directory

## Deferred to Phase 9

- [ ] Update README.md, getting-started.md, configuration.md, operations.md
- [ ] Add troubleshooting guidance
- [ ] Final release blocker verification
