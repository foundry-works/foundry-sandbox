# foundry-sandbox — Phase 8: Code Remediation + CI Pipeline

**Last updated:** 2026-04-21
**Branch:** `sbx`
**Scope:** Finish remaining code items from §2–§4, build full CI pipeline (§5), move HMAC secret outside worktree (§6)
**Deferred to Phase 9:** §7 (docs)

---

## 1. Objective

Close the remaining code and test gaps that block a shippable `foundry-git-safety` runtime, and put the standalone package under required CI so regressions are merge-blocking.

---

## 2. Workstreams

### 2.1 Plumb configured observability paths into decision-log creation

Current state:
- `DecisionLogWriter` reads from `GIT_SAFETY_DECISION_LOG_DIR` env var or defaults to `~/.foundry/logs`.
- The `foundry.yaml` config schema has no observability/log-dir field for this.
- The server's `create_git_api()` does not pass any log directory config to the decision log.

Required work:
- Add a `decision_log_dir` field to `GitSafetyServerConfig` (default: `~/.foundry/logs`).
- When `create_git_api()` is called with a config, initialize or reconfigure the `DecisionLogWriter` singleton with the configured path.
- Reset the module-level `_writer` singleton if the configured path differs from the current one.

Exit criteria:
- A `foundry.yaml` with `git_safety.server.decision_log_dir: /tmp/test-logs` causes decisions to be written there.
- The `/health` endpoint reflects whether the decision log writer is functional.

### 2.2 Surface degraded observability in health/readiness output

Current state:
- `/health` checks config validity and returns `degraded` if config fails to load.
- `/ready` checks workspace, config, and secret store — but not the decision log.
- If the decision-log directory is unwritable, operations silently degrade with a `logger.debug`.

Required work:
- Add a decision-log check to `/ready`: attempt a test write and report failure as a non-fatal degradation.
- Add a `logging` section to `/health` showing decision-log path and writability.
- Keep the overall `/ready` status at 200 even if only logging is degraded (observability failures should not trigger orchestration restarts).

Exit criteria:
- `/ready` response includes a `decision_log` check with `ok: true/false`.
- Unwritable log directory returns 200 with the check marked `ok: false` — not 503.

### 2.3 Add integration test: blocked commands return 422

Current state:
- Unit tests cover `execute_git` returning validation errors for blocked commands.
- No integration test proves the full HTTP stack returns `422` (not `500`) for blocked commands.

Required work:
- Add an integration test in `foundry-git-safety/tests/integration/` that:
  - Starts the server with a registered sandbox.
  - Sends a request with a blocked command (e.g., `git push --force`, `git reflog`).
  - Asserts HTTP 422 with a JSON error body.
  - Also test that observability failures don't change 422 to 500.

Exit criteria:
- Integration test proves blocked commands produce HTTP 422 through the full stack.

### 2.4 Add integration tests for denial paths while logging is unavailable

Current state:
- `audit_log()` catches decision-log write failures with a bare `except Exception` and logs at debug level.
- No integration test covers the path where the decision-log directory is missing/unwritable during a denial.

Required work:
- Add integration tests that:
  - Configure a non-existent/unwritable decision log directory.
  - Send requests that should produce 401 (bad signature), 422 (blocked command), and 429 (rate limit).
  - Assert each returns its expected status — never 500.
  - Verify the decision-log directory is still empty/unwritable (proving the best-effort path).

Exit criteria:
- Auth failures, command denials, and rate limits all return their expected HTTP status even when logging is completely unavailable.

### 2.5 Build required CI pipeline for `foundry-git-safety`

Current state:
- `.github/workflows/test.yml` only runs root-package tests (`pytest tests/unit/`).
- `foundry-git-safety` has ~30 test files across `unit/`, `integration/`, and `security/` but none are run in CI.
- Running both packages' tests in one pytest invocation causes import collisions.

Required work:
- Add a `git-safety-unit` job to `test.yml`:
  - Working directory: `foundry-git-safety/`
  - Install: `pip install -e ".[dev]"`
  - Run: `pytest tests/unit/ -v --tb=short`
- Add a `git-safety-security` job to `test.yml`:
  - Same setup, run: `pytest tests/security/ -v --tb=short`
- Add a `git-safety-integration` job to `test.yml`:
  - Same setup, run: `pytest tests/integration/ -v --tb=short`
- Update the `all-pass` gate to require all four test jobs (root `unit`, `lint`, `git-safety-unit`, `git-safety-security`, `git-safety-integration`).
- Update `scripts/ci-local.sh` to mirror: add steps for the three `foundry-git-safety` test suites.
- Document the pytest isolation rule in a comment in `test.yml`.

Exit criteria:
- CI runs root-package + all three `foundry-git-safety` test tiers as merge-blocking jobs.
- `scripts/ci-local.sh` covers all the same steps.

### 2.6 Move HMAC secret outside the repository worktree

Current state:
- `write_hmac_secret_to_worktree()` writes the secret to `{worktree}/.foundry/hmac-secret` — inside the VCS tree.
- Both wrapper scripts (`stubs/git-wrapper-sbx.sh`, `foundry-git-safety/wrapper.sh`) auto-discover the secret at `${WORKSPACE_DIR}/.foundry/hmac-secret`.
- `inject_git_wrapper()` sets `GIT_HMAC_SECRET_FILE` to that same path.
- The watchdog also re-writes the secret to the worktree path on HMAC rotation.
- This risks accidental VCS exposure if a target repo doesn't ignore `.foundry/`.

Required work:
- Change `write_hmac_secret_to_worktree()` to write to `/run/foundry/hmac-secret` instead of `{worktree}/.foundry/hmac-secret`. Inside the container, `/run` is tmpfs — never persisted, never in any VCS tree.
- Update `inject_git_wrapper()` to set `GIT_HMAC_SECRET_FILE="/run/foundry/hmac-secret"`.
- Update both wrapper scripts to auto-discover at `/run/foundry/hmac-secret` (remove the `${WORKSPACE_DIR}/.foundry/hmac-secret` fallback).
- Update the watchdog to write to the new location on rotation.
- Remove the old `{worktree}/.foundry/hmac-secret` file during `cast new` if it exists (migration).
- Rename `write_hmac_secret_to_worktree()` → `write_hmac_secret_to_sandbox()` since it no longer targets the worktree.

Files touched:
- `foundry_sandbox/git_safety.py` — write path + `inject_git_wrapper()` env var
- `foundry_sandbox/commands/new_sbx.py` — call site
- `foundry_sandbox/watchdog.py` — rotation call site
- `stubs/git-wrapper-sbx.sh` — auto-discovery path
- `foundry-git-safety/foundry_git_safety/wrapper.sh` — auto-discovery path
- `tests/unit/test_git_safety.py` — update assertions
- `tests/unit/test_new_sbx.py` — update mocks
- `tests/unit/test_watchdog.py` — update mocks

Exit criteria:
- HMAC secret is written to `/run/foundry/hmac-secret` (outside VCS tree).
- Both wrapper scripts read from the new location.
- No code references `{worktree}/.foundry/hmac-secret` for the secret.
- Existing tests updated to match.

---

## 3. Execution Order

1. §2.1 — Plumb decision-log path from config
2. §2.2 — Add decision-log health/readiness check
3. §2.3 — Integration test: blocked commands → 422
4. §2.4 — Integration tests: denial paths with broken logging
5. §2.5 — CI pipeline (depends on §2.3/§2.4 tests existing)
6. §2.6 — Move HMAC secret outside worktree (independent of §2.1–§2.5)

---

## 4. Verification Gate

Before calling this phase complete:

- [x] `foundry.yaml` can configure the decision-log directory
- [x] `/ready` reports decision-log health without going 503 on failure
- [x] `/health` shows logging status
- [x] Blocked commands return 422 through the full HTTP stack
- [x] Auth/deny/rate-limit responses are unchanged when logging is unavailable
- [x] CI runs all test suites as merge-blocking
- [x] `scripts/ci-local.sh` mirrors CI
- [x] HMAC secret lives outside the VCS worktree (`/run/foundry/hmac-secret`)
- [x] Wrapper scripts read from new location
- [x] No code references `{worktree}/.foundry/hmac-secret`
