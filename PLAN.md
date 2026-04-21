# foundry-sandbox — Post-Review Remediation Plan

**Last updated:** 2026-04-20
**Branch:** `sbx`
**Source:** Senior engineering review of the branch plus local verification
**Status:** Open. Release should be treated as blocked until sections 1-5 are complete.

---

## 1. Objective

Replace the deleted migration-era plan with a short, execution-focused plan for the concrete regressions and release blockers found during review.

This document supersedes the earlier `sbx` migration plan. Any older ADR references to historical `PLAN.md` section numbers should be treated as archival context, not the current source of truth.

---

## 2. What Was Verified

- Root package unit suite passes:
  - `pytest -q tests/unit/ --import-mode=importlib`
  - Result: `508 passed, 10 deselected`
- `foundry-git-safety` test suites pass only when the decision-log directory is overridden to a writable path.
- Default runtime behavior is not yet shippable:
  - the standalone git-safety binary is not installed by the main package path
  - default host paths point at privileged locations
  - sandbox registration does not persist a host-side `repo_root`
  - audit logging can turn expected `4xx` responses into `500`s
  - CI does not cover the standalone package

---

## 3. Remediation Workstreams

### 3.1 Make `foundry-git-safety` installable and mandatory

Current problem:
- The branch treats `foundry-git-safety` as required for normal git behavior, but the root package and installer do not reliably install that binary.
- `cast new` and `cast start` warn and continue if the service is missing or fails to start.

Required work:
- Decide the packaging strategy:
  - publish and install `foundry-git-safety` as an explicit dependency, or
  - vendor its CLI/runtime into the main install path
- Update `install.sh`, package metadata, and docs so a default install includes the git-safety runtime.
- Make `cast new` and `cast start` fail closed when git safety is unavailable or unhealthy.
- Add a smoke test that proves a fresh install can create a sandbox and run `git status`.

Exit criteria:
- Fresh install produces a working `cast` CLI and a working `foundry-git-safety` binary.
- Sandbox creation/startup stops with a clear error instead of creating a broken environment.

### 3.2 Fix host path defaults and config propagation

Current problem:
- Default secrets/data paths still point to privileged locations such as `/run/secrets/sandbox-hmac` and `/var/lib/foundry-git-safety`.
- The server schema exposes configurable paths, but runtime creation still ignores parts of that config.
- Readiness checks inspect the wrong secret-store attribute.

Required work:
- Move defaults to user-writable locations, or add an explicit privileged bootstrap path with clear ownership rules.
- Thread configured `secrets_path`, `data_dir`, and observability paths through runtime object creation.
- Fix readiness checks to inspect the actual secret-store path in use.
- Add tests that start the server with non-default configured paths and verify they are honored.

Exit criteria:
- Default install works for an unprivileged user.
- Runtime components use the configured locations, not hardcoded fallbacks.

### 3.3 Fix sandbox registration and host-side repo-root resolution

Current problem:
- Sandbox registration writes branch metadata but not the host worktree path.
- The server falls back to `/git-workspace`, which does not exist for the standalone host daemon.
- Real git requests fail with host-side cwd errors instead of using the registered worktree.

Required work:
- Persist a host-side `repo_root` during sandbox registration.
- Validate that `repo_root` exists before executing git.
- Replace the `/git-workspace` fallback with an explicit fail-closed error if registration is incomplete.
- Add integration coverage for:
  - successful `git status` against a registered sandbox
  - missing `repo_root`
  - blocked commands and blocked paths still returning `422`, not `500`

Exit criteria:
- A registered sandbox can execute proxied git commands against the intended host worktree.
- Incomplete registration produces a clear user-facing error instead of a bad default path.

### 3.4 Make audit logging and observability non-fatal

Current problem:
- `audit_log()` unconditionally writes to the structured decision log.
- If the decision-log path is unwritable, normal denials and execution errors escalate into `500 Internal Server Error`.

Required work:
- Make decision-log writes best-effort.
- Preserve the main request response even if structured logging or metrics emission fails.
- Surface degraded observability in logs and health/readiness output rather than crashing request handling.
- Add regression tests for unwritable decision-log paths.

Exit criteria:
- Observability failures never change expected auth/validation/command responses into `500`s.
- The server can run in degraded mode with logging disabled or unavailable.

### 3.5 Put the standalone package under required CI

Current problem:
- CI only runs the root `tests/unit/` suite.
- `foundry-git-safety` regressions are not merge-blocking today.
- Naively mixing root and standalone test trees in one pytest invocation causes import collisions because both use top-level `tests` packages.

Required work:
- Add dedicated CI jobs for `foundry-git-safety` unit, security, and integration suites.
- Run the standalone suite from its own working directory or otherwise isolate import roots.
- Update `scripts/ci-local.sh` to mirror the same separation.
- Document the pytest invocation rules needed to avoid test-package collisions.

Exit criteria:
- Required CI covers both the root package and the standalone package.
- The test strategy is reproducible locally and in CI.

### 3.6 Revisit HMAC secret placement in the synced worktree

Current problem:
- The wrapper secret is currently written into `{worktree}/.foundry/hmac-secret`.
- That location lives inside the synced repository worktree, which risks accidental VCS exposure unless every target repo ignores it.

Required work:
- Re-evaluate whether the secret can be moved out of the repository tree while still remaining available to the wrapper.
- If it must remain in the worktree, add layered mitigations:
  - hard block it from staging/push
  - ensure wrapper/bootstrap code does not rely on repo-local ignore rules
  - document the residual risk clearly

Exit criteria:
- The HMAC secret is either outside the VCS tree, or it is provably protected from accidental commit and push.

### 3.7 Update docs to match the actual runtime model

Current problem:
- Current docs describe `foundry-git-safety` as installed automatically and describe paths/behavior that do not match the verified runtime.

Required work:
- Update:
  - `README.md`
  - `docs/getting-started.md`
  - `docs/configuration.md`
  - `docs/operations.md`
- Document the actual install path, runtime directories, and failure behavior.
- Add an operator-oriented troubleshooting section for git-safety startup, path config, and degraded observability.

Exit criteria:
- A user following docs from a clean machine reaches a working setup.
- Docs no longer rely on assumptions that are false in the current branch.

---

## 4. Suggested Execution Order

1. Workstream 3.1: install/runtime bootstrap
2. Workstream 3.2: path defaults and config propagation
3. Workstream 3.3: repo-root registration
4. Workstream 3.4: non-fatal observability
5. Workstream 3.5: CI coverage
6. Workstream 3.6: HMAC secret placement
7. Workstream 3.7: docs cleanup

---

## 5. Release Gate

Do not cut a release from this branch until all of the following are true:

- default install provides a working git-safety runtime
- sandbox creation/startup fails closed when safety prerequisites are missing
- registered sandboxes execute proxied git commands against the correct host repo
- unwritable decision-log paths no longer cause `500`s
- required CI covers both `foundry-sandbox` and `foundry-git-safety`

