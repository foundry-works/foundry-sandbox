# foundry-sandbox — Post-Review Checklist

**Last updated:** 2026-04-20
**Companion to:** `PLAN.md`

Legend: `[ ]` todo, `[x]` done, `[~]` partial / accepted risk

---

## 1. Install and Bootstrap

- [x] Choose how `foundry-git-safety` is shipped with the main product.
- [x] Update root packaging so default install path provides the git-safety runtime.
- [x] Update `install.sh` so it installs everything needed for a working sandbox.
- [x] Make `cast new` fail closed if git safety is missing.
- [x] Make `cast start` fail closed if git safety is missing.
- [x] Add a smoke test for fresh install -> create sandbox -> proxied `git status`.
- [ ] Update docs that currently claim git safety is installed automatically.

## 2. Runtime Paths and Config

- [x] Replace privileged default paths with user-writable defaults, or add an explicit privileged bootstrap flow.
- [x] Plumb configured `git_safety.server.secrets_path` into `SecretStore`.
- [x] Plumb configured `git_safety.server.data_dir` into all registration/runtime code paths.
- [ ] Plumb configured observability paths into decision-log creation.
- [x] Fix readiness checks to read the real secret-store path.
- [x] Add tests covering non-default configured paths.
- [ ] Verify default startup works for an unprivileged user on a clean machine.

## 3. Sandbox Registration and Repo Root

- [x] Persist a host-side `repo_root` during sandbox registration.
- [x] Ensure sandbox metadata includes enough information to resolve the correct host worktree.
- [x] Remove `/git-workspace` as an implicit standalone-host fallback.
- [x] Fail closed with a clear message when `repo_root` is missing or invalid.
- [x] Add integration test: registered sandbox can run proxied `git status`.
- [x] Add integration test: missing `repo_root` returns controlled error.
- [ ] Add integration test: blocked commands still return `422`.

## 4. Observability Must Be Best-Effort

- [x] Make decision-log writes best-effort.
- [x] Prevent logging failures from changing expected `401`/`422` responses into `500`s.
- [x] Keep metrics emission non-fatal.
- [ ] Surface degraded observability in health/readiness output.
- [x] Add unit tests for unwritable decision-log directory.
- [ ] Add integration tests for denial paths while logging is unavailable.

## 5. CI and Test Strategy

- [ ] Add required CI job for `foundry-git-safety` unit tests.
- [ ] Add required CI job for `foundry-git-safety` security tests.
- [ ] Add required CI job for `foundry-git-safety` integration tests.
- [ ] Keep root-package tests as a separate CI job.
- [ ] Run standalone-package tests from their own working directory or isolated import root.
- [ ] Document the pytest invocation pattern needed to avoid test-package collisions.
- [ ] Update `scripts/ci-local.sh` to match CI coverage.

## 6. HMAC Secret Placement

- [ ] Decide whether `.foundry/hmac-secret` can be removed from the synced repo worktree.
- [ ] If it cannot be moved, block it from staging and pushing.
- [ ] Add tests proving the secret cannot be committed accidentally.
- [ ] Document the security model and residual risk for wrapper-secret placement.

## 7. Docs and Operator Cleanup

- [ ] Update `README.md` install/runtime claims.
- [ ] Update `docs/getting-started.md`.
- [ ] Update `docs/configuration.md`.
- [ ] Update `docs/operations.md`.
- [ ] Add troubleshooting guidance for:
  - [ ] missing `foundry-git-safety`
  - [ ] bad secrets/data paths
  - [ ] bad sandbox registration / missing `repo_root`
  - [ ] degraded decision logging

## 8. Release Blockers

- [ ] Fresh install provides a working `foundry-git-safety` runtime.
- [ ] `cast new` and `cast start` fail closed on missing safety prerequisites.
- [ ] Registered sandboxes use the correct host worktree for proxied git.
- [ ] Observability failures no longer produce `500`s.
- [ ] Required CI covers both packages.
