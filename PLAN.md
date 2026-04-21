# foundry-sandbox - sbx Migration Release Readiness Plan

**Last updated:** 2026-04-21
**Branch:** `sbx`
**Scope:** Close the correctness, safety, packaging, and verification gaps found during the senior engineering review of the sbx migration.

---

## 1. Objective

Make the sbx migration releasable by proving that installed builds create, migrate, start, and operate sandboxes with the same safety boundaries documented in the security model.

The release should fail closed when git safety cannot be provisioned, migration should not create misleading metadata, and CI should exercise at least one real installed-wheel sbx flow instead of only unit-level behavior.

---

## 2. Review Findings Driving This Plan

1. Packaged installs do not include the root `stubs/git-wrapper-sbx.sh` or `scripts/build-foundry-template.sh` assets, while runtime code depends on them (`foundry_sandbox/git_safety.py:242,449`).
2. `cast new` and `cast start` can continue after git-safety wrapper provisioning fails, leaving metadata that claims git safety is enabled (`commands/new_sbx.py:174-184,249-259`).
3. `cast start` treats a missing local wrapper stub as "integrity OK" because `FileNotFoundError` from `compute_wrapper_checksum` is caught and forces `is_ok = True` (`commands/start.py:87-94`). The same pattern short-circuits the watchdog at `watchdog.py:69-72`.
4. `cast migrate-to-sbx` converts metadata but does not create sbx sandboxes, inject wrappers, register git-safety state, or provision HMAC secrets (`commands/migrate.py:_convert_one_sandbox`). It also has no story for existing worktrees from the 0.20.x layout.
5. The security model documents a GitHub API safety filter, but `foundry_git_safety.github_filter` is referenced only by tests — `server.py` / `cli.py` never start it or route `api.github.com` traffic through it.
6. Watchdog HMAC rotation rewrites secrets on disk but does not invalidate the running git-safety server's cached secret (`foundry_git_safety/auth.py:50-69` memoizes reads; `revoke()`/`rotate()` are never called out-of-process).
7. User-service and deep-policy proxy paths are not strongly authenticated per sandbox: `user_services_proxy.py:68-102` injects host-env credentials with no caller verification, and `deep_policy_proxy.py:67-73` keys rate limits on a caller-supplied `X-Sandbox-Id`.
8. Installer checks and release metadata still contain pre-sbx assumptions: `install.sh` installs tmux, checks `docker info`, and touches `unified-proxy/` stubs; `pyproject.toml` says 0.20.15 while `CHANGELOG.md` declares 0.21.0; `foundry_sandbox/__init__.py:8` falls back to `"0.13.0"`.
9. CI lacks a live installed-wheel sbx smoke test and does not prove the migration boundary end to end. No test currently builds a wheel and exercises `cast new` against it.
10. Dependency on `foundry-git-safety[server]>=0.1.0` is unpinned, so any internal API change in the git-safety package during the experimental phase silently ships with a 0.21.x release.
11. `emit_wrapper_tamper_event` (`git_safety.py:497-524`) swallows all exceptions, so tamper notifications can vanish when the decision log is unwritable — in the same scenario where `/ready` intentionally stays 200 ("degraded logging is non-fatal").

---

## 3. Workstreams

### 3.1 Package Runtime Assets and Fail Closed

Current state:
- The root wheel packages only `foundry_sandbox` (`pyproject.toml:96`).
- Runtime code reads wrapper/template assets from repo-root paths that do not exist in installed wheels (`git_safety.py:242,449`).
- Wrapper injection and checksum failures are warnings in normal flows.
- `cast start` and the watchdog both short-circuit to "integrity OK" when the local wrapper stub is missing, which is the exact failure mode on a wheel install.

Required work:
- Decide the runtime asset source:
  - Prefer `foundry_git_safety` package resources for the canonical wrapper.
  - Include template-building assets in the root package or replace shell-script lookup with package resources.
- Replace repo-root path assumptions with `importlib.resources` or another installed-package-safe lookup.
- Make wrapper injection, checksum generation, and wrapper integrity repair fatal by default on **both** `cast new` and `cast start`.
- Change `FileNotFoundError` handling in `start.py` and `watchdog.py` so a missing wrapper asset raises or surfaces an error — never silently sets `is_ok = True`.
- Add an explicit diagnostic or unsafe escape hatch only if needed for development.
- Set `git_safety_enabled=True` only after provisioning succeeds (shared with §3.3).
- Add wheel packaging tests that build the root wheel and verify each required asset (`git-wrapper-sbx.sh`, template build script or its replacement, any default YAML shipped out of `foundry_git_safety/default_config/`) is resolvable from the installed artifact.

Exit criteria:
- A locally built wheel can run `cast new` without relying on the source checkout.
- Missing wrapper/template assets produce a hard failure with a clear error on `cast new`, `cast start`, and the watchdog poll.
- Metadata never reports git safety enabled unless wrapper provisioning and checksum verification succeeded.

### 3.2 Define and Implement Real sbx Migration Semantics

Current state:
- Migration docs promise automatic sandbox migration.
- `migrate-to-sbx` converts metadata and presets but does not create sbx sandboxes or provision git safety (`commands/migrate.py:_convert_one_sandbox`).
- Converted metadata can describe non-existent or unsafe sbx sandboxes.
- Existing 0.20.x worktrees under the old layout have no reparenting story; `ensure_bare_repo` / `create_worktree` assume fresh creation.

Required work:
- Pick one migration contract:
  - Full migration: create sbx sandboxes, preserve workspace state, provision git safety, and verify startability.
  - Metadata-only migration: migrate presets/configuration and explicitly mark old sandboxes as requiring recreation.
- Update docs and command output to match the chosen contract.
- If full migration is chosen:
  - Share the same provisioning path used by `cast new` (via §3.3).
  - Define explicit handling for pre-existing worktrees (reparent, re-clone, or refuse and error).
- If metadata-only migration is chosen, rely on the §3.3 helper to refuse writing `git_safety_enabled=True` for sandboxes that don't exist in `sbx` yet. Do not invent a separate "migrated" flag that `cast start` has to special-case.
- Add an end-to-end migration smoke test for the chosen behavior.

Exit criteria:
- A migrated sandbox is either startable and fully protected, or clearly marked as not migrated/requiring recreation.
- `cast migrate-to-sbx` output does not overstate what happened.
- Tests cover the exact migration contract, including the existing-worktree case.

### 3.3 Centralize sbx Git-Safety Provisioning

Current state:
- New sandbox creation (`new_sbx.py:157-178`), start-time repair (`start.py:95-109`), and watchdog repair (`watchdog.py:109-161`) duplicate the same five-step sequence (HMAC gen → write guest secret → write server secret → register → inject) in slightly different forms, with inconsistent failure handling across the three sites.
- Migration (§3.2) does none of these today and needs to share this path if it becomes full-migration.

Required work:
- Introduce a single provisioning function for:
  - Wrapper injection.
  - Wrapper checksum computation and metadata update.
  - Sandbox registration with git-safety.
  - Host and guest HMAC secret creation.
  - Verification that the sandbox can reach git-safety through the expected path.
- Route all four callers (`cast new`, `cast start` repair, watchdog repair, migration full-path) through this helper. No caller writes `git_safety_enabled=True` directly; only the helper does, and only after verification.
- Return structured provisioning status so commands can print precise failures.
- Include a "template compatibility" check that detects sandboxes built from a stale foundry template (e.g., after an `sbx` upgrade that rebuilt the template) so `cast start` can force re-provisioning rather than assuming an older wrapper version is still valid.

Exit criteria:
- There is one primary code path for provisioning git safety into an sbx sandbox.
- Callers cannot silently downgrade from protected to unprotected operation.
- Running sandboxes whose template digest is stale are surfaced as requiring re-provisioning.

### 3.4 Wire or Correct the GitHub API Safety Layer

Current state:
- The security model documents a GitHub API filter on port 8084.
- The filter code exists, but the git-safety CLI start path appears to start only the git API server.

Required work:
- Decide whether GitHub API filtering is required for this release.
- If required:
  - Start and supervise the GitHub API filter with git-safety.
  - Ensure sandbox GitHub API traffic is routed through it.
  - Add a live test proving `gh api` merge/update operations are blocked.
- If deferred:
  - Remove or qualify the security-model claim.
  - Document the residual risk and unsupported commands.

Exit criteria:
- The documented GitHub API protection is either enforced by runtime behavior or explicitly marked out of scope.

### 3.5 Fix HMAC Rotation Cache Invalidation

Current state:
- Watchdog rotation writes new secret files (`watchdog.py:123-127`).
- The running git-safety server caches secrets in `SecretStore._cache` (`foundry_git_safety/auth.py:50-69`) with no mtime check; `revoke()` and `rotate()` exist but are not called from any out-of-process path.

Required work:
- Add one of:
  - An authenticated local admin endpoint or CLI command to rotate/revoke a sandbox secret and clear server cache.
  - File mtime/version-aware secret reloading in `SecretStore`.
  - A short TTL cache with atomic file reload semantics.
- Update watchdog to use the chosen rotation mechanism.
- Add an integration test that primes the cache, rotates the secret from a host process, and verifies the old HMAC is rejected.
- Authenticate the admin path (if that's the chosen design) — the rotation mechanism itself must not become a new unauthenticated endpoint exposed on the same socket.

Exit criteria:
- Old HMAC secrets stop working after watchdog rotation without requiring a server restart.
- The rotation mechanism is not itself spoofable from within a sandbox or from another local process.

### 3.6 Harden Per-Sandbox Proxy Authorization

Current state:
- User-service proxy requests (`user_services_proxy.py:68-102`) inject host-env credentials into upstream calls with no caller authentication.
- Deep-policy proxy (`deep_policy_proxy.py:67-73`) rate-limits by a caller-supplied `X-Sandbox-Id` header.
- Unauthenticated requests currently collapse into a shared `"unknown"` bucket, silently degrading rate limiting for everyone.

Required work:
- Add per-sandbox authorization to user-service proxy requests.
- Require HMAC or a scoped capability token before injecting host service credentials.
- Make deep-policy identity derive from verified sandbox authentication instead of caller-supplied headers.
- Decide explicit behavior for unauthenticated callers: reject with 401/403, or route to a dedicated penalty bucket — not a shared "unknown" entry.
- Add tests proving one sandbox cannot use another sandbox's service capability.

Exit criteria:
- Host credentials are only injected for sandboxes authorized to use that service.
- Spoofing `X-Sandbox-Id` does not bypass rate limits or policy.
- Unauthenticated requests follow a documented, tested rejection path.

### 3.7 Align Installer and Release Metadata

Current state:
- `install.sh` still validates Docker/tmux and touches `unified-proxy` paths.
- The changelog declares 0.21.0 while package metadata still reports 0.20.15.
- `foundry_sandbox/__init__.py:8` falls back to `"0.13.0"` — eight releases stale.
- `pyproject.toml:33` pins `foundry-git-safety[server]>=0.1.0`, an unbounded range against an experimental internal API.

Required work:
- Replace stale installer checks with sbx-specific validation.
- Remove tmux and unified-proxy setup from the installer unless still required by live code.
- Validate `sbx` availability and supported version during install.
- Bump package version metadata to 0.21.0 or align the changelog with the actual release version.
- Update any fallback `__version__` values to avoid stale reporting.
- Pin `foundry-git-safety[server]` with a compatible-release operator (e.g. `~=0.1.0`) or an explicit upper bound so internal API changes during the experimental phase cannot silently ship with a 0.21.x release.

Exit criteria:
- Fresh install checks the dependencies actually required by the sbx implementation.
- Built artifacts and changelog agree on the release version.
- `foundry-git-safety` dependency range is bounded.

**Note:** This workstream is cheap and independent of the correctness fixes — can (and should) run in parallel with §3.1–§3.3.

### 3.8 Add Live Release Gates

Current state:
- Unit tests cover many helper paths.
- CI does not prove an installed wheel can create and operate a real sbx sandbox.
- No test exercises `importlib.resources` (because it isn't used yet — see §3.1).

Required work:
- Add an installed-wheel smoke test:
  - Build root wheel and git-safety wheel.
  - Install them into a clean environment.
  - Run `cast diagnose`.
  - Create a sandbox.
  - Verify wrapper injection and checksum.
  - Run a basic git command through the wrapper.
  - Prove blocked push/merge paths.
  - Destroy the sandbox.
- Add a negative wheel test that names each required asset explicitly — `git-wrapper-sbx.sh`, the template build helper, and `foundry_git_safety/default_config/*.yaml` — and asserts it resolves from the installed package.
- Add a separate migration smoke test for the chosen migration contract.
- Add shellcheck or equivalent coverage for the active sbx wrapper scripts.
- Keep root-package and `foundry-git-safety` pytest invocations isolated.

Exit criteria:
- CI has a required or manually triggered gate that validates the real sbx runtime path.
- Release sign-off does not rely only on unit tests.
- Every runtime asset is named in at least one packaging assertion.

### 3.9 Decide Tamper-Event Delivery Policy

Current state:
- `emit_wrapper_tamper_event` (`git_safety.py:497-524`) swallows all exceptions.
- `/ready` is intentionally non-fatal for decision-log failures (Phase 8).
- A broken log therefore silently drops tamper notifications in exactly the failure mode where observability matters most.

Required work:
- Decide the contract:
  - Fatal emission: failure to record a tamper event aborts re-injection and surfaces a CLI/watchdog error.
  - Buffered emission: in-memory ring buffer surfaced via `/metrics` or `cast diagnose` when the log is unavailable.
  - Metric-only: increment a Prometheus counter for tamper events even when the log write fails.
- Implement the chosen option and remove the bare `except Exception: pass`.
- Add a test that writes to a read-only decision-log directory and asserts tamper events are still counted / surfaced through the chosen channel.

Exit criteria:
- Wrapper tamper events cannot disappear silently.
- Operators can observe tamper activity even with a degraded decision log.

---

## 4. Execution Order

1. Align installer and release metadata (§3.7). Cheap, independent, unblocks clean wheel builds for everything downstream.
2. Package runtime assets and fail closed (§3.1).
3. Centralize git-safety provisioning (§3.3) — this is the refactor that makes §3.1's "fail closed" invariant enforceable everywhere and prevents §3.2 from re-introducing the same bug.
4. Define and implement migration semantics (§3.2), reusing the §3.3 helper.
5. Fix HMAC rotation cache invalidation (§3.5).
6. Harden user-service and deep-policy proxy authorization (§3.6).
7. Decide tamper-event delivery policy (§3.9).
8. Wire or correct GitHub API filtering (§3.4). This is a scope decision that can be deferred without blocking correctness fixes upstream; resolving it late avoids speculative work if the filter is dropped from 0.21.0.
9. Add live release gates and update docs to match final behavior (§3.8).

This order puts the §3.1 + §3.3 correctness foundation first because both classes of "claims git safety, isn't actually protected" bugs share a root cause. §3.7 runs in parallel at the start. The GitHub-filter scope call (§3.4) is intentionally late so it doesn't gate the correctness track.

---

## 5. Verification Gate

Before calling this plan complete:

- Root unit tests pass.
- `foundry-git-safety` unit, security, and integration tests pass.
- Built wheels contain or can locate all runtime assets (named explicitly in the packaging test).
- `cast new` from an installed wheel provisions git safety and fails closed on provisioning errors.
- `cast start` cannot silently start an unprotected sandbox that claims git safety is enabled, including when the local wrapper stub is missing.
- Watchdog cannot skip integrity checks because the local wrapper stub is missing.
- All four provisioning callers (`cast new`, `cast start` repair, watchdog, migration full-path if chosen) route through a single helper; `git_safety_enabled=True` is only written by that helper.
- `cast migrate-to-sbx` behavior matches the documented migration contract, including handling of pre-existing 0.20.x worktrees.
- Watchdog HMAC rotation invalidates old secrets in the running server.
- The rotation mechanism itself is authenticated.
- User-service and deep-policy proxy endpoints reject unauthenticated callers on a documented path; `X-Sandbox-Id` spoofing does not bypass rate limits.
- Wrapper tamper events are delivered through a documented channel even when the decision log is unavailable.
- GitHub API protection is either live-tested or removed from the release security claims.
- Installer validates sbx-era dependencies.
- Version metadata and changelog agree; `foundry-git-safety` dependency is version-bounded.
