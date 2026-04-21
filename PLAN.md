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

1. Packaged installs do not include the root `stubs/git-wrapper-sbx.sh` or `scripts/build-foundry-template.sh` assets, while runtime code depends on them.
2. `cast new` and `cast start` can continue after git-safety wrapper provisioning fails, leaving metadata that claims git safety is enabled.
3. `cast migrate-to-sbx` converts metadata but does not create sbx sandboxes, inject wrappers, register git-safety state, or provision HMAC secrets.
4. The security model documents a GitHub API safety filter, but the runtime start path does not appear to start or route traffic through that filter.
5. Watchdog HMAC rotation rewrites secrets on disk but does not invalidate the running git-safety server's cached secret.
6. User-service and deep-policy proxy paths are not strongly authenticated per sandbox.
7. Installer checks and release metadata still contain pre-sbx assumptions.
8. CI lacks a live installed-wheel sbx smoke test and does not prove the migration boundary end to end.

---

## 3. Workstreams

### 3.1 Package Runtime Assets and Fail Closed

Current state:
- The root wheel packages only `foundry_sandbox`.
- Runtime code reads wrapper/template assets from repo-root paths that do not exist in installed wheels.
- Wrapper injection and checksum failures are warnings in normal flows.

Required work:
- Decide the runtime asset source:
  - Prefer `foundry_git_safety` package resources for the canonical wrapper.
  - Include template-building assets in the root package or replace shell-script lookup with package resources.
- Replace repo-root path assumptions with `importlib.resources` or another installed-package-safe lookup.
- Make wrapper injection, checksum generation, and wrapper integrity repair fatal by default.
- Add an explicit diagnostic or unsafe escape hatch only if needed for development.
- Set `git_safety_enabled=True` only after provisioning succeeds.
- Add wheel packaging tests that build the root wheel and verify required assets are available from the installed artifact.

Exit criteria:
- A locally built wheel can run `cast new` without relying on the source checkout.
- Missing wrapper/template assets produce a hard failure with a clear error.
- Metadata never reports git safety enabled unless wrapper provisioning and checksum verification succeeded.

### 3.2 Define and Implement Real sbx Migration Semantics

Current state:
- Migration docs promise automatic sandbox migration.
- `migrate-to-sbx` converts metadata and presets but does not create sbx sandboxes or provision git safety.
- Converted metadata can describe non-existent or unsafe sbx sandboxes.

Required work:
- Pick one migration contract:
  - Full migration: create sbx sandboxes, preserve workspace state, provision git safety, and verify startability.
  - Metadata-only migration: migrate presets/configuration and explicitly mark old sandboxes as requiring recreation.
- Update docs and command output to match the chosen contract.
- If full migration is chosen, share the same provisioning path used by `cast new`.
- If metadata-only migration is chosen, avoid writing metadata that `cast start` treats as a ready sbx sandbox.
- Add an end-to-end migration smoke test for the chosen behavior.

Exit criteria:
- A migrated sandbox is either startable and fully protected, or clearly marked as not migrated/requiring recreation.
- `cast migrate-to-sbx` output does not overstate what happened.
- Tests cover the exact migration contract.

### 3.3 Centralize sbx Git-Safety Provisioning

Current state:
- New sandbox creation, start-time repair, watchdog repair, and migration need the same safety setup but implement pieces independently.

Required work:
- Introduce a single provisioning function for:
  - Wrapper injection.
  - Wrapper checksum computation and metadata update.
  - Sandbox registration with git-safety.
  - Host and guest HMAC secret creation.
  - Verification that the sandbox can reach git-safety through the expected path.
- Use this function from `cast new`, `cast start` repair, watchdog repair, and migration.
- Return structured provisioning status so commands can print precise failures.

Exit criteria:
- There is one primary code path for provisioning git safety into an sbx sandbox.
- Callers cannot silently downgrade from protected to unprotected operation.

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
- Watchdog rotation writes new secret files.
- The running git-safety server caches secrets and is not notified by watchdog rotation.

Required work:
- Add one of:
  - An authenticated local admin endpoint or CLI command to rotate/revoke a sandbox secret and clear server cache.
  - File mtime/version-aware secret reloading in `SecretStore`.
  - A short TTL cache with atomic file reload semantics.
- Update watchdog to use the chosen rotation mechanism.
- Add an integration test that primes the cache, rotates the secret from a host process, and verifies the old HMAC is rejected.

Exit criteria:
- Old HMAC secrets stop working after watchdog rotation without requiring a server restart.

### 3.6 Harden Per-Sandbox Proxy Authorization

Current state:
- User-service proxy requests can access configured host credentials without a per-sandbox capability check.
- Deep-policy proxy rate limits by a spoofable `X-Sandbox-Id` header.

Required work:
- Add per-sandbox authorization to user-service proxy requests.
- Require HMAC or a scoped capability token before injecting host service credentials.
- Make deep-policy identity derive from verified sandbox authentication instead of caller-supplied headers.
- Add tests proving one sandbox cannot use another sandbox's service capability.

Exit criteria:
- Host credentials are only injected for sandboxes authorized to use that service.
- Spoofing `X-Sandbox-Id` does not bypass rate limits or policy.

### 3.7 Align Installer and Release Metadata

Current state:
- `install.sh` still validates Docker/tmux and touches `unified-proxy` paths.
- The changelog declares 0.21.0 while package metadata still reports 0.20.15.

Required work:
- Replace stale installer checks with sbx-specific validation.
- Remove tmux and unified-proxy setup from the installer unless still required by live code.
- Validate `sbx` availability and supported version during install.
- Bump package version metadata to 0.21.0 or align the changelog with the actual release version.
- Update any fallback `__version__` values to avoid stale reporting.

Exit criteria:
- Fresh install checks the dependencies actually required by the sbx implementation.
- Built artifacts and changelog agree on the release version.

### 3.8 Add Live Release Gates

Current state:
- Unit tests cover many helper paths.
- CI does not prove an installed wheel can create and operate a real sbx sandbox.

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
- Add a separate migration smoke test for the chosen migration contract.
- Add shellcheck or equivalent coverage for the active sbx wrapper scripts.
- Keep root-package and `foundry-git-safety` pytest invocations isolated.

Exit criteria:
- CI has a required or manually triggered gate that validates the real sbx runtime path.
- Release sign-off does not rely only on unit tests.

---

## 4. Execution Order

1. Package assets and fail closed.
2. Centralize git-safety provisioning.
3. Define and implement migration semantics.
4. Fix HMAC rotation cache invalidation.
5. Wire or correct GitHub API filtering.
6. Harden user-service and deep-policy proxy authorization.
7. Align installer and version metadata.
8. Add live release gates and update docs to match final behavior.

This order prioritizes the paths that can create misleading or unsafe sandboxes before hardening secondary proxy surfaces.

---

## 5. Verification Gate

Before calling this plan complete:

- Root unit tests pass.
- `foundry-git-safety` unit, security, and integration tests pass.
- Built wheels contain or can locate all runtime assets.
- `cast new` from an installed wheel provisions git safety and fails closed on provisioning errors.
- `cast start` cannot silently start an unprotected sandbox that claims git safety is enabled.
- `cast migrate-to-sbx` behavior matches the documented migration contract.
- Watchdog HMAC rotation invalidates old secrets in the running server.
- GitHub API protection is either live-tested or removed from the release security claims.
- Installer validates sbx-era dependencies.
- Version metadata and changelog agree.
