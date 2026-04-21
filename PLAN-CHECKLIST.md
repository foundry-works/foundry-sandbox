# foundry-sandbox - sbx Migration Release Readiness Checklist

**Last updated:** 2026-04-21
**Companion to:** `PLAN.md`

Legend: `[ ]` todo, `[x]` done, `[~]` partial / accepted risk

---

## 3.1 Package Runtime Assets and Fail Closed

- [ ] Choose canonical wrapper asset source
- [ ] Replace repo-root wrapper lookup with installed-package-safe resource lookup
- [ ] Replace repo-root template builder lookup with installed-package-safe resource lookup or remove dependency
- [ ] Make `cast new` fail when wrapper injection fails
- [ ] Make `cast new` fail when checksum generation fails
- [ ] Make `cast start` fail when wrapper integrity cannot be verified or repaired
- [ ] Only write `git_safety_enabled=True` after provisioning succeeds
- [ ] Add wheel test proving runtime assets are present or resolvable
- [ ] Add negative test proving missing assets fail closed

## 3.2 Define and Implement Real sbx Migration Semantics

- [ ] Decide migration contract: full sandbox migration or metadata-only migration
- [ ] Update `cast migrate-to-sbx` command output for chosen contract
- [ ] Update migration docs for chosen contract
- [ ] Prevent ready-state metadata for non-existent sbx sandboxes
- [ ] If full migration: create sbx sandbox during migration
- [ ] If full migration: preserve or attach workspace state
- [ ] If full migration: provision wrapper, HMAC secrets, and git-safety registration
- [ ] If metadata-only: mark migrated records as requiring recreation
- [ ] Add migration smoke test for chosen behavior

## 3.3 Centralize sbx Git-Safety Provisioning

- [ ] Create shared provisioning function
- [ ] Provision wrapper through shared function
- [ ] Compute and store wrapper checksum through shared function
- [ ] Register sandbox with git-safety through shared function
- [ ] Create host HMAC secret through shared function
- [ ] Create guest HMAC secret through shared function
- [ ] Verify sandbox connectivity to git-safety through shared function
- [ ] Use shared provisioning from `cast new`
- [ ] Use shared provisioning from `cast start` repair path
- [ ] Use shared provisioning from watchdog repair path
- [ ] Use shared provisioning from migration path, if full migration is chosen
- [ ] Return structured provisioning failures to CLI callers

## 3.4 Wire or Correct GitHub API Safety Layer

- [ ] Decide whether GitHub API filtering is in scope for 0.21.0
- [ ] If in scope: start GitHub API filter with git-safety service
- [ ] If in scope: supervise GitHub API filter health
- [ ] If in scope: route sandbox GitHub API traffic through the filter
- [ ] If in scope: add live test for blocked PR merge/update GitHub API calls
- [ ] If deferred: remove or qualify GitHub API filter claims in security docs
- [ ] If deferred: document residual risk and unsupported commands

## 3.5 Fix HMAC Rotation Cache Invalidation

- [ ] Choose cache invalidation design
- [ ] Implement server-side cache invalidation or reload mechanism
- [ ] Update watchdog to use the rotation mechanism
- [ ] Add integration test that primes server cache
- [ ] Add integration test that rotates secret from a host process
- [ ] Add assertion that old HMAC is rejected after rotation
- [ ] Add assertion that new HMAC is accepted after rotation

## 3.6 Harden Per-Sandbox Proxy Authorization

- [ ] Add per-sandbox authorization to user-service proxy requests
- [ ] Require HMAC or scoped capability token before injecting host service credentials
- [ ] Bind service permissions to sandbox metadata or registration state
- [ ] Stop trusting caller-supplied `X-Sandbox-Id` for deep-policy identity
- [ ] Add test proving unauthorized sandbox cannot use a service credential
- [ ] Add test proving one sandbox cannot spoof another sandbox's identity
- [ ] Add test proving rate limits use verified sandbox identity

## 3.7 Align Installer and Release Metadata

- [ ] Remove stale tmux requirement from installer if no longer needed
- [ ] Remove stale unified-proxy setup from installer
- [ ] Replace generic Docker checks with sbx-era dependency checks
- [ ] Validate `sbx` binary availability during install
- [ ] Validate supported `sbx` version during install
- [ ] Align package version with changelog release version
- [ ] Update stale fallback `__version__` values
- [ ] Rebuild wheel and confirm artifact version

## 3.8 Add Live Release Gates

- [ ] Build root wheel in CI smoke gate
- [ ] Build `foundry-git-safety` wheel in CI smoke gate
- [ ] Install wheels into clean environment
- [ ] Run `cast diagnose`
- [ ] Create a real sbx sandbox
- [ ] Verify wrapper file exists in sandbox
- [ ] Verify wrapper checksum matches metadata
- [ ] Run basic git command through wrapper
- [ ] Prove protected push path is blocked or shadowed as expected
- [ ] Prove GitHub API merge/update path is blocked if filter is in scope
- [ ] Destroy smoke-test sandbox
- [ ] Add migration smoke test
- [ ] Shellcheck active sbx wrapper scripts
- [ ] Keep root-package and `foundry-git-safety` pytest invocations isolated

---

## Final Verification Gate

- [ ] Root unit tests pass
- [ ] `foundry-git-safety` unit tests pass
- [ ] `foundry-git-safety` security tests pass
- [ ] `foundry-git-safety` integration tests pass
- [ ] Built wheels contain or can locate all runtime assets
- [ ] Installed-wheel `cast new` provisions git safety successfully
- [ ] Installed-wheel `cast new` fails closed on provisioning errors
- [ ] `cast start` cannot silently start an unprotected sandbox with protected metadata
- [ ] `cast migrate-to-sbx` behavior matches documented contract
- [ ] Watchdog rotation invalidates old HMAC secrets without server restart
- [ ] GitHub API protection is live-tested or removed from security claims
- [ ] Installer validates sbx-era dependencies
- [ ] Package metadata and changelog agree on version
- [ ] `git diff --check main HEAD` is clean
