# foundry-sandbox - sbx Migration Release Readiness Checklist

**Last updated:** 2026-04-21
**Companion to:** `PLAN.md`

Legend: `[ ]` todo, `[x]` done, `[~]` partial / accepted risk

---

## 3.1 Package Runtime Assets and Fail Closed

- [x] Choose canonical wrapper asset source
- [x] Replace repo-root wrapper lookup with installed-package-safe resource lookup
- [x] Replace repo-root template builder lookup with installed-package-safe resource lookup or remove dependency
- [x] Make `cast new` fail when wrapper injection fails
- [x] Make `cast new` fail when checksum generation fails
- [x] Make `cast start` fail when wrapper integrity cannot be verified or repaired
- [x] Remove `FileNotFoundError → is_ok = True` short-circuit from `cast start`
- [x] Remove the equivalent `FileNotFoundError → early-return` short-circuit from the watchdog poll
- [x] Only write `git_safety_enabled=True` after provisioning succeeds (shared with §3.3)
- [x] Add wheel test proving runtime assets are present or resolvable
- [x] Add negative test proving missing assets fail closed on `cast new`
- [x] Add negative test proving missing assets fail closed on `cast start`
- [x] Add negative test proving missing assets fail closed on the watchdog poll

## 3.2 Define and Implement Real sbx Migration Semantics

- [x] Decide migration contract: full sandbox migration or metadata-only migration
- [x] Update `cast migrate-to-sbx` command output for chosen contract
- [x] Update migration docs for chosen contract
- [x] Prevent ready-state metadata for non-existent sbx sandboxes (enforced by §3.3 helper)
- [x] Define behavior for pre-existing 0.20.x worktrees (reparent, re-clone, or refuse)
- [~] If full migration: create sbx sandbox during migration via §3.3 helper
- [~] If full migration: preserve or attach workspace state
- [~] If full migration: provision wrapper, HMAC secrets, and git-safety registration via §3.3 helper
- [x] If metadata-only: confirm §3.3 helper refuses to mark unprovisioned records as protected (no new "migrated" flag)
- [x] Add migration smoke test for chosen behavior, including existing-worktree case

## 3.3 Centralize sbx Git-Safety Provisioning

- [x] Create shared provisioning function
- [x] Provision wrapper through shared function
- [x] Compute and store wrapper checksum through shared function
- [x] Register sandbox with git-safety through shared function
- [x] Create host HMAC secret through shared function
- [x] Create guest HMAC secret through shared function
- [x] Verify sandbox connectivity to git-safety through shared function
- [x] Helper is the only writer of `git_safety_enabled=True` in metadata
- [x] Use shared provisioning from `cast new`
- [x] Use shared provisioning from `cast start` repair path
- [x] Use shared provisioning from watchdog repair path
- [x] Use shared provisioning from migration path, if full migration is chosen
- [x] Return structured provisioning failures to CLI callers
- [x] Detect stale foundry template digest and surface re-provisioning requirement on `cast start`

## 3.4 Wire or Correct GitHub API Safety Layer

- [x] Decide whether GitHub API filtering is in scope for 0.21.0
- [~] If in scope: start GitHub API filter with git-safety service
- [~] If in scope: supervise GitHub API filter health
- [~] If in scope: route sandbox GitHub API traffic through the filter
- [~] If in scope: add live test for blocked PR merge/update GitHub API calls
- [x] If deferred: remove or qualify GitHub API filter claims in security docs
- [x] If deferred: document residual risk and unsupported commands

**Resolution:** Removed standalone `github_filter.py` proxy (port 8084) entirely. The deep policy sidecar (`deep-policy-github.yaml`) on port 8083 is the sole GitHub API protection mechanism. Updated security model, architecture docs, ADR-011, config schema, and CLI. Deleted dead code, config, and 4 test files that exclusively tested the removed proxy.

## 3.5 Fix HMAC Rotation Cache Invalidation

- [x] Choose cache invalidation design
- [x] Implement server-side cache invalidation or reload mechanism
- [x] Update watchdog to use the rotation mechanism
- [x] If rotation uses a new endpoint: authenticate the endpoint
- [x] Add integration test that primes server cache
- [x] Add integration test that rotates secret from a host process
- [x] Add assertion that old HMAC is rejected after rotation
- [x] Add assertion that new HMAC is accepted after rotation
- [x] Add assertion that an unauthenticated caller cannot trigger rotation

## 3.6 Harden Per-Sandbox Proxy Authorization

- [x] Add per-sandbox authorization to user-service proxy requests
- [x] Require HMAC or scoped capability token before injecting host service credentials
- [x] Bind service permissions to sandbox metadata or registration state
- [x] Stop trusting caller-supplied `X-Sandbox-Id` for deep-policy identity
- [x] Define and implement rejection path for unauthenticated callers (no shared `"unknown"` bucket)
- [x] Add test proving unauthorized sandbox cannot use a service credential
- [x] Add test proving one sandbox cannot spoof another sandbox's identity
- [x] Add test proving rate limits use verified sandbox identity
- [x] Add test proving unauthenticated callers are rejected on the documented path

## 3.7 Align Installer and Release Metadata

- [x] Remove stale tmux requirement from installer if no longer needed
- [x] Remove stale unified-proxy setup from installer
- [x] Replace generic Docker checks with sbx-era dependency checks
- [x] Validate `sbx` binary availability during install
- [x] Validate supported `sbx` version during install
- [x] Align package version with changelog release version
- [x] Update stale fallback `__version__` values
- [x] Bound `foundry-git-safety[server]` dependency with `~=` or explicit upper bound
- [x] Rebuild wheel and confirm artifact version

## 3.8 Add Live Release Gates

- [x] Build root wheel in CI smoke gate
- [x] Build `foundry-git-safety` wheel in CI smoke gate
- [x] Install wheels into clean environment
- [x] Run `cast diagnose`
- [x] Create a real sbx sandbox
- [x] Verify wrapper file exists in sandbox
- [x] Verify wrapper checksum matches metadata
- [x] Run basic git command through wrapper
- [x] Prove protected push path is blocked or shadowed as expected
- [~] Prove GitHub API merge/update path is blocked if filter is in scope
- [x] Destroy smoke-test sandbox
- [x] Add migration smoke test
- [x] Add named-asset packaging assertion covering `git-wrapper-sbx.sh`, template build helper, and `foundry_git_safety/default_config/*.yaml`
- [x] Shellcheck active sbx wrapper scripts
- [x] Keep root-package and `foundry-git-safety` pytest invocations isolated

**Note:** GitHub API merge/update blocking (item 10) is accepted risk — the GitHub filter was removed per §3.4 resolution. The deep-policy sidecar is the sole mechanism; live testing requires a running deep-policy proxy which needs sbx networking. The local smoke tests include `test_protected_push_blocked` which verifies the git-safety stack blocks protected branch pushes.

## 3.9 Decide Tamper-Event Delivery Policy

- [x] Decide delivery contract (fatal / buffered / metric-only)
- [x] Remove bare `except Exception: pass` from `emit_wrapper_tamper_event`
- [x] Implement the chosen delivery mechanism
- [x] Surface tamper-event status in `cast diagnose` and/or `/metrics`
- [x] Add test: tamper event in sandbox with read-only decision-log directory is still observable

**Resolution:** Metric-only approach. The watchdog POSTs tamper events to `POST /tamper-event` on the git-safety server, which always increments `wrapper_tamper_events_total` (Prometheus counter) and writes to the decision log best-effort (returns 202 if counter incremented but log write failed). On server unreachable, the watchdog falls back to a local counter + direct decision log write + WARNING log. `cast diagnose` surfaces the server counter alongside decision-log entries and flags when counter > log entries (degraded log indicator).

---

## Final Verification Gate

- [x] Root unit tests pass
- [x] `foundry-git-safety` unit tests pass
- [x] `foundry-git-safety` security tests pass
- [x] `foundry-git-safety` integration tests pass
- [x] Built wheels contain or can locate all runtime assets (named explicitly)
- [ ] Installed-wheel `cast new` provisions git safety successfully
- [ ] Installed-wheel `cast new` fails closed on provisioning errors
- [ ] Installed-wheel `cast start` fails closed when the wrapper stub is missing
- [ ] Installed-wheel watchdog fails closed when the wrapper stub is missing
- [ ] `cast start` cannot silently start an unprotected sandbox with protected metadata
- [x] Only the shared §3.3 helper writes `git_safety_enabled=True`
- [x] `cast migrate-to-sbx` behavior matches documented contract, including existing-worktree handling
- [x] Watchdog rotation invalidates old HMAC secrets without server restart
- [x] Rotation mechanism rejects unauthenticated callers
- [x] Proxy endpoints reject unauthenticated callers on a documented path
- [x] `X-Sandbox-Id` spoofing does not bypass rate limits
- [x] Tamper events are observable even with a degraded decision log
- [x] GitHub API protection is live-tested or removed from security claims
- [x] Installer validates sbx-era dependencies
- [x] Package metadata and changelog agree on version
- [x] `foundry-git-safety[server]` dependency range is bounded
- [x] `git diff --check main HEAD` is clean
