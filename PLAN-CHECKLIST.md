# sbx Hardening — Checklist

**Last updated:** 2026-04-20
**Companion to:** `PLAN.md`

Legend: `[x]` done, `[ ]` todo

---

## Phase 1: Shrink the tamper window (H1)

- [x] Change `WrapperWatchdog.__init__` default `poll_interval` from `30.0` to `10.0` in `foundry_sandbox/watchdog.py`
- [x] Update `start_watchdog()` default `poll_interval` to match
- [x] Update `--interval` default and help text in `foundry_sandbox/commands/watchdog_cmd.py`
- [x] Update any docs referencing the 30 s interval

## Phase 2: Rotate HMAC on re-injection (H2)

- [x] In `WrapperWatchdog._reinject_wrapper`, generate a fresh HMAC before re-injection
- [x] Write the new HMAC to the worktree via `write_hmac_secret_to_worktree`
- [x] Write the new HMAC to the server via `write_hmac_secret_for_server`
- [x] Resolve worktree path from sandbox metadata (bare repo + branch)
- [x] Confirm `write_hmac_secret_for_server` uses replace semantics (no append)
- [x] Fail-closed: if HMAC write fails, skip re-injection rather than leaving worktree/server desynced

## Phase 3: Tamper event observability (H3)

- [x] Define `wrapper_tamper` event schema (sandbox, expected_sha256, actual_sha256, action, timestamp)
- [x] Add a decision-log write helper (or HTTP endpoint) in `foundry-git-safety/foundry_git_safety/decision_log.py`
- [x] Emit event from `WrapperWatchdog._reinject_wrapper` on success path
- [x] Emit event with `action="reinject_failed"` on failure path
- [x] Suppress event when checksum matches (no-op polls stay silent)
- [x] Surface recent events in `cast diagnose` text output
- [x] Surface recent events in `cast diagnose --json`
- [x] Add alert rule in `docs/observability/alerts.yaml` (rate > 0 over 5 min)
- [x] Document the event schema in `docs/observability.md`

## Phase 4: sbx CLI identity probe (H5)

- [x] In `sbx_check_available()`, resolve the realpath of the `sbx` binary
- [x] Reject paths under `~/.docker/cli-plugins/`
- [x] Reject paths under `/Applications/Docker.app/Contents/Resources/cli-plugins/`
- [x] Reject Windows Docker Desktop plugin paths
- [x] Run a standalone-only probe (e.g. `sbx template ls --help`); require exit 0
- [x] Print actionable error pointing at `brew install docker/tap/sbx` / `winget install Docker.sbx`
- [x] `SystemExit(1)` on probe failure

## Phase 5: Kernel-separation assertion (H7)

- [x] Capture host kernel via `uname -r` in `cast diagnose`
- [x] For each running sandbox, run `sbx_exec(name, ["uname", "-r"])` with a short timeout
- [x] Per-sandbox status: `ok` if kernels differ, `warn` if equal
- [x] Include `isolation` section in `cast diagnose --json`
- [x] Include one-line per-sandbox summary in text output
- [x] Per-sandbox failure (e.g. sandbox stopped) does not fail the overall diagnose run
- [x] Document the assertion in `docs/security/security-model.md`

## Phase 6: Tests

- [ ] `tests/unit/test_watchdog.py` — default interval is 10.0
- [ ] `tests/unit/test_watchdog.py` — HMAC writers called before `inject_git_wrapper` on re-injection
- [ ] `tests/unit/test_watchdog.py` — consecutive tamper events produce different HMAC values
- [ ] `tests/unit/test_watchdog.py` — `wrapper_tamper` event emitted exactly once per mismatch
- [ ] `tests/unit/test_watchdog.py` — no event emitted on matching checksum
- [ ] `tests/unit/test_sbx_identity.py` — Docker Desktop plugin path rejected
- [ ] `tests/unit/test_sbx_identity.py` — standalone path accepted when probe passes
- [ ] `tests/unit/test_sbx_identity.py` — unknown path + failing probe rejected
- [ ] `tests/unit/test_diagnose_isolation.py` — different kernels → status `ok`
- [ ] `tests/unit/test_diagnose_isolation.py` — equal kernels → status `warn` in JSON and text
- [ ] `tests/unit/test_diagnose_isolation.py` — sbx_exec failure per sandbox does not abort diagnose

## Phase 7: Documentation

- [ ] `CHANGELOG.md` — "Added" entry for H1, H2, H3, H5, H7
- [ ] `docs/security/security-model.md` — Wrapper Integrity section updated for HMAC rotation + tamper observability
- [ ] `docs/security/security-model.md` — MicroVM Isolation section updated for kernel-separation check
- [ ] `docs/security/wrapper-integrity.md` — document the rotation invariant
- [ ] `docs/observability.md` — `wrapper_tamper` event schema
- [ ] `docs/observability/alerts.yaml` — new alert rule
- [ ] New ADR `docs/adr/014-tamper-observability.md`

## Deferred

- [ ] H4 — in-VM capability check at wrapper startup (weak on its own; revisit if H1–H3 prove insufficient)
- [ ] H6 — record sbx binary path/version in `SbxSandboxMetadata` at creation (revisit if mid-session CLI swaps become a real signal)

---

## Verification

- [ ] `pytest tests/unit/test_watchdog.py tests/unit/test_sbx_identity.py tests/unit/test_diagnose_isolation.py -v` passes
- [ ] `pytest tests/unit/ -q` passes
- [ ] `./scripts/ci-local.sh` passes (Ruff / Mypy / Shellcheck / Unit tests)
- [ ] Manual: sandbox wrapper tamper → re-injected within 10 s and HMAC rotated
- [ ] Manual: `cast diagnose` surfaces the `wrapper_tamper` event with new checksum
- [ ] Manual: symlinked plugin `sbx` → `cast new` refuses with actionable error
- [ ] Manual: `cast diagnose --json` reports `isolation.sandboxes[*].status == "ok"` on macOS and Linux
