# Plan: Harden sbx Backend Beyond Docker Defaults

**Last updated:** 2026-04-20
**Branch:** sbx
**Status:** Implementation planning
**Supersedes:** template-preset integration plan (completed commit `e4a4087`)

---

## 1. Objective

Close the three open-question hardening gaps surfaced by re-examining `sbx-analysis.md` against the current implementation:

- **U20** — agent-with-sudo removes the git wrapper during the watchdog's 30 s blind window, or replays a stolen HMAC after re-injection.
- **U23** — `sbx` on `PATH` silently resolves to Docker Desktop's `docker sandbox` plugin rather than the standalone CLI we pin.
- **U26** — sbx silently degrades to a legacy container path on Linux (no kernel separation), defeating the core microVM isolation assumption.

Each gap is observable but not currently observed, alerted on, or defended against.

The recommended hardening subset is **H1, H2, H3, H5, H7** (see Section 5 for design decisions). H4 and H6 are explicitly deferred.

## 2. Current State

### Wrapper integrity (U20)

- `foundry_sandbox/watchdog.py` runs a daemon thread that polls every **30 s** and re-injects the git wrapper on checksum mismatch (`WrapperWatchdog._poll_all_sandboxes`).
- HMAC secret is generated **once** at sandbox creation (`commands/new_sbx.py:131-133`) and written to `{workspace}/.foundry/hmac-secret` + the foundry-git-safety `SecretStore`. It is never rotated.
- Re-injection emits a single `log_warn` line (`watchdog.py:121`). Nothing enters the decision log, so `cast diagnose` and `docs/observability/alerts.yaml` do not see tamper events.

### sbx CLI identity (U23)

- `foundry_sandbox/sbx.py:523 sbx_check_available()` verifies only that `shutil.which("sbx")` succeeds and `sbx --version` parses into `[SBX_MIN_VERSION, SBX_MAX_VERSION)`.
- No check that the binary is the standalone CLI and not a Docker Desktop plugin shim.
- `SbxSandboxMetadata` does not record which CLI binary created the sandbox.

### Kernel isolation (U26)

- Phase 0 validation (`docs/adr/008-sbx-migration.md:13-16`) confirms Linux microVM support on Fedora 43 with sbx 0.26.1.
- No runtime assertion that the running sandbox actually got a separate kernel. `cast diagnose` does not compare host `uname -r` against sandbox `uname -r`.

## 3. Implementation Plan

### Phase 1: Shrink the wrapper-tamper window (H1)

**Modified: `foundry_sandbox/watchdog.py`**

- Change `WrapperWatchdog.__init__` default `poll_interval` from `30.0` to **`10.0`**.
- Lower cap on `start_watchdog()` accordingly.

**Modified: `foundry_sandbox/commands/watchdog_cmd.py`**

- Update the `--interval` flag default and help text to match.

Trade-off: ~3× more `sbx exec` calls per sandbox per minute. Cheap per call (sub-second) and bounded by `len(sbx_ls())`. If observed load is a problem, operators can revert via `cast watchdog --interval 30`.

### Phase 2: Rotate HMAC on re-injection (H2)

**Modified: `foundry_sandbox/watchdog.py`**

- In `_reinject_wrapper`, before calling `inject_git_wrapper`:
  1. `new_secret = generate_hmac_secret()`
  2. `write_hmac_secret_to_worktree(worktree_path, new_secret)`
  3. `write_hmac_secret_for_server(name, new_secret)`
- Derive `worktree_path` from the sandbox's bare-repo + branch (same path helpers `create_worktree` uses).

**Modified: `foundry_sandbox/git_safety.py`**

- Ensure `write_hmac_secret_for_server` is an idempotent replace (overwrites prior secret, not append).

Invariant: after any tamper event, any captured copy of the old secret is dead on the next legitimate git call.

### Phase 3: Emit tamper events to the decision log (H3)

**Modified: `foundry_sandbox/watchdog.py`**

- Add a structured event on every checksum mismatch:

  ```json
  {
    "event": "wrapper_tamper",
    "sandbox": "<name>",
    "expected_sha256": "...",
    "actual_sha256": "...",
    "action": "reinjected" | "reinject_failed",
    "timestamp": "2026-04-20T...Z"
  }
  ```

- Write via an existing foundry-git-safety decision-log helper (see `foundry-git-safety/foundry_git_safety/decision_log.py`) or, if no public entry point exists, extend the git-safety HTTP API with a `POST /events/wrapper-tamper` endpoint and call it from the watchdog.

**Modified: `foundry_sandbox/commands/diagnose.py`**

- Surface recent tamper events in `cast diagnose` output (last N, JSON-compatible).

**Modified: `docs/observability/alerts.yaml`**

- Add an alert rule on `wrapper_tamper` rate > 0 over any 5 min window.

### Phase 4: sbx CLI identity probe (H5)

**Modified: `foundry_sandbox/sbx.py`**

- In `sbx_check_available()`, after `sbx_is_installed()` and `check_sbx_version()`:
  1. Resolve the absolute binary path (`shutil.which("sbx")` + `os.path.realpath`).
  2. Refuse paths inside Docker Desktop's plugin directory: `~/.docker/cli-plugins/`, `/Applications/Docker.app/Contents/Resources/cli-plugins/`, Windows equivalents.
  3. Run a low-cost standalone-only probe (e.g., `sbx template ls --help`) and require it to exit 0 with recognizable output.
- On failure, print an actionable error (`"Detected Docker Desktop's docker sandbox plugin instead of standalone sbx. Install standalone via brew install docker/tap/sbx."`) and `SystemExit(1)`.

**Modified: `tests/unit/test_sbx.py`**

- Cover: standalone binary accepted; plugin path rejected; unknown path accepted with warning only if probe passes.

### Phase 5: Kernel-separation assertion in `cast diagnose` (H7)

**Modified: `foundry_sandbox/commands/diagnose.py`**

- Add an `isolation` check:
  1. For each running sandbox: `sbx_exec(name, ["uname", "-r"])` → record sandbox kernel.
  2. Capture host `uname -r`.
  3. Emit per-sandbox status: `ok` (different kernel) or `warn` (same kernel, likely container fallback).

**Modified: `foundry_sandbox/commands/diagnose.py` output**

- For `--json` mode, include `isolation: { host_kernel, sandboxes: [{name, kernel, status}] }`.
- For text mode, a one-line summary per sandbox.

**Modified: `docs/security/security-model.md`**

- Document the kernel-separation assertion under "MicroVM Isolation" so operators know what `cast diagnose` verifies.

### Phase 6: Tests

**New: `tests/unit/test_watchdog.py` (extend existing)**

- H1: default `poll_interval == 10.0`.
- H2: on re-injection, HMAC writer functions are called before `inject_git_wrapper`; secret values differ across two consecutive tamper events.
- H3: tamper path emits the structured event exactly once per mismatch; skipped when checksum matches.

**New: `tests/unit/test_sbx_identity.py`**

- H5: reject binaries resolved under Docker Desktop plugin paths (monkeypatch `shutil.which` + `os.path.realpath`).
- H5: standalone path with valid probe output → pass.
- H5: plugin probe fallback (missing `template ls --help` success) → `SystemExit`.

**New: `tests/unit/test_diagnose_isolation.py`**

- H7: host/sandbox kernels differ → status `ok`.
- H7: equal → status `warn`; JSON and text outputs both surface it.
- H7: sbx_exec failure per sandbox does not fail the whole diagnose run.

### Phase 7: Documentation

- `CHANGELOG.md` — "Added" section for H1, H2, H3, H5, H7.
- `docs/security/security-model.md` — new subsections under Wrapper Integrity (H2, H3) and MicroVM Isolation (H7).
- `docs/security/wrapper-integrity.md` — document HMAC rotation invariant.
- `docs/observability.md` — new `wrapper_tamper` event schema + alert rule.
- New ADR `docs/adr/014-tamper-observability.md` covering the decision to auto-rotate HMAC on re-injection and to promote tamper events to first-class observability signals.

## 4. Key Files

| File | Change |
|------|--------|
| `foundry_sandbox/watchdog.py` | Default interval 30 → 10; rotate HMAC on re-injection; emit `wrapper_tamper` events |
| `foundry_sandbox/commands/watchdog_cmd.py` | Update default + help text |
| `foundry_sandbox/sbx.py` | Add standalone-vs-plugin identity probe in `sbx_check_available` |
| `foundry_sandbox/commands/diagnose.py` | Surface tamper events + kernel-separation assertion |
| `foundry_sandbox/git_safety.py` | Ensure HMAC writes are replace-semantics |
| `foundry-git-safety/foundry_git_safety/decision_log.py` | New event type (or new HTTP endpoint) for `wrapper_tamper` |
| `docs/observability/alerts.yaml` | New alert rule for `wrapper_tamper` |
| `docs/observability.md` | Document the new event schema |
| `docs/security/security-model.md` | Document HMAC rotation + kernel-separation check |
| `docs/security/wrapper-integrity.md` | Document rotation invariant |
| `docs/adr/014-tamper-observability.md` | New ADR |
| `tests/unit/test_watchdog.py` | Extend for H1/H2/H3 |
| `tests/unit/test_sbx_identity.py` | New for H5 |
| `tests/unit/test_diagnose_isolation.py` | New for H7 |
| `CHANGELOG.md` | Summarize user-visible changes |

## 5. Design Decisions

- **Why 10 s, not 5 s, for the watchdog default?** 10 s halves the window vs. 30 s at ~3× the call rate; 5 s would halve again at ~6× the rate. Pick the lower-cost end until we have data showing 10 s isn't tight enough. Operators can still tighten via `--interval`.
- **Why rotate HMAC on every tamper, not on a fixed schedule?** Tamper is the exact event that suggests a secret may have been exfiltrated. Scheduled rotation adds ops burden without a matching threat signal.
- **Why promote tamper events to the decision log rather than just logs?** The decision log is the observability surface `cast diagnose` and the alert rule already consume. Logs are best-effort; the decision log is structured and queryable.
- **Why reject Docker Desktop's `sbx` plugin entirely rather than supporting both?** The two CLIs have diverged in minor releases (see `sbx-analysis.md` U23, Section 7.4). Supporting both doubles the compatibility surface; users who have Docker Desktop can still install the standalone CLI alongside it.
- **Why a `cast diagnose` assertion for kernel separation rather than a startup check?** Startup checks would slow every `cast new`. The diagnose command is the right place for point-in-time "is my install healthy?" assertions, and operators running the new/start commands already see warnings from `sbx_check_available`.
- **Why defer H4 (in-VM cap check) and H6 (CLI binary pinning in metadata)?** H4 is weak on its own because the agent can modify the wrapper; it only adds value layered on top of H1–H3, and we should measure whether H1–H3 are sufficient first. H6 protects against mid-session CLI swaps, which are rare and already partially covered by H5 at startup.

## 6. Verification

1. `pytest tests/unit/test_watchdog.py tests/unit/test_sbx_identity.py tests/unit/test_diagnose_isolation.py -v`
2. `pytest tests/unit/ -q` — full unit suite green
3. `./scripts/ci-local.sh` — Ruff / Mypy / Shellcheck / Unit tests all pass
4. Manual (live sandbox):
   - Start a sandbox; confirm `cast watchdog --interval 10` is the effective default.
   - Inside the sandbox, `sudo rm /usr/local/bin/git`; within 10 s, wrapper is restored and HMAC file at `{workspace}/.foundry/hmac-secret` has a new value.
   - `cast diagnose` surfaces the `wrapper_tamper` event with the new checksum.
5. Manual (CLI identity):
   - Symlink `~/.docker/cli-plugins/sbx` first on `PATH`; `cast new` refuses to run with an actionable error pointing at the standalone install instructions.
6. Manual (isolation):
   - Run `cast diagnose --json` on macOS/Linux hosts; confirm `isolation.sandboxes[*].status == "ok"` and `host_kernel != sandbox_kernel`.
