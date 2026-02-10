# Plan: Address All Review Feedback (7 Fixes)

## Context

A senior engineering review of the shell-to-Python rewrite identified 7 issues
ranging from missing subprocess timeouts to architectural cleanup. This plan
addresses all of them in dependency order.

## Execution Order

| # | Fix | Files | Risk |
|---|-----|-------|------|
| 1 | Add missing subprocess timeouts | `api_keys.py` | Low |
| 2 | Fix broken cleanup path in prune | `commands/prune.py` | Low |
| 3 | Expand sensitive path prefixes | `validate.py` | Low |
| 4 | Add file locking to state.py | `state.py` | Medium |
| 5 | Break up new.py main handler | `commands/new.py` | Medium |
| 6 | Extract duplicated network cleanup | `commands/_helpers.py`, `commands/destroy_all.py`, `commands/prune.py` | Medium |
| 7 | Document legacy bridge sunset | `docs/adr/006-legacy-bridge-sunset.md` | None |

Fixes 1-3 are independent one-line-ish changes. Fix 6 must follow Fix 2 (both touch prune.py).

---

## Fix 1: Add missing subprocess timeouts — `api_keys.py`

**Add import** (after line 18):
```python
from foundry_sandbox.constants import TIMEOUT_LOCAL_CMD
```

**3 changes:**
- Line 214-219 (`get_cli_status`, `gh auth status`): add `timeout=TIMEOUT_LOCAL_CMD`
- Line 346-351 (`export_gh_token`, `gh auth status`): add `timeout=TIMEOUT_LOCAL_CMD`
- Line 353-356 (`export_gh_token`, `gh auth token`): add `timeout=TIMEOUT_LOCAL_CMD`

**Also** widen `except OSError:` to `except (OSError, subprocess.SubprocessError):` at lines ~221 and ~360 to catch `TimeoutExpired`.

---

## Fix 2: Fix broken cleanup path — `prune.py`

**Line 202:** Delete the `continue` statement. The `log_warn` stays but execution falls through to volume cleanup (lines 204-224) instead of skipping it.

---

## Fix 3: Expand `_SENSITIVE_PREFIXES` — `validate.py`

**Line 197:** Replace:
```python
_SENSITIVE_PREFIXES = ("/etc", "/proc", "/sys", "/dev", "/var/run")
```
with:
```python
_SENSITIVE_PREFIXES = ("/etc", "/proc", "/sys", "/dev", "/var/run", "/root", "/boot", "/var/lib/docker")
```

---

## Fix 4: Add file locking to state.py

**Add imports:** `import contextlib` and `import fcntl`

**Add `_state_lock()` context manager** (after `_secure_write`, ~line 98):
- Takes a `Path` and optional `shared=False` flag
- Creates `.lock` sidecar file, uses `fcntl.flock(LOCK_EX)` or `LOCK_SH`
- Lock file left in place after release (removing would race)

**Wrap 3 sites:**
1. `_secure_write()` — wrap write+replace in `with _state_lock(path):`
2. `load_sandbox_metadata()` JSON read — wrap in `with _state_lock(json_path, shared=True):`
3. Legacy migration block (lines 255-291) — wrap in `with _state_lock(json_path):` with a double-check (re-verify json_path doesn't exist after acquiring lock, since another process may have migrated while waiting)

---

## Fix 5: Break up new.py main handler

**Add helper function** `_load_and_apply_defaults()` (~line 280) that consolidates:
- Load data (last or preset)
- Error if None, exit(1)
- Echo banner
- Call `_apply_saved_new_defaults()` with all current params
- Return the `_NewDefaults` dataclass

**Replace** the `--last` block (lines 381-418) and `--preset` block (lines 420-458) to call this helper. The 13-field unpack stays (needed because `new()` uses local variables throughout) but the load+validate+echo+apply logic is centralized.

Net: ~20 lines removed, error handling consolidated.

---

## Fix 6: Extract duplicated network cleanup

**Step 6a: Add to `commands/_helpers.py`:**
- Add imports: `import re`, `from typing import Callable`, `TIMEOUT_DOCKER_NETWORK`
- New function `cleanup_orphaned_networks(*, skip_confirm, confirm_fn, check_running) -> list[str]`
- Consolidates the logic from both destroy_all.py and prune.py: list networks matching pattern, optionally check running containers, optionally prompt, disconnect endpoints, remove stopped containers, remove network.

**Step 6b: Simplify `destroy_all.py`:**
- Replace `_cleanup_orphaned_networks()` body (lines 78-112) with a call to the shared helper
- Remove `re` import (only used for the network pattern)

**Step 6c: Simplify `prune.py` Stage 3:**
- Replace lines 231-357 with a call to `cleanup_orphaned_networks()` passing a `confirm_fn` closure
- Remove `re` import (only used at line 242)

---

## Fix 7: Document legacy bridge sunset — `docs/adr/006-legacy-bridge-sunset.md`

New ADR documenting:
- What the bridge is (per-module `bridge_main` dispatch + `legacy_bridge.py`)
- Which 14 modules still have bridge dispatch tables
- Removal conditions (no shell callers remain)
- Removal sequence (6 steps)
- Timeline (gated on migration completion, no hard deadline)

---

## Verification

After all fixes:
1. `python -m py_compile foundry_sandbox/api_keys.py` — syntax check
2. `python -m py_compile foundry_sandbox/commands/prune.py` — syntax check
3. `python -m py_compile foundry_sandbox/state.py` — syntax check
4. `python -m py_compile foundry_sandbox/commands/new.py` — syntax check
5. `python -m py_compile foundry_sandbox/commands/_helpers.py` — syntax check
6. `python -m py_compile foundry_sandbox/commands/destroy_all.py` — syntax check
7. Run unit tests: `python -m pytest tests/unit/ -x -q`
8. Run validate tests specifically: `python -m pytest tests/unit/test_validate.py -x -q`
9. Run state tests specifically: `python -m pytest tests/unit/test_state.py -x -q`
10. Verify imports: `python -c "from foundry_sandbox import cli; print('OK')"`
