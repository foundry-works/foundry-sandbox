# Senior Engineer Review: Shell-to-Python Rewrite

**Branch**: `tyler/foundry-sandbox-20260209-0718`
**Scope**: 180 files, +36,697 / -10,514 lines across 27 commits
**Date**: 2026-02-11

## Overall Verdict: Approve with follow-up items

Well-executed migration from ~8K lines of shell to ~13.5K lines of Python with a 2:1 test-to-code ratio (28K test lines across 56 files). Security posture is strong, architecture is sound, test quality is excellent.

**P0 security items resolved** (2026-02-11): Atomic YAML writes in `network.py` and temp file location fix in `credential_setup.py`. See sections below for details.

---

## What's Done Well

- **Zero `shell=True` calls** across all 167 subprocess invocations. No command injection surface.
- **Atomic file writes** in `state.py` using `mkstemp()` + `os.replace()` with `fcntl` advisory locking.
- **Credential isolation boundary** is well-defined — every real secret copy gated by `if not isolate_credentials:`, per-sandbox nonces use `secrets.token_hex(16)`.
- **Secrets passed via stdin** to avoid `ps` leakage (e.g., `provision_hmac_secret()`).
- **Container path allowlist** in `container_io.py` prevents arbitrary writes via `posixpath`-based validation.
- **Lazy CLI loading** — commands import on first access via `CastGroup.get_command()`, not at startup.
- **Test quality is excellent** — behavior-focused, minimal mock assertions (~10 total `assert_called` across large test files), fail-closed security invariant tests, Hypothesis fuzzing with domain-appropriate strategies.
- **Proxy refactoring** is clean modularization with acyclic dependency graph. Re-exports preserve backward compatibility.
- **Clean import layering** — no circular dependencies at module initialization. Five clear layers from constants up to commands.

---

## P0 — Security (fix before merge) — RESOLVED

### 1. ~~Non-atomic YAML read-modify-write in `network.py`~~ FIXED

**Files**: `network.py:96-168` (`_strip_yaml_blocks()`), `network.py:230-289` (`append_override_list_item()`), `network.py:72-93` (`ensure_override_header()`)

~~Both functions read a file into memory, modify it, and write it back without locking or atomic replacement. A concurrent process could race the operation and inject YAML content.~~

**Resolution**: Extracted atomic I/O primitives (`file_lock`, `atomic_write_unlocked`, `atomic_write`) from `state.py` into a new shared module `foundry_sandbox/atomic_io.py`. All three vulnerable functions in `network.py` now acquire `file_lock()` around their read-modify-write operations and use `atomic_write_unlocked()` (mkstemp + os.replace with 0o600 permissions) for write-back. Also fixed a latent bug where the lock's `finally` block would attempt `flock(LOCK_UN)` on an already-closed fd after timeout. Tests added: 13 in `test_atomic_io.py`, 7 in `test_network.py`.

### 2. ~~Temp file in world-writable `/tmp` in `credential_setup.py`~~ FIXED

**File**: `credential_setup.py:99-137` (`_merge_claude_settings_safe()`)

~~Uses `NamedTemporaryFile(delete=False)` which defaults to `/tmp`. An attacker could symlink the predictable temp path before the merge completes.~~

**Resolution**: Replaced `NamedTemporaryFile(delete=False)` with `tempfile.mkstemp(dir=Path(host_settings).resolve().parent)`, creating temp files in `~/.claude/` (user-owned, not world-writable) instead of `/tmp`. Uses `os.fdopen(fd, "w")` for writing. Existing try/finally cleanup pattern preserved. Tests added: 5 in `test_credential_setup.py` verifying temp file location, cleanup on success/failure, and credential key stripping.

---

## P1 — Code Quality (fix soon after merge) — RESOLVED

**P1 items #3–#7 resolved** (2026-02-11): Exception hierarchy, IP validation, environment scope context manager, `_helpers.py` redistribution, and network dedup. See sections below for details.

### 3. ~~`new.py` env save/restore duplication with `start.py`~~ FIXED

~~The `os.environ` save/restore pattern is duplicated between `new.py:776-869` and `start.py:436-512`.~~

**Resolution**: Added `environment_scope()` context manager to `foundry_sandbox/utils.py`. Replaced manual `_saved_env = dict(os.environ)` / `try` / `finally` / `os.environ.clear()` / `os.environ.update(_saved_env)` pattern in both `new.py` and `start.py` with `with environment_scope(updates):`. Tests added: 5 in `test_foundation.py` covering restore on normal exit, restore on exception, and removal of vars added inside scope.

### 4. ~~Network removal logic duplicated 3x~~ FIXED

~~Network removal logic is copied 3 times across `destroy.py`, `destroy_all.py`, and `new_setup.py`.~~

**Resolution**: Extracted `remove_sandbox_networks(container)` in `foundry_sandbox/docker.py` — a single function that inspects+removes both `credential-isolation` and `proxy-egress` networks for a given container prefix. Replaced inline loops in `destroy.py` (lines 141–160), `destroy_all.py` (`_remove_network()` helper + inline loop), and `new_setup.py` `_rollback_new()` (lines 78–86). Also removed the now-unused `_remove_network()` helper from `destroy_all.py`. Tests added in `test_canonical_imports.py`.

### 5. ~~`_helpers.py` is a 489-line grab bag~~ FIXED

~~Mixes path generation, UI/fzf selection, Docker operations, and crypto ID generation in one module.~~

**Resolution**: Redistributed all 14 functions to their domain homes:
- **Path ops** → `foundry_sandbox/paths.py`: `repo_url_to_bare_path`, `sandbox_name`, `find_next_sandbox_name`, `strip_github_url`, `resolve_ssh_agent_sock`
- **Docker ops** → `foundry_sandbox/docker.py`: `uses_credential_isolation`, `apply_network_restrictions`, `cleanup_orphaned_networks`, `_NETWORK_PATTERN`, `proxy_cleanup`, plus new `remove_sandbox_networks`
- **Utilities** → `foundry_sandbox/utils.py`: `generate_sandbox_id`
- **Tmux** → `foundry_sandbox/tmux.py`: `tmux_session_name`
- **Kept in `_helpers.py`**: `auto_detect_sandbox`, `fzf_select_sandbox`, `list_sandbox_names` (UI helpers)
- Backward-compatible re-exports added in `_helpers.py` for all moved functions.
- Updated imports in 7 command files: `new.py`, `start.py`, `new_setup.py`, `destroy.py`, `destroy_all.py`, `prune.py`, `refresh_creds.py`.
- `_helpers.py` reduced from 489 lines / 14 functions to ~130 lines / 3 functions + re-exports.
- Tests added: `test_canonical_imports.py` with canonical location imports, backward-compat re-exports, and `remove_sandbox_networks` unit tests. Import layering tests continue to pass.

### 6. ~~No exception hierarchy~~ FIXED

~~Multiple patterns coexist: `RuntimeError`, custom `_SetupError`, `sys.exit(1)`.~~

**Resolution**: Created `foundry_sandbox/errors.py` (base-layer module, zero internal imports) with hierarchy: `SandboxError` → `ValidationError`, `SetupError`, `ProxyError`, `DockerError`. Updated `new_setup.py` so `_SetupError` inherits from `SetupError`. Replaced all 9 `raise RuntimeError(...)` in `proxy.py` with `raise ProxyError(...)` and updated corresponding `except` clauses. Added `"errors"` to `BASE_MODULES` in `test_import_layering.py`. Updated all proxy-related test assertions in `test_network.py` from `RuntimeError` to `ProxyError`. Tests added: `test_errors.py` with hierarchy, catchability, and `_SetupError` subclass tests.

### 7. ~~Missing IP validation in `proxy.py:proxy_register()`~~ FIXED

~~Accepts `ip_address` as string without format validation.~~

**Resolution**: Added `import ipaddress` and validation via `ipaddress.ip_address(ip_address)` in `proxy_register()` after the emptiness check. Invalid IPs raise `ProxyError` with a descriptive message including the original `ValueError`. Tests added: `test_proxy_validation.py` with cases for empty args, 6 invalid IP formats, and 6 valid IPv4/IPv6 addresses.

---

## P2 — Architecture (next sprint) — RESOLVED

**P2 items #8 and #12 resolved** (2026-02-11): Domain models added, settings merge extracted. Items #9, #10, #11 were already resolved or below threshold.

### 8. ~~`models.py` is too lean (53 lines, 1 model)~~ FIXED

~~Single `SandboxMetadata` Pydantic model for a 13.5K-line project.~~

**Resolution**: Added 3 domain models to `foundry_sandbox/models.py`: `CastNewPreset` (replaces raw dict in state.py preset persistence), `ProxyRegistration` (replaces metadata dict for proxy registration in new_setup.py/start.py), and `CredentialPlaceholders` (replaces env dict from docker.py with `.to_env_dict()` method). Integrated into consumers: `state.py` validates presets through `CastNewPreset`, `docker.py:setup_credential_placeholders()` returns `CredentialPlaceholders`, `new_setup.py` and `start.py` build `ProxyRegistration` for proxy API calls. `ContainerConfig` skipped — would require refactoring the YAML pipeline. Tests added: `test_models.py` with construction, validation, defaults, round-trip, and `.to_env_dict()` tests.

### 9. ~~Remove legacy bridge dead code~~ FIXED (prior commit)

### 10. ~~Missing timeout on Docker network cleanup~~ FIXED (prior commit)

### 11. `state.py` — below threshold, monitoring

Currently 637 lines (below 1000-line split threshold). No action needed.

### 12. ~~`credential_setup.py` (776 lines) is the densest module~~ FIXED

**Resolution**: Extracted `_merge_claude_settings_in_container()` and `_merge_claude_settings_safe()` from `credential_setup.py` into new `foundry_sandbox/settings_merge.py` as public functions (no underscore prefix). Original functions in `credential_setup.py` now delegate via lazy imports. Added `"settings_merge"` to `BRIDGE_CALLABLE_MODULES` in `test_import_layering.py`. Tests added: `test_settings_merge.py` with merge success/failure, subprocess return code handling, credential key stripping, and temp file cleanup tests.

---

## Additional Findings (low priority) — RESOLVED

All 5 additional findings resolved (2026-02-11):

### ~~TOCTOU in `docker.py:setup_credential_placeholders()`~~ FIXED
Removed `.is_file()` guard before `open()`. The existing `except (OSError, json.JSONDecodeError)` handles `FileNotFoundError` (subclass of `OSError`). Regression test added in `test_docker.py`.

### ~~Silent failure in `credential_setup.py:_merge_claude_settings_in_container()`~~ FIXED
Now captures subprocess result, checks `returncode != 0`, returns `False` with warning on failure. Regression tests in `test_credential_setup.py` and `test_settings_merge.py`.

### ~~Imprecise elapsed time in `proxy.py:proxy_wait_ready()`~~ FIXED
Replaced counter-based `elapsed` with `time.monotonic()`. Added `_clock` parameter for testability. Regression tests in `test_proxy_validation.py`.

### ~~String splitting without bounds in command handlers~~ FIXED
Replaced `copy_spec.split(":")[0]` with `.partition(":")` in `new.py` (lines 365, 752).

### ~~Unvalidated `$USER` env var~~ FIXED
Replaced `os.environ.get("USER", "ubuntu")` with `os.environ.get("USER") or getpass.getuser()` in both `start.py` and `new_setup.py`.

---

## Metrics

| Dimension | Grade | Notes |
|-----------|-------|-------|
| Security | **A** | Strong fundamentals; YAML atomicity and temp file paths fixed |
| Architecture | **B+** | Clean layering, no circular deps; some modules too large |
| Test quality | **A** | 2:1 ratio, behavior-focused, excellent security invariants |
| Error handling | **B+** | Exception hierarchy added; ProxyError replaces RuntimeError |
| Code duplication | **B+** | Env scope, network dedup, _helpers redistribution |
| Click idioms | **A-** | Lazy loading and aliases done well |

| Metric | Value |
|--------|-------|
| Source code | 13,493 lines |
| Test code | 28,138 lines |
| Test files | 56 |
| Test:code ratio | 2.09x |
| Subprocess calls | 167 (0 with shell=True) |
| Bare except Exception | 18 (all in cleanup/rollback paths) |
