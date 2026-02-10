# Remaining Improvements

Items identified during senior engineer review. All 1197 unit tests pass as of the last commit.

---

## Completed

### 1. Standardize error handling and add debug logging to silent exception paths
**Status: DONE** — Added `log_debug()` calls to all silent `except` blocks in `docker.py`, `proxy.py`, and `container_io.py`. Issues are now visible when `SANDBOX_DEBUG=1`.

### 2. Fix test issues (sleep-based timing, env pollution, tautological asserts)
**Status: DONE**
- **Sleep-based flakiness:** Replaced `time.sleep()` with mock time control in `test_circuit_breaker.py`, `test_registry.py`, and `test_git_operations.py`. Circuit breaker tests now run in ~0.14s instead of ~7s.
- **Environment variable pollution:** Was already properly handled with try/finally in `test_fuzzing.py` (false positive from review).
- **Tautological asserts:** Replaced constant-value assertions in `test_foundation.py` with structural invariant checks (e.g., image has tag, paths are absolute, plugin dir under home).

### 3. `install_workspace_permissions` silently ignores failure
**Status: Already fixed** — Uses `check=False` with explicit return code handling, `log_error()`, and raises `RuntimeError`.

### 4. Deduplicate `FOUNDRY_ALLOW`/`FOUNDRY_DENY` lists
**Status: Already fixed** — `foundry_plugin.py` imports from `permissions.py`; no duplication exists.

### 5. `compose_up` suppresses all output on failure
**Status: Already fixed** — `CalledProcessError` includes captured stderr.

### 6. Global `os.environ` mutation in `start.py` and `destroy.py`
**Status: DONE** — `start.py` now snapshots `os.environ` before mutations and restores it in a `finally` block. The `del os.environ["SANDBOX_ID"]` was replaced with `os.environ.pop()`. `destroy.py` and `destroy_all.py` already used proper save/restore patterns.

### 7. `safe_remove()` symlink traversal risk
**Status: Already fixed** — Uses `_rmtree_no_follow_symlinks()` helper that checks `is_symlink()` before `is_dir()`.

### 8. Subnet collision space is limited
**Status: DONE** — `generate_sandbox_subnet()` now checks existing Docker network subnets and retries with a salt (up to 16 attempts) on collision.

### 10. `validate_git_url` accepts almost anything
**Status: DONE** — Tightened validation: HTTP URLs use `urllib.parse.urlparse` (rejects embedded credentials, missing host/path, suspicious characters), SSH URLs validate host format and reject absolute paths, local paths reject sensitive system locations (`/etc`, `/proc`, `/sys`, `/dev`, `/var/run`). Added 12 new test cases.

---

## Deferred

### 9. Inline Python scripts in `tool_configs.py` (~1,095 lines)
Large inline Python scripts (30-115 lines each) constructed as string literals and executed via `docker exec python3 -`. Untestable, no syntax checking at build time. Consider extracting to template files or a container-side script directory. **Deferred to a separate PR** due to scope.

---

## Test coverage gaps

Critical modules with zero unit tests:
- `compose.py` — Docker Compose configuration generation
- `docker.py` — Docker API wrapper (only bridge tests exist)
- `container_io.py` — Container I/O primitives
- `permissions.py` — Filesystem permission rules (security boundary)
- `proxy.py` — Proxy configuration and registration
- `stub_manager.py` — Stub injection logic
- `ide.py` — IDE launcher logic
- `tmux.py` — Tmux session management

Lower priority (less security-sensitive):
- `image.py`, `tui.py`, `container_configurator.py`, `container_setup.py`
