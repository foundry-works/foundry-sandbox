# Code Review Findings — foundry-sandbox Shell-to-Python Rewrite

**Branch:** `tyler/foundry-sandbox-20260209-0718` based on `tylerburleigh/hardening-and-rewrite`
**Scope:** 13 commits + uncommitted changes across ~131 files (~29.5K lines added, ~5.4K removed)
**Tests:** 171 unit tests passing
**Date:** 2026-02-10
**Verified:** 2026-02-10 — each finding cross-checked against source code

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH     | 4 |
| MEDIUM   | 12 |
| LOW      | 8 |

---

## CRITICAL

### 1. Non-atomic state writes — `state.py:75`

`_secure_write()` uses `path.write_text()` which is not atomic. A crash or power loss mid-write corrupts the sandbox metadata file with no recovery path. Should use `tempfile.NamedTemporaryFile` + `os.replace()` for atomic writes. Notably, an atomic `write_json()` already exists in `config.py:39-58` using `tempfile.mkstemp()` + `os.rename()` but is not used here.

### 2. `git_with_retry` doesn't handle `TimeoutExpired` — `git.py:30-88`

The retry function uses `check=False` and checks `result.returncode == 0` to decide whether to retry. However, `subprocess.TimeoutExpired` is not caught inside the loop. When a git operation exceeds the `timeout=120` parameter, the exception propagates immediately, bypassing retry logic entirely.

### 3. `destroy_all` missing cleanup steps — `commands/destroy_all.py`

`destroy_all` iterates sandboxes and removes worktrees/metadata but skips four cleanup steps that `destroy.py` performs:
- Proxy deregistration (`cleanup_proxy_registration`)
- Stubs volume removal (`remove_stubs_volume`)
- HMAC secrets volume removal (`remove_hmac_volume`)
- Branch cleanup (`cleanup_sandbox_branch`)

Confirmed by line-by-line comparison: `destroy.py` has 10 cleanup steps, `destroy_all.py` has 5.

### 4. No rollback on `new` command failure — `commands/new.py`

The `new` command (~1,320 lines) performs ~22 `_shell_call` invocations plus direct Python calls to set up a sandbox. There is one rollback path (proxy registration failure calls `compose_down`), but for all other failure modes — worktree creation, compose up, network configuration, pip install — partial worktrees, config directories, metadata files, and running containers are left behind with no cleanup. Needs a try/finally or context-manager approach.

---

## HIGH

### 1. Bridge crash handler produces no output — `_bridge.py:77-80,106-109`

When a bridge command crashes with an unexpected exception, `_emit_crash()` only prints a traceback if `SANDBOX_DEBUG=1`. Otherwise, the caller receives no stdout and exit code 2 with no explanation. Shell callers parsing JSON will get a parse error with no diagnostic info.

### 2. SSH key isolation gap — `credential_setup.py:386-438`

SSH key copying (step 20) is gated on `enable_ssh`, not on `isolate_credentials`. When both `enable_ssh=True` and `isolate_credentials=True`, private keys (`id_rsa`, `id_ed25519`, `id_ecdsa`) are copied into the container. The `isolate_credentials` flag correctly blocks Gemini OAuth, OpenCode auth, and Codex credentials (lines 249-307), but SSH keys bypass this gate entirely. Risk is bounded by the fact that SSH must be explicitly enabled by the user.

### 3. Global `os.environ` mutation — `commands/start.py`

`_export_feature_flags()` mutates the global `os.environ` dictionary at lines 99-101. Additional mutations occur at lines 226, 359, 385, and 413. These are process-wide and persist beyond the command invocation, affecting all subsequent subprocess calls. Should pass environment variables explicitly to subprocess calls.

### 4. No sandbox existence check before teardown — `commands/stop.py:21-53`

`stop` calls `validate_existing_sandbox_name()` which validates name format but does not check whether the sandbox actually exists on disk or has a running container. `compose_down` failures are caught and logged as warnings but the command exits 0 regardless. Compare with `start.py:203` which checks `worktree_path.is_dir()` before proceeding. Exit code should be non-zero when the sandbox doesn't exist.

---

## MEDIUM

### 1. Incomplete `json_escape()` — `config.py:99`

The manual JSON escape function handles `\n`, `\r`, `\t`, `\\`, and `\"` but misses `\b`, `\f`, and null bytes as required by the JSON spec. Should use `json.dumps()` instead of reimplementing JSON string escaping.

### 2. Tar process exit code ignored — `container_io.py:99-132`

`_pipe_tar_to_docker()` calls `tar_proc.wait()` on line 131 but never checks `tar_proc.returncode`. Only `docker_proc.returncode` is returned on line 132. A tar failure (e.g., source file missing, permission denied) goes undetected if docker exits 0.

### 3. No validation on `SANDBOX_NETWORK_MODE` — `constants.py:128`

`get_sandbox_network_mode()` returns the raw environment variable value without validating it against the allowed set (`limited`, `host-only`, `none`). Invalid values pass through silently.

### 4. `safe_remove()` symlink traversal risk — `paths.py:221-237`

`safe_remove()` checks `p.is_dir()` (which follows symlinks) and then calls `shutil.rmtree(p)`. While Python 3.12+ improved top-level symlink handling, symlinks *within* the directory tree are still followed by `rmtree`, meaning a symlink inside a sandbox directory could cause deletion of the target outside the sandbox.

### 5. Repetitive `create_worktree` branches — `git_worktree.py:171-319`

The single `create_worktree()` function (~150 lines) contains 6 distinct code paths based on `from_branch`, `branch_exists`, and `sparse_checkout` flags. Each branch repeats similar `git worktree add` subprocess calls with slight argument variations. This is a maintainability concern within one function, not duplication across files. Extracting the common subprocess invocation pattern would reduce the repetition.

### 6. Duplicated `repo_url_to_bare_path` — `legacy_bridge.py:62-84`, `_helpers.py:14-52`

Two independent implementations of the URL-to-bare-path conversion exist. `new.py:299-301` delegates to the legacy bridge rather than being a third copy, but the two real implementations have subtle differences (`Path.home()` vs `os.path.expanduser`, presence of `p.exists()` check). These should be consolidated.

### 7. Duplicated `_saved_flag_enabled` — `new.py:76-84`, `_helpers.py:55-70`, `state.py:82-90`

Flag-checking helper is defined independently in three modules with identical logic: checks `bool`, `int != 0`, and `str.lower() in {"1", "true", "yes", "on"}`. Should be a single shared utility.

### 8. `SandboxMetadata` Pydantic model unused — `models.py`

The Pydantic model is defined with 14 validated fields and is tested in `test_foundation.py`, but no production code imports it. All metadata read/write in `state.py` uses raw `dict[str, Any]`. The model should either be integrated into the actual metadata flow or removed.

### 9. Inline Python scripts in `tool_configs.py` (~1,095 lines)

Large inline Python scripts (30-115 lines each) are constructed as string literals and executed via `docker exec python3 -`. These are untestable, lack syntax checking at build time, and are difficult to maintain. Examples include `ensure_codex_config()` (~115 lines), `prefetch_opencode_npm_plugins()` (~110 lines), and `ensure_gemini_settings()` (~70 lines).

### 10. Silent install fallback in CI — `.github/workflows/test.yml:23`

`pip install -e ".[dev,test-orchestration]" 2>/dev/null || pip install pytest` suppresses stderr on the full install. If it fails, the fallback installs only `pytest` — tests run without the project's actual dependencies, leading to confusing failures or false passes.

### 11. Unvalidated JSON kwargs in `_cmd_write_metadata` — `state.py:640-643`

Bridge command passes `json.loads(json_str)` result directly as `**kwargs` to `write_sandbox_metadata()`. No schema validation ensures the parsed JSON keys match expected parameters. Unexpected keys cause a `TypeError`, but matching keys with wrong types pass through unchecked.

### 12. `os.times().elapsed` for seed generation — `commands/start.py:362,374`

Using `os.times().elapsed` as entropy in the sandbox ID seed is platform-dependent — returns `0.0` on Windows and has varying resolution on Unix systems. `time.time_ns()` or `os.urandom()` would provide more reliable entropy.

---

## LOW

### 1. Unused `import json` — `image.py:9`

`json` is imported but never used in the 67-line file.

### 2. Version duplication — `pyproject.toml:7` + `__init__.py:3`

Version `"0.1.0"` is defined in both locations with no sync mechanism (e.g., `importlib.metadata`).

### 3. `mypy --strict .` runs on test files — `.github/workflows/test.yml:42`

Strict mypy on test code is typically counterproductive. Tests use mocks, fixtures, and dynamic patterns that generate false positives. No `exclude` pattern is configured in `pyproject.toml`.

### 4. No CI timeout — `.github/workflows/test.yml`

Neither the `test` nor `lint` job has `timeout-minutes` set. A hanging test could consume CI resources until GitHub's default 6-hour timeout.

### 5. Missing `__all__` exports — `foundry_sandbox/` (0 of 51 files)

No module in the `foundry_sandbox` package declares `__all__`. Public API surface is entirely implicit.

### 6. Inconsistent error returns vs exceptions

Within the same module (`container_io.py`): `copy_file_to_container()` returns `False` on failure, while `docker_exec_json()` raises `ValueError`/`CalledProcessError`. Similar inconsistency across `git.py` (`RuntimeError`), `proxy.py` (`RuntimeError`), vs. container I/O (bool returns).

### 7. Magic numbers in retry logic

`range(5)` + `time.sleep(0.2)` appears in 3 locations (`container_io.py:175,294`, `credential_setup.py:122`). `timeout=30` is hardcoded in 4 places in `proxy.py`. `git_with_retry` defaults to `max_attempts=3` and `initial_delay=1.0` as function parameters. These should be named constants.

### 8. No `logging` module usage — `foundry_sandbox/`

`log_error()` and `log_warn()` use `print(..., file=sys.stderr)`. `log_debug()` prints to stdout (not stderr). No module in `foundry_sandbox` uses `import logging`. This makes it difficult to configure log levels, format output, or redirect logs in production.

---

## Architecture Notes

**Strengths:**
- Clean separation of concerns across modules
- Bridge protocol design is well-structured with JSON envelopes
- `_bridge_`-prefixed commands are handled in-process via `_run_bridge()` in `legacy_bridge.py:311`, avoiding shell round-trips for the common case
- Hypothesis property-based fuzzing tests (`test_fuzzing.py`) are excellent
- Foundation tests (`test_foundation.py`) and validation tests (`test_validate.py`) are thorough
- Click CLI framework is a good choice for the command structure
- Pydantic model definitions show good intent for type safety
- Input validation via `validate_sandbox_name()` blocks path traversal at call sites

**Concerns:**
- `new.py` at 1,320 lines needs decomposition — it's the most complex and most fragile module
- Code duplication across 2-3 modules will cause bugs as copies diverge
- The gap between defined Pydantic models and actual validation usage undermines type safety
- Non-bridge legacy commands still use the `sandbox.sh` trampoline at `legacy_bridge.py:324`
- ~22 bridge calls per sandbox creation add overhead even without shell round-trips

---

## Uncommitted Changes Assessment

30 modified files + 6 untracked files in the working directory. Changes include:
- New `_helpers.py` shared module (addresses some duplication)
- Test infrastructure improvements
- Various command handler refinements

These changes are coherent and move in the right direction but should be committed in logical units rather than as a single batch.

---

## Additional Findings — Extended Review

Modules reviewed in this pass: `docker.py`, `proxy.py`, `network.py`, `cli.py`, `validate.py`, `permissions.py`, `foundry_plugin.py`, `container_setup.py`, `opencode_sync.py`, `compose.py`, `commands/attach.py`, `commands/prune.py`, `commands/destroy_all.py` (re-check), `commands/destroy.py`.

**Note on CRITICAL #3 (`destroy_all` parity):** The current working copy of `destroy_all.py` now contains all 10 cleanup steps matching `destroy.py` — proxy deregistration (line 220), stubs volume removal (line 238), HMAC volume removal (line 244), and branch cleanup (line 284). This finding appears to have been addressed in the uncommitted changes.

---

### Updated Summary

| Severity | Count (original) | Count (extended) |
|----------|-------------------|------------------|
| CRITICAL | 4 | 4 (1 resolved in WIP) |
| HIGH     | 4 | 6 |
| MEDIUM   | 12 | 19 |
| LOW      | 8 | 14 |

---

## HIGH (continued)

### 5. `compose_up` suppresses all output on failure — `docker.py:288-291`

`compose_up()` runs `docker compose up -d` with `stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL` and `check=True`. When compose fails, the `CalledProcessError` propagates with no captured stdout or stderr — the diagnostic output (image pull failures, port conflicts, permission errors) is gone. Compare with `compose_down()` at line 339 which does *not* suppress output. Should use `capture_output=True` instead so the error can be logged or included in the exception.

### 6. `install_workspace_permissions` silently ignores failure — `permissions.py:146-150`

The function runs an inline Python script in the container with `check=False` and discards the return code entirely. If the script fails — Python not installed, permission denied, JSON decode error inside the container — permissions are never installed and no error is reported. This is a security-relevant operation (installing allow/deny rules for Claude's tool access) and silent failure means the sandbox may run with no permission restrictions.

```python
subprocess.run(
    ["docker", "exec", "-u", CONTAINER_USER, "-i", container_id, "python3", "-"],
    input=script,
    check=False,  # failure silently ignored
)
```

---

## MEDIUM (continued)

### 13. Duplicated `FOUNDRY_ALLOW`/`FOUNDRY_DENY` lists — `foundry_plugin.py:28-85` and `permissions.py:17-74`

Two independent modules define identical 48-element and 5-element permission lists. `foundry_plugin.py` uses them in `ensure_claude_foundry_mcp()` for MCP settings. `permissions.py` uses them in `install_workspace_permissions()` for container Claude settings. These are maintained separately — updating one without the other will produce inconsistent sandbox permissions. Should be a single canonical source.

### 14. `proxy_curl` triplicated transport logic — `proxy.py:80-116`

The three transport modes (HTTP, Unix socket, Docker exec) each independently construct curl commands with identical `-w`, `-H`, `-d`, and path-building logic. Only the command prefix and URL scheme differ. A helper to build the common arguments would eliminate the 3-way duplication.

### 15. `validate_git_url` accepts almost anything — `validate.py:181-196`

The validator accepts any non-empty string that starts with `http`, `git@`, or contains `/`. This means `foo/bar`, `/etc/passwd`, `http://evil.com/../../../`, and `git@:` all pass. Given that the URL is used to clone repositories (potentially executing git hooks), this is too permissive. At minimum should validate URL structure beyond substring presence.

### 16. `proxy_wait_ready` swallows all exceptions — `proxy.py:256-258`

The health-check polling loop catches `except Exception: pass` on every iteration. This masks errors unrelated to "proxy not ready yet" — incorrect proxy URL, malformed JSON responses, `KeyError` on dict access, etc. These should at least be debug-logged, and structural errors (e.g., `KeyError`) should break the loop early rather than polling until timeout.

### 17. Subnet collision space is limited — `docker.py:141-169`

`generate_sandbox_subnet()` uses MD5 but only takes the first 4 hex chars (16 bits), producing subnets in the range `10.{1-254}.{1-254}.0/24`. With only ~64,516 distinct subnets and the birthday-paradox threshold at ~253 sandboxes, collision probability is non-trivial for active users. Colliding subnets means two sandboxes share a credential-isolation network, breaking isolation.

### 18. `destroy`/`destroy_all` mutate `os.environ` during cleanup — `destroy.py:106`, `destroy_all.py:219`

Both commands set `os.environ["CONTAINER_NAME"] = container` before calling `cleanup_proxy_registration()`. This is a process-wide side effect. In `destroy_all`, this mutation happens inside a loop over all sandboxes. While each iteration overwrites the previous value, any exception handler or signal handler that runs between the assignment and the proxy cleanup will see a potentially stale value. Same class of issue as HIGH #3 (`start.py` env mutation).

### 19. Network override YAML manipulation is fragile — `network.py` (throughout)

The network module manually constructs and strips YAML via string operations across ~776 lines. Functions like `strip_network_config()` (lines 119-209) use 7 boolean state variables to track parser position, and `strip_ssh_agent_config()` (lines 231-345) uses 9. False positives are possible — e.g., the capability filter at line 157 uses `any(cap in stripped for cap in ["NET_ADMIN", ...])` which substring-matches (would match `"MY_NET_ADMIN"`). A YAML library (PyYAML or ruamel.yaml) would eliminate this entire class of bugs.

---

## LOW (continued)

### 9. Unused `_merge_permissions()` — `permissions.py:77-80`

A Python-side `_merge_permissions()` function is defined but never called. The actual permission merging happens inside the inline Python script that executes in the container (lines 95-96). Dead code.

### 10. Gemini OAuth detection via string matching — `docker.py:110-113`

`setup_credential_placeholders()` checks for Gemini OAuth by searching for raw strings `'"selectedType"'` and `'"oauth-personal"'` in the settings file content rather than parsing JSON. Could false-positive on string values or comments. The try/except at line 114 catches `OSError` but since JSON isn't actually parsed, `json.JSONDecodeError` isn't relevant — the deeper issue is the detection method itself.

### 11. `_shell_fallback` dead code path — `cli.py:73-90`

The docstring at line 76-78 explains that shell fallback would cause infinite recursion now that `sandbox.sh` delegates to the Python CLI. The function always returns exit code 1. Despite this, `_make_fallback_command()` (line 156) still constructs synthetic Click commands that delegate to `_shell_fallback()`. Any command in `KNOWN_SHELL_COMMANDS` that hasn't been registered as a Click subcommand will hit this dead path. Since all 16 commands are now registered (lines 231-246), the entire fallback mechanism is unused.

### 12. No `timeout-minutes` in CI workflow — `.github/workflows/test.yml`

(Restating for completeness with updated context.) Neither the `test` nor `lint` job sets `timeout-minutes`. The `pip install` fallback (finding M10) combined with a hanging test could consume CI runner time up to GitHub's 6-hour default.

### 13. `prune` doesn't clean up proxy registrations — `commands/prune.py`

When `prune --no-container` removes a sandbox without a running container, it calls `remove_worktree()` and `cleanup_sandbox_branch()` but does not call `cleanup_proxy_registration()` or remove stubs/HMAC volumes. Compare with `destroy.py` which performs all cleanup steps. Proxy entries for pruned sandboxes persist until TTL expires.

### 14. `_auto_detect_sandbox` in `attach.py` doesn't validate the detected name — `attach.py:51-78`

`_auto_detect_sandbox()` extracts the first path component under the worktrees directory and returns it as a sandbox name. This bypasses `validate_existing_sandbox_name()` — if a directory with an unusual name exists under worktrees (e.g., created manually), it's returned without validation and used directly in subsequent operations.

---

## Recommended Priority Order

1. **Atomic state writes** — data corruption risk, well-known pattern, atomic write already exists in `config.py`
2. **`TimeoutExpired` handling in retry** — silent failure, one-line fix
3. **Rollback on `new` failure** — reliability, requires design but high impact
4. **`compose_up` stderr suppression** — diagnostic loss on failure, simple fix (`capture_output=True`)
5. **`install_workspace_permissions` failure handling** — security-relevant silent failure, add `check=True` or return code check
6. **Deduplicate `FOUNDRY_ALLOW`/`FOUNDRY_DENY`** — two identical 48-element lists, maintenance hazard
7. **Path traversal defense-in-depth** — upstream validation exists, but path functions should guard independently
8. **`validate_git_url` tightening** — accepts nearly anything, used before `git clone`
9. **Subnet collision mitigation** — use more hash bits or random selection with conflict detection
