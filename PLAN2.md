# Security Fixes for foundry-sandbox Code Review

## Context

A comprehensive code review identified security issues across the proxy, CLI, and Docker layers. This plan addresses 11 confirmed fixes grouped by file, ordered by priority. False positives from the initial review have been eliminated (e.g., metrics addon tests already exist, entrypoint-root.sh variables are properly validated).

---

## Fix 1 (CRITICAL): TOCTOU in upgrade.py

**File:** `foundry_sandbox/commands/upgrade.py` lines 40-58

Replace `NamedTemporaryFile(delete=False)` + close + curl + bash pattern with `tempfile.mkstemp()` + `os.chmod(0o700)` + `try/finally` cleanup. This eliminates the race window between file creation and execution.

- Use `tempfile.mkstemp(suffix=".sh")` which returns (fd, path)
- Close fd immediately, then `os.chmod(tmp_path, 0o700)` before curl writes
- Wrap everything in `try/finally` for guaranteed `os.unlink()`

---

## Fix 2 (HIGH): Strip credential placeholders from forwarded headers

**Files:**
- `unified-proxy/gateway.py` — after line 203 (header loop)
- `unified-proxy/github_gateway.py` — after line 470 (header loop)
- `unified-proxy/openai_gateway.py` — after line 172 (header loop)

In each gateway, after building `upstream_headers` but before injecting real credentials, filter out any header values containing placeholder markers:

```python
_PLACEHOLDER_MARKERS = ("CRED_PROXY_", "CREDENTIAL_PROXY_PLACEHOLDER")
```

Strip headers whose values contain these markers. Define the constant per-file (gateways are self-contained aiohttp apps).

---

## Fix 3 (HIGH): Use `.fullmatch()` for policy path patterns

**Files:**
- `unified-proxy/addons/policy_engine.py` lines 657-678 — `_check_github_blocklist()`
- `unified-proxy/addons/policy_engine.py` lines 712, 747-748 — `_check_github_body_policies()`
- `unified-proxy/github_gateway.py` lines 218-246 — `_check_github_blocklist()`
- `unified-proxy/github_gateway.py` lines 253+ — body policy patterns

Change all `PATTERN.match(path)` → `PATTERN.fullmatch(path)`. The existing `^...$` anchors are redundant with `fullmatch()` but harmless.

---

## Fix 4 (HIGH): Non-greedy `**` glob and consistent `.fullmatch()`

**File:** `unified-proxy/config.py` lines 140-189

- Line 160: Change `regex_parts.append(r".+")` → `regex_parts.append(r".+?")`
- Line 189 in `segment_match()`: Change `.match()` → `.fullmatch()`
- Line 221 in `BlockedPathConfig.matches()`: Change `.match()` → `.fullmatch()`

Leave `BlockedPatternConfig.matches()` (line 137) as `.match()` — those are user-supplied regex where semantics would change.

---

## Fix 5 (HIGH): Tighten branch isolation remote-prefix fallback

**File:** `unified-proxy/branch_isolation.py` lines 349-359

Add a guard requiring the prefix to look like a valid remote name (alphanumeric + hyphens + underscores, no dots) before attempting the remote-branch interpretation:

```python
if branch_part and re.fullmatch(r"[A-Za-z0-9_-]+", prefix):
    return _is_allowed_branch_name(branch_part, sandbox_branch, base_branch)
```

This prevents `release/1.0` from being misinterpreted as `remote=release, branch=1.0` when the full name `release/1.0` already failed the first check. The `re` module is already imported.

---

## Fix 6 (MEDIUM): Move path-based checks before body read

**File:** `unified-proxy/github_gateway.py` lines 416-458

Reorder to: normalize path → blocklist check (path-only) → read body → merge check (needs body) → body policies. This avoids buffering large payloads for requests rejected by path alone.

Specifically:
1. Move `method` and `raw_path` extraction before `body = await request.read()`
2. Move `normalized_path` computation and `_check_github_blocklist()` before the body read
3. Keep `_is_merge_request()` and `_check_github_body_policies()` after body read (they need it)

---

## Fix 7 (MEDIUM): Restrict temp file permissions in docker.py

**File:** `foundry_sandbox/docker.py` lines 448-454

Add `os.chmod(tmp_path, 0o600)` after creating the allowlist override temp file, before writing content.

---

## Fix 8 (MEDIUM): Log proxy cleanup errors

**File:** `foundry_sandbox/docker.py` lines 978-979

Replace `pass` with `log_warn(f"Proxy cleanup failed for {container}: {e}")`. The `log_warn` import already exists at line 37.

---

## Fix 9 (LOW): Fix hardcoded timeout in error message

**File:** `foundry_sandbox/proxy.py` line 142

Change `"curl timed out after 30s: {e}"` → `f"curl timed out after {PROXY_TIMEOUT}s: {e}"`. `PROXY_TIMEOUT` is already imported.

---

## Fix 10 (LOW): Remove redundant path normalization

**File:** `unified-proxy/addons/policy_engine.py`

- Line 476: Change `self._check_endpoint_paths(host, method, path)` → `self._check_endpoint_paths(host, method, normalized_path)`
- Lines 599-604 in `_check_endpoint_paths()`: Remove the redundant `normalize_path()` call; use the passed-in path directly. Rename parameter from `raw_path` to `path`.

---

## Fix 11 (LOW): Elevate credential isolation audit logging

**File:** `foundry_sandbox/credential_setup.py` lines 325-400

Add prominent `log_step()` calls at the isolation decision boundary:
- Before the `if not isolate_credentials:` block: `log_step("SECURITY: Credential isolation DISABLED — copying real credentials")`
- In the `else` branch: `log_step("SECURITY: Credential isolation ENABLED — using proxy placeholders")`

---

## Verification

```bash
# Unit tests (host-side CLI)
python -m pytest tests/unit/ -v

# Unit tests (proxy)
cd unified-proxy && python -m pytest tests/unit/ -v && cd ..

# Security tests
python -m pytest tests/security/ -v

# Full local CI
./scripts/ci-local.sh
```
