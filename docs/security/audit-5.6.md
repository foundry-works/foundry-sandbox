# Security Audit — §5.6

**Date:** 2026-04-20
**Scope:** foundry-git-safety server, HMAC authentication, wrapper injection, credential flows
**Status:** Internal audit complete; external review recommended before Gate B

---

## 1. HMAC Authentication Model

### Scheme

- **Algorithm:** HMAC-SHA256 over canonical request string `{method}\n{path}\n{sha256(body)}\n{timestamp}\n{nonce}`
- **Secret:** 64 hex characters (32 bytes `secrets.token_hex`), per-sandbox
- **Comparison:** `hmac.compare_digest()` (constant-time)

### Replay Protection

- Nonce uniqueness enforced per-sandbox via `OrderedDict` (LRU eviction at 1000 entries)
- Nonce TTL: 600 seconds (lazily expired)
- Clock window: 300 seconds (request timestamp vs server time)

### Rate Limiting (3 layers)

1. **IP throttle:** 100 requests per IP per 60-second window (pre-auth)
2. **Per-sandbox token bucket:** 300 burst capacity, 120 sustained/min (2 tokens/sec refill)
3. **Global ceiling:** 1000 requests/minute across all sandboxes

### Rotation

- `rotate_sandbox_secret()`: clears cache + nonce store; server re-reads from disk
- `revoke_sandbox_secret()`: clears cache + nonce store + rate limiter bucket
- **Gap:** < 100ms (synchronous, verified by `test_rotation_gap_duration_acceptable`)
- **Procedure:** Documented in `docs/operations.md` → HMAC Secret Rotation

### Automated Tests

- `foundry-git-safety/tests/security/test_hmac_rotation.py` (10 tests)
- Covers: old secret rejected, new secret accepted, concurrent rotation, bulk rotation, revocation

---

## 2. Wrapper Injection Attack Surface

### Who Can Inject

- Only the host-side `cast` CLI via `inject_git_wrapper()` in `git_safety.py`
- Requires `sbx exec <name> -u root` — the sbx binary is host-side only
- A sandbox process **cannot** run `sbx exec` because `sbx` is not available inside the microVM

### Trust Boundary

- The microVM boundary prevents sandbox-side wrapper replacement without root inside the VM
- If the agent (running as root inside the VM) replaces `/usr/local/bin/git`:
  - The watchdog daemon (host-side) detects the change within ~10 seconds and re-injects
  - The wrapper is baked into the sbx template, surviving `sbx reset`
- **Accepted risk:** ~10-second window where a malicious wrapper could bypass git safety

### `sbx exec -u root` Access

- Only the host-side `cast` user can invoke `sbx`
- The `-u root` flag is passed through to sbx which enforces user switching
- Recommendation: request a `--restrict-exec-root` flag from Docker for additional defense

---

## 3. Credential Flow

### Where Credentials Enter

| Credential | Source | Storage |
|------------|--------|---------|
| HMAC secrets | `cast new` generates | Server: `/run/secrets/sandbox-hmac/{id}` (mode 0600) |
| HMAC secrets | `cast new` generates | Client: `/run/foundry/hmac-secret` (tmpfs, mode 0600) |
| API keys | Host environment variables | User services proxy reads at request time |
| Git tokens | `FOUNDRY_PROXY_GIT_TOKEN` | Subprocess env (not persisted) |

### Where Credentials Are Injected

- **Git operations:** Host-side proxy adds `FOUNDRY_PROXY_GIT_TOKEN` to subprocess env
- **User services proxy:** Reads API key from host env at request time, adds as HTTP header
- **sbx credential injection:** Handled by sbx's built-in secret storage

### Where Credentials Never Go

- Credentials **never** enter the microVM (verified by red-team tests)
- The user services proxy reads keys from host env and injects headers on the host side
- The wrapper script inside the VM only holds the HMAC secret (used for signing, not for data access)

### Verified By

- `foundry-git-safety/tests/security/test_credential_leak_audit.py` (7 tests)
- `tests/redteam/modules/01-credentials-env.sh` (20 modules)

---

## 4. Threat Model

| Threat | Defense | Test | Residual Risk |
|--------|---------|------|---------------|
| **Credential leak via HTTP responses** | Responses never contain HMAC secrets or API keys; metrics/health endpoints verified | `test_credential_leak_audit.py` | None found |
| **Credential leak via logs** | Decision log entries exclude all secrets; audit log truncates output | `test_decision_log_contains_no_secrets` | None found |
| **Wrapper replacement** | Template baking + watchdog polling every 10s | `test_wrapper_integrity` in watchdog tests | ~10s window before re-injection |
| **Replay attack** | Nonce uniqueness + clock window + HMAC signature | `test_hmac_rotation.py` replay tests | None found |
| **Man-in-the-middle** | sbx network policy + HTTP-only inside VM | Red-team network tests | None found |
| **Privilege escalation via args** | Deny-by-default command allowlist; shell metacharacters blocked | `test_privilege_escalation.py` | None found |
| **Path traversal** | `..` component check + realpath resolution + startswith boundary check | `test_path_traversal_in_cwd_blocked` | None found |
| **stdin injection** | stdin passed via `subprocess.run(input=)`, not shell | `test_stdin_b64_cannot_inject_commands` | None found |
| **Environment variable leak** | Allowlist-based env sanitization; all GIT_*/SSH_* excluded | `test_environment_sanitization_complete` | None found |
| **HMAC timing side-channel** | `hmac.compare_digest()` (constant-time) | Code review | Python implementation detail |
| **Concurrent data corruption** | `threading.Lock` on all shared state | `test_chaos.py` (14 tests) | Lock contention under high QPS |

---

## 5. Findings

### F-001: Non-atomic metadata writes

**Severity:** Low
**Location:** `foundry_sandbox/git_safety.py:185` (`register_sandbox_with_git_safety`)
**Description:** Uses `metadata_path.write_text(json.dumps(...))` which is not atomic. If the process is killed mid-write, the JSON file may be partially written, causing the server to fail parsing on next request.
**Impact:** Server returns 500 on next request for that sandbox (non-critical, self-healing on re-registration).
**Recommendation:** Write to a temp file and `os.rename()` for atomic replacement.

### F-002: Non-atomic HMAC secret writes

**Severity:** Low
**Location:** `foundry_sandbox/git_safety.py:113` and `139` (`write_hmac_secret_to_worktree`, `write_hmac_secret_for_server`)
**Description:** Same non-atomic `write_text()` pattern for HMAC secrets.
**Impact:** If killed mid-write, the secret file may be empty or partial, causing auth failures.
**Recommendation:** Use atomic write (temp file + rename).

### F-003: Single lock contention under high QPS

**Severity:** Informational
**Location:** Multiple (`auth.py:_lock`, `metrics.py:_lock`, `decision_log.py:_lock`)
**Description:** Each module uses a single `threading.Lock` for all operations. Under high QPS (>100 req/sec), lock contention may increase latency.
**Impact:** Performance degradation, not a correctness issue.
**Recommendation:** Consider per-sandbox locks or read-write locks for metrics registry.

---

## 6. Recommendations for External Review

Before Gate B sign-off, an external security review should focus on:

1. **HMAC implementation correctness:** Verify the canonical request string construction and signature comparison have no subtle vulnerabilities
2. **Timing side-channels:** Confirm `hmac.compare_digest()` timing is not influenced by secret length or position of first mismatch
3. **File descriptor leaks:** During rotation, ensure `_current_fd` is properly closed in all error paths
4. **TOCTOU in metadata loading:** Server reads metadata from disk on every request; verify no race between read and write
5. **Symlink attacks:** Verify `os.path.realpath()` in path validation prevents all symlink traversal vectors
6. **Wrapper script security:** Review `stubs/git-wrapper-sbx.sh` for injection vulnerabilities in argument handling

---

## 7. Test Coverage Summary

| Test File | Tests | Status |
|-----------|-------|--------|
| `foundry-git-safety/tests/unit/test_chaos.py` | 14 | All passing |
| `foundry-git-safety/tests/security/test_hmac_rotation.py` | 10 | All passing |
| `foundry-git-safety/tests/security/test_credential_leak_audit.py` | 7 | All passing |
| `foundry-git-safety/tests/security/test_privilege_escalation.py` | 8 | All passing |
| `foundry-git-safety/tests/unit/test_performance.py` | 8 | All passing |
| `tests/unit/test_chaos_sbx.py` | 10 | All passing |
| **Total** | **57** | **All passing** |
