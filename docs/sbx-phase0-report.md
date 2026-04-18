# Phase 0: Validation Spike Report

**Date:** 2026-04-18
**Environment:** Fedora 43 (Linux 6.17.8), `sbx` v0.26.1
**Duration:** 1 day (research + hands-on validation)

---

## Summary

Phase 0 validates whether foundry-sandbox's git safety layer can be injected and operated inside Docker `sbx` sandboxes. The spike tested credential isolation, git wrapper injection, API connectivity, policy enforcement, agent removal resistance, and reset behavior.

**Result: PASS (with caveats)**

Git wrapper injection works. Credential isolation works. Policy enforcement works through a host-side API server. However, two significant architectural constraints were discovered.

---

## Test Results

### 1. Credential Isolation Verification

| Test | Result | Details |
|------|--------|---------|
| `sbx secret set -g anthropic` | PASS | Secret stored on host |
| `env \| grep -i anthropic` in sandbox | PASS | No credentials visible |
| `GH_TOKEN` placeholder | PASS | Shows `proxy-managed` not real token |
| API calls with injected creds | PASS | Proxy injects real credentials into outbound HTTP |

### 2. Git Wrapper Injection

| Test | Result | Details |
|------|--------|---------|
| Copy wrapper via `sbx exec --user root` | PASS | `cp` to `/usr/local/bin/git` succeeds |
| Wrapper takes PATH precedence | PASS | `which git` returns `/usr/local/bin/git` |
| File sync for wrapper delivery | PASS | Copy to host workspace, sync to sandbox, then `sbx exec cp` |
| Wrapper activates inside workspace | PASS | Commands under `WORKSPACE_DIR` are proxied |
| Wrapper falls through outside workspace | PASS | Commands outside workspace use real git |

### 3. API Connectivity

| Test | Result | Details |
|------|--------|---------|
| Direct `gateway.docker.internal:8083` | **FAIL** | Connection established but empty reply (network layer blocks non-proxy ports) |
| Via HTTP proxy `gateway.docker.internal:3128` | PASS | Proxy forwards to `host.docker.internal:18083` |
| HMAC authentication | PASS | Signatures verified, requests accepted |
| Nonce replay protection | PASS | Duplicate nonces rejected |

**Critical finding:** The sandbox cannot directly reach host ports. All host-bound traffic must go through the sbx HTTP proxy at `gateway.docker.internal:3128`. The git wrapper must use `--proxy` and target `host.docker.internal`.

### 4. Git Operations

| Test | Result | Details |
|------|--------|---------|
| `git status` | PASS | Returned `On branch phase0-validation` via API |
| `git log --oneline` | PASS | Returned commit history via API |
| `git branch -a` | PASS | Showed both branches via API |
| `git push --force origin main` | BLOCKED | API server rejected `--force` flag |
| `git --version` (outside workspace) | PASS | Returned `git version 2.51.0` (real git) |

### 5. Agent Removal Resistance

| Test | Result | Details |
|------|--------|---------|
| `rm /usr/local/bin/git` as root | **FAIL** | Agent can remove wrapper |
| Git access after removal | **UNRESTRICTED** | Real git at `/usr/bin/git` provides full access |

**Critical finding:** The agent (with root access) can remove the wrapper and bypass all git safety. No mechanism exists to prevent this. The wrapper is only as strong as the agent's willingness not to remove it.

### 6. sbx Reset Behavior

| Test | Result | Details |
|------|--------|---------|
| `sbx reset --force` | PASS | Destroyed all 4 sandboxes, stopped daemon, signed out |
| Wrapper persistence after reset | **N/A** | Sandbox filesystem is destroyed entirely; wrapper is gone |

**Finding:** `sbx reset` is a nuclear option — destroys all sandboxes, policies, secrets, and daemon state. Wrapper persistence is moot since the sandbox itself is gone.

### 7. Security Audit

| Check | Result | Details |
|-------|--------|---------|
| Separate kernel (microVM) | PASS | Sandbox kernel 6.12.44 vs host 6.17.8 |
| `sbx exec --privileged` | Available | Agent can run privileged commands inside sandbox |
| Host filesystem access beyond workspace | PASS | Only workspace path synced |
| `gateway.docker.internal` network access | Limited | Only proxy port (3128) responds; other ports blocked |
| Git API communication channel security | PASS | HMAC-SHA256, nonce replay protection, clock window |

---

## Key Discoveries

### Discovery 1: Linux sbx IS MicroVM-based

The sbx-analysis.md stated Linux gets "legacy container-based sandboxes." This is **incorrect for sbx v0.26.1**. The sandbox kernel (`6.12.44`) differs from the host kernel (`6.17.8`), confirming microVM isolation on Linux.

### Discovery 2: Host Communication Only Via Proxy

Sandboxes cannot directly reach host ports. All host-bound traffic must route through the HTTP proxy at `gateway.docker.internal:3128`. The git wrapper must:
- Use `host.docker.internal` as the API hostname
- Route through `--proxy http://gateway.docker.internal:3128`
- The proxy forwards the request to the host

This adds a network hop but works reliably.

### Discovery 3: Agent Can Remove Wrapper

The wrapper is installed at `/usr/local/bin/git` via `sbx exec --user root`. The agent also has root access and can remove it. This is the same vulnerability as foundry-sandbox's current container-based approach, but more severe because:
- No Docker secrets mount (wrapper file is on regular filesystem)
- No bind-mount replacement mechanism
- `sbx reset` destroys everything anyway

Mitigation options:
- Build wrapper into custom sbx template (`sbx template save`)
- Monitor wrapper presence and re-inject
- Make wrapper resilience part of the threat model acceptance

### Discovery 4: File Sync Works for HMAC Secret Delivery

The HMAC secret can be delivered via file sync (`.foundry/hmac-secret` in workspace). This is simpler than Docker secrets mounts but means the secret is readable by the agent inside the sandbox. For Phase 0 validation this is acceptable; Phase 2 should explore more secure delivery (e.g., `sbx exec -e` env var, or `sbx secret set`).

---

## Recommendation

**Proceed to Phase 2** (Extract Git Safety Layer) with the following architectural decisions:

1. **Host-side git API server** — Standalone service on host, listening on a port forwarded via `sbx` proxy
2. **Git wrapper routes through sbx proxy** — Use `host.docker.internal` + proxy at `gateway.docker.internal:3128`
3. **Wrapper delivered via file sync + `sbx exec`** — Copy to workspace, then `sbx exec --user root` to install
4. **HMAC secret via file sync** — Place in `.foundry/hmac-secret` in workspace
5. **Agent removal is accepted risk** — Document in threat model; monitor/re-inject as mitigation
6. **Template-based wrapper for persistence** — Build wrapper into custom sbx template for survival across resets

---

## Updated Risk Assessment

| Risk | Pre-Phase 0 | Post-Phase 0 |
|------|-------------|--------------|
| Git wrapper injection | Unknown | **Resolved** — works via file sync + `sbx exec` |
| API connectivity | Unknown | **Resolved** — works via sbx HTTP proxy |
| Agent removes wrapper | High | **Confirmed High** — no prevention mechanism |
| sbx reset destroys wrapper | Medium | **Confirmed** — entire sandbox destroyed |
| Credential isolation | Assumed | **Confirmed** — secrets never enter VM |
| Linux microVM support | Unknown | **Resolved** — works on Linux with sbx v0.26.1 |
