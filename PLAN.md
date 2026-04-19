# Rearchitecting foundry-sandbox on Docker's Native `sbx`

**Date:** 2026-04-18
**Branch:** sbx
**Status:** Phase 2 **COMPLETE** (727 tests passing, documentation written)
**Approach:** Option E (Wait and Watch) with Phase 0 Validation + Option C Preparation

---

## Executive Summary

Docker has shipped a native `sbx` CLI providing microVM lifecycle, network policies, secret management, file synchronization, and multi-agent support. Docker's `sbx` already provides credential isolation through a network-level HTTP/HTTPS proxy (secrets never enter the VM), eliminating the primary reason foundry-sandbox built its own proxy layer.

A rearchitecture could eliminate a significant majority of foundry-sandbox's codebase. The remaining value is in git safety (operation-level mediation, protected branches, push restrictions, branch visibility isolation) and deep API policy enforcement (method/path/body-level).

**Caveat:** Docker Sandboxes is currently marked **"Experimental"** with no GA timeline announced. Linux microVM support is confirmed (sbx v0.26.1 on Fedora 43).

**Recommendation:** Proceed with migration to `sbx` backend now. Phase 2 (git safety extraction) is complete; Phase 3 (migration) can begin immediately.

---

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Layer 3: Foundry Additive Layer (what we build)                     │
│                                                                      │
│  ┌──────────────┐  ┌─────────────────────────────────────────────┐  │
│  │  Git Safety  │  │  Deep Policy Engine (optional)              │  │
│  │  Server      │  │  - GitHub blocklist (merges, releases)     │  │
│  │              │  │  - Push file restrictions                   │  │
│  │  - Branch    │  │  - Body inspection for PATCH operations     │  │
│  │    isolation │  │  - Per-container rate limiting              │  │
│  │  - Push      │  │  - Circuit breaker (fail-closed)            │  │
│  │    guards    │  └─────────────────────────────────────────────┘  │
│  │  - HMAC      │                                                    │
│  │    auth      │  NOTE: Credential isolation is NO LONGER needed   │
│  └──────────────┘  here — Docker's sbx already provides it via      │
│                    network-level proxy injection (confirmed by       │
│                    official Docker security docs).                   │
│                                                                      │
│  ┌─────────────────┐                                                │
│  │  cast CLI       │  Translates cast commands → sbx commands +     │
│  │  (thin wrapper) │  configures git-safety layer only              │
│  └─────────────────┘                                                │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 2: Docker `sbx` (what Docker provides)                       │
│                                                                      │
│  Each sandbox is a microVM containing a private Docker daemon:      │
│  - MicroVM lifecycle (create/run/stop/rm)                           │
│  - Network policy (allow/deny, balanced profile)                    │
│  - Secret storage + proxy injection (HTTP/HTTPS only)               │
│  - Git worktree creation (--branch, --branch auto)                  │
│  - Port publishing, templates, diagnostics, TUI dashboard            │
│  - 8 AI agents (claude, codex, copilot, gemini, kiro, opencode,     │
│    shell, docker-agent)                                              │
│  - Resource limits (CPU/memory), multiple workspaces                 │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 1: Host Hypervisor                                            │
│  macOS virtualization.framework │ Windows Hyper-V │ Linux KVM       │
│                                                                      │
│  NOTE: sbx is standalone — Docker Desktop NOT required               │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Phases

### Phase 0: One-Week Validation Spike (Before Phase 2)

**Critical blockers to validate before investing in extraction:**

| Validation | Method | Success Criteria | If Failed |
|------------|--------|------------------|-----------|
| Git wrapper injection via `sbx exec -u root` | Prototype injection, test reset behavior | Wrapper persists after `sbx reset` without manual re-injection | Document blocker, reconsider architecture |
| Git wrapper agent removal resistance | Simulate agent removal, test auto-recovery | Wrapper survives `rm /usr/local/bin/git` attempts | Build into template as fallback |
| Privileged injection security boundaries | Security audit of root-level injection | No sandbox escape vectors identified | Explore alternative injection mechanisms |
| Credential isolation verification | Test `env | grep anthropic` inside VM | Zero credential leakage confirmed | Document as Docker security bug |

**Duration:** 1 week
**Outcome:** Pass/Fail report with technical findings. Proceed to Phase 2 only on pass.

---

### Phase 1: Monitor and Validate (Ongoing)

Track Docker Sandboxes development and validate assumptions.

**Phase 1 Research Results (2026-04-18):**

| Validation | Status | Finding |
|------------|--------|---------|
| Experimental status | **Confirmed** | Still "Experimental" in docs. Launched Mar 31, 2026. No GA timeline. |
| Linux support | **Partial** | Install artifacts exist (.deb/.rpm) but Linux gets **legacy container-based** sandboxes, NOT microVMs. KVM backend not yet activated. |
| Licensing | **Resolved** | Proprietary (Docker Inc.). Individual standalone use free. Team/enterprise requires sales contact. |
| Git policy features | **Confirmed absent** | `sbx policy` is network-only. No git operation guardrails, protected branches, ref filtering, or API-level policies. |
| Version stability | **Risk identified** | `docker sandbox` (v0.12.0) and `sbx` (v0.24.1) are two diverged systems with no migration path. Community reports surprise breaking changes. |
| GitHub presence | **Found** | `docker/sbx-releases` — releases only, proprietary, no source code. 7 releases + nightly builds. |

**Remaining hands-on validations (require macOS/Windows with `sbx` installed):**
- Verify credential isolation: `env | grep -i anthropic` returns nothing inside VM
- Test git wrapper injection via `sbx exec -u root`
- Test `sbx reset` behavior with injected binaries

**Exit criteria:** Docker Sandboxes reaches GA with acceptable licensing and Linux microVM support.

---

### Phase 2: Extract Git Safety Layer (2-3 weeks)

Decouple git safety from proxy infrastructure, making it portable to any sandbox runtime.

**Components to extract:**
- Git API server (standalone service, no proxy dependency)
- Git wrapper (installable via `sbx exec` or bind-mount)
- Branch isolation and output filtering
- Push restrictions and protected branch enforcement
- Configuration via workspace-level `foundry.yaml`

**Exit criteria:** Git safety layer runs independently of unified-proxy.

---

### Phase 3: Migration to `sbx` Backend (Now)

Docker Sandboxes provides sufficient stability for migration. Linux microVM support confirmed on sbx v0.26.1.

**Migration approach:**
1. Rewrite `cast` CLI as thin wrapper over `sbx`
2. Replace unified-proxy with Docker's built-in credential injection
3. Deploy extracted git safety layer as only additive component
4. Maintain backward compatibility during transition

**Exit criteria:** All existing `cast` workflows work with `sbx` backend.

---

## What Docker `sbx` Handles

| Capability | Foundry-sandbox fate |
|------------|---------------------|
| MicroVM lifecycle | Delete — delegate to `sbx` |
| Network policies | Delete — delegate to `sbx policy` |
| Secret storage | Delete — delegate to `sbx secret` |
| Credential injection | Delete — Docker's proxy handles this |
| Git worktree creation | Delete — `sbx --branch` handles this |
| Container orchestration | Delete — `sbx` manages private daemon |
| API gateways (streaming) | Delete — or keep for performance |
| Rate limiting | Delete — or keep for depth |
| Circuit breaker | Delete — or keep for fail-closed |

---

## What Foundry Must Keep

| Capability | Why Docker `sbx` doesn't have it |
|------------|----------------------------------|
| Git operation mediation | No operation-level guardrails |
| Protected branch enforcement | Full git access to agent |
| Push file restrictions | No workspace path policies |
| Branch visibility isolation | Worktrees don't filter refs |
| GitHub API blocklist | No method/path/body policies |
| Deep policy engine | Domain-level policies only |

---

## Key Risks

| Risk | Mitigation |
|------|------------|
| Docker Sandboxes remains experimental indefinitely | Maintain current architecture as fallback |
| Linux gets container-based sandboxes only (not microVM) | Wait for KVM activation; maintain dual architecture if needed |
| CLI version divergence (`docker sandbox` vs `sbx`) | Target standalone `sbx` only; ignore Desktop plugin |
| Breaking changes during experimental phase | Pin to specific `sbx` version; test before upgrading |
| Proprietary license with no source access | Accept dependency; maintain fallback architecture |
| Git wrapper can't be reliably injected | Phase 0 spike validates before proceeding |
| Agent removes injected git wrapper | Build wrapper into template; add watchdog |
| Docker deprecates or changes `sbx` API | Keep git safety as standalone tool; version pin `sbx` |
| Linux users excluded | Wait for Linux install docs; maintain dual architecture if needed |
| `sbx reset` destroys injected binaries | Build wrapper into template; Phase 0 confirms behavior |
| Non-HTTP protocols blocked | Configure git to use HTTPS URLs only |
| Docker adds native git safety features | Monitor roadmap; prepared to sunset differentiation |
| Privileged injection introduces sandbox escape | Security audit in Phase 0; explore alternatives |
| Migration causes production downtime | Zero-downtime migration strategy required |
| Licensing terms are unacceptable for commercial use | Document for `docs/sbx-licensing-questions.md` |
| Git safety layer performance is unacceptable | Establish baselines; add caching if needed |

---

## Open Questions (Require Investigation)

| # | Question | Impact |
|---|----------|--------|
| U7 | Does `sbx` support user-defined service credential injection? | Medium — custom providers |
| U8 | Does `sbx` enforce API-level policies (e.g., GitHub merge blocking)? | Medium — policy layer needed |
| U9 | Does `sbx` allow custom CA certificates inside the VM? | Low — MITM for niche providers |
| U10 | What is the licensing model for teams/enterprise? | High — commercial use |
| U12 | What happens to injected binaries after `sbx reset`? | Critical — wrapper persistence |
| U13 | Can file sync be configured or disabled for specific paths? | Medium — wrapper installation |
| U15 | Does `sbx create` support `--branch auto`? | Low — workflow separation |
| U20 | Can `sbx exec --privileged` be restricted by policy? | High — wrapper enforceability |
| U21 | What is the standalone install path for Linux? | Critical — Linux support |
| U22 | What is Docker's commitment level to `sbx` long-term? | High — project risk |
| U23 | Are there any API versioning guarantees for `sbx`? | Medium — stability |
| U24 | What is the performance overhead of the git safety hop? | Medium — UX impact |
| U25 | Can templates include pre-installed binaries? | Medium — wrapper distribution |

---

## Decision Point

**Proceed with Phase 3 migration now:**
1. ~~Docker Sandboxes exits "Experimental" status~~ — proceeding with experimental
2. Linux microVM support confirmed (sbx v0.26.1 on Fedora 43)
3. Licensing terms acceptable for individual use
4. Git wrapper injection validated as reliable (Phase 0 pass)

---

## Migration Concerns

### Zero-Downtime Migration

Existing users with production sandboxes require:

- State preservation (running sandboxes, uncommitted work, active tmux sessions)
- Gradual migration path with rollback capability
- Dual-mode operation during transition period
- Data migration validation and integrity checks

### Performance Baseline

Git operations through the safety layer introduce an additional network hop. Establish baseline targets before migration:

- Clone operation latency increase should be minimal
- Status/fetch operations should remain responsive
- Push operations with policy enforcement have acceptable overhead

---

## Alternative Scenarios

| Scenario | Trigger | Response |
|----------|---------|----------|
| Docker Sandboxes is cancelled | Official announcement or 6+ months without updates | Continue current architecture; Phase 2 work still provides value |
| Linux support never ships | No Linux install docs after GA | Maintain dual architecture (current + `sbx` for macOS/Windows) |
| Git wrapper injection proves impossible | Phase 0 fails on wrapper persistence | Reconsider entire approach; evaluate building git safety into `sbx` templates directly |
| Docker adds git safety natively | Operation-level policies appear in `sbx` roadmap | Sunset Foundry git safety layer; pivot to configuration/wrapper role |
| `sbx reset` always destroys injected binaries | Confirmed behavior that can't be worked around | Build wrapper into custom templates; accept template maintenance burden |

---

## Additional Technical Gaps

| Area | Concern |
|------|---------|
| **Observability** | No monitoring plan for git safety layer health and performance |
| **Testing** | No chaos engineering for `sbx` daemon crash scenarios |
| **Security** | Git safety server communication channel needs audit for new attack surface |
| **CI/CD** | No plan for testing during transition (dual backend?) |
| **Cost** | Docker Sandboxes pricing is TBD — budget impact unknown |
