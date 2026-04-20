# foundry-sandbox on Docker `sbx` — Plan

**Last updated:** 2026-04-20
**Branch:** sbx
**Status:** Phase 0, 1, 2 **COMPLETE**. Phase 3 steps 3.0–3.3 **COMPLETE** (~67k lines removed). §5.1 Wrapper Integrity **SHIPPED**. §5.2 Migration **SHIPPED**. §5.3 Observability **SHIPPED**. §5.4 User-Defined Credential Injection **SHIPPED**. §5.5 Deep Policy Sidecar **SHIPPED**. §5.6 Chaos, Security Audit, Performance **SHIPPED**. §5.7 sbx Version Pinning **SHIPPED**. §5.8 **IN PROGRESS**.

---

## 1. Objective

Rebase foundry-sandbox (`cast`) on Docker's native `sbx` microVM backend, delegating microVM lifecycle, network policy, secret storage, credential injection, and worktree management to `sbx`. Extend `sbx` with the security features it doesn't provide: git operation mediation, branch isolation, push/commit guardrails, GitHub API filtering, and — as follow-on work — a deep method/path/body policy layer and wrapper-integrity enforcement.

The full rationale, architectural trade-offs, and risk register live in `sbx-analysis.md`. This document tracks **what remains to ship** on top of that analysis.

---

## 2. Current Architecture (already shipped on this branch)

```
┌──────────────────────────────────────────────────────────────────────┐
│  Foundry Additive Layer                                              │
│                                                                      │
│  foundry-git-safety (standalone Python package, 727 tests)           │
│    • HMAC-authed HTTP server mediating git operations                │
│    • Branch isolation + ref output filtering                         │
│    • Protected branches, push file restrictions, commit validation   │
│    • GitHub API filter (method/path/body blocklist)                  │
│    • YAML config (foundry.yaml) + workspace auto-discovery           │
│                                                                      │
│  cast CLI (thin sbx wrapper)                                         │
│    • foundry_sandbox/sbx.py — 20 wrappers over sbx subcommands       │
│    • foundry_sandbox/git_safety.py — server + wrapper injection      │
│    • commands/{new,start,stop,destroy,attach,list,...} delegate      │
│      lifecycle to sbx and configure the safety layer                 │
├──────────────────────────────────────────────────────────────────────┤
│  Docker `sbx` (v0.26.1+)                                             │
│    • MicroVM lifecycle (hypervisor-level isolation)                  │
│    • Network policy (domain/IP allow/deny, balanced profile)         │
│    • Secret storage + network-level credential injection             │
│    • Git worktree creation (--branch)                                │
│    • Templates, diagnostics, resource limits, TUI                    │
├──────────────────────────────────────────────────────────────────────┤
│  Hypervisor: macOS virtualization.framework / Windows Hyper-V /      │
│              Linux KVM (confirmed on sbx v0.26.1, Fedora 43)         │
└──────────────────────────────────────────────────────────────────────┘
```

**Deleted in this branch:** entire `unified-proxy/` (credential injector, API gateways, policy engine, DNS filter, rate limiter, circuit breaker, container registry), docker-compose generation, network management, and the original in-package git_api / branch_isolation / git_policies / github-api-filter modules (now living in `foundry-git-safety/`).

---

## 3. Deviation from `sbx-analysis.md` — and why

`sbx-analysis.md` §10 recommended **Option E (Wait and Watch)** with Option C preparation, citing experimental status and CLI divergence risk. This branch has executed **Option A (full rearchitecture)** instead.

Rationale for proceeding now, despite the analysis's caution:
- Phase 0 validation passed on Linux KVM (kernel 6.12.44 vs host 6.17.8).
- `foundry-git-safety` is already runnable standalone, so rollback is a clean revert to `main`.
- The code-reduction win (~67k lines removed) is realized immediately.
- Experimental-status risk is mitigated by version-pinning `sbx` (see §6.6 below).

This means several risks the analysis flagged as hypothetical are now live and must be addressed by the remaining work in §5.

---

## 4. What `sbx` Handles vs. What Foundry Must Keep Extending

| Capability | Provider |
|------------|----------|
| MicroVM lifecycle, network policy, secrets | `sbx` |
| Credential injection (9 providers, HTTP header) | `sbx` host-side proxy |
| Git worktree creation | `sbx --branch` |
| Git operation mediation (protected branches, push restrictions, commit validation) | `foundry-git-safety` |
| Branch visibility isolation / ref output filter | `foundry-git-safety` |
| GitHub API blocklist (merges, releases, workflows) | `foundry-git-safety` |
| **Wrapper persistence against agent removal** | **Shipped — §5.1** |
| **User-defined credential injection (Tavily, Perplexity, …)** | **Shipped — §5.4** |
| **Deep method/path/body policy (general, not just GitHub)** | **Shipped — §5.5** |
| **Existing-user migration path** | **Not yet built — §5.2** |
| **Observability (health, metrics, decision logs)** | **Not yet built — §5.3** |

---

## 5. Remaining Work (in priority order)

### 5.1 Wrapper Integrity Enforcement — **HIGH** — **SHIPPED**

SHA-256 checksum-based wrapper verification, host-side watchdog daemon, and CLI surfacing. Template bake (pre-existing), checksum functions in `git_safety.py`, `WrapperWatchdog` daemon thread in `watchdog.py`, `cast watchdog` command, `--watchdog` flag on `cast start`, wrapper status in `cast status` and drift marker in `cast list`. 52 unit tests across 4 test files. `docs/security/wrapper-integrity.md` documents model and residual risk.

**Remaining:** Integration tests on a live sbx environment (manual, pre-release validation).

### 5.2 Migration Path for Existing 0.20.x Users — **HIGH** — **SHIPPED**

`cast migrate-to-sbx` and `cast migrate-from-sbx` commands with automatic metadata conversion, credential migration, preset translation, snapshot/rollback, and dry-run mode. ADR-009 documents the decision against dual-mode operation. 56 unit + CLI tests passing.

**Remaining:** End-to-end test on a real 0.20.x installation (manual, pre-release validation).

### 5.3 Observability — **HIGH** — **SHIPPED**

`/health` (enhanced with config validity + uptime), `/ready` (workspace/config/secret-store checks), and `/metrics` (Prometheus format with operation counters, latency histograms, policy-decision counters) endpoints on foundry-git-safety server. Structured JSON Lines decision log with size-based rotation at `~/.foundry/logs/decisions.jsonl`. `cast diagnose` command gathering sbx diagnostics, git-safety health/readiness, and recent decision log entries with secret redaction. Prometheus alert rule templates in `docs/observability/alerts.yaml`.

**Remaining:** Runbook addendum to `docs/operations.md`.

### 5.4 User-Defined Credential Injection — **MEDIUM** — **SHIPPED**

Reverse-proxy routes on the foundry-git-safety Flask server. `config/user-services.yaml` declares services with domain, header, format. Sandbox talks HTTP to `host.docker.internal:8083/proxy/<slug>/...`, proxy reads API key from host env, adds header, forwards HTTPS to upstream. No MITM, no custom CA. Integrated with `cast new` (env var injection), `cast refresh-credentials` (secret push), and `migration.py` (credential map). 30 unit tests (15 config + 15 proxy). ADR-010 documents the decision.

**Remaining:** Test with real service endpoints (manual, pre-release validation).

### 5.5 Deep Policy Sidecar — **MEDIUM** — **SHIPPED**

`sbx policy` is domain/IP only. Foundry's GitHub filter is the one surviving method/path/body rule set — generalized into a YAML-driven request inspector so any service can have request-shape policies. Flask Blueprint on main server with per-sandbox rate limiting (reuses existing `RateLimiter`), per-service circuit breaker (3-state), and simple dot-notation body inspection. GitHub rules become a bundled default YAML file (`bundled://github-default`). Off by default; enabled via `foundry.yaml` or `--deep-policy` flag. ADR-011 documents the decision. 174 tests (46 engine + 8 proxy + 120 GitHub parity).

**Remaining:** Threat model documentation (deferred to ops runbook), performance measurements (folded into §5.6).

### 5.6 Chaos, Security Audit, Performance — **MEDIUM** — **SHIPPED**

Unit tests pass; negative-path validation complete.

**Deliverables:**
- Chaos tests: 14 unit-level simulations (thread safety, concurrent access, fault injection) + 4 shell modules for live sbx testing. 57 automated tests total.
- Security audit: HMAC rotation tested (10 tests), credential leak audit (7 tests), privilege escalation review (8 tests), wrapper injection privilege review documented. Findings in `docs/security/audit-5.6.md`.
- Performance baselines: microbenchmarks for HMAC, nonce, rate limiter, metrics, decision log, server throughput (8 tests). Benchmark scripts for full-stack latency measurement. Published in `docs/operations.md`.

**Remaining:** External security review (manual, recommended before Gate B). Full-stack benchmark results on live sbx (manual, pre-release validation).

### 5.7 `sbx` Version Pinning and Drift Detection — **LOW** — **SHIPPED**

`SBX_MIN_VERSION`/`SBX_MAX_VERSION` constants in `foundry_sandbox/sbx.py` with `get_sbx_version()` and `check_sbx_version()` functions. Every `cast` command enforces the range via `sbx_check_available()`. Weekly CI drift job (`.github/workflows/sbx-drift.yml`) downloads latest sbx, compares against range, opens a deduplicated GitHub issue on drift. `docs/sbx-compatibility.md` documents the tested-against matrix and expansion process. 12 unit tests.

### 5.8 Nice-to-Have (Defer Unless Needed)

- DNS-level filtering (was in old proxy; unclear if achievable inside microVM network stack).
- Native `sbx template` integration for presets (currently presets are JSON CLI-arg snapshots).
- Docker Desktop plugin parity (track `docker sandbox` CLI convergence per U27).

---

## 6. Risks (updated from analysis §11)

| Risk | Status | Mitigation |
|------|--------|------------|
| Experimental `sbx` churn breaks CLI | **Live** | §5.7 version pin + drift check |
| Agent removes git wrapper | **Shipped** | §5.1 checksum watchdog + template bake |
| `sbx reset` destroys injected binaries | **Shipped** | §5.1 template-bake + watchdog re-inject |
| CLI divergence (`docker sandbox` vs `sbx`) | **Live** | Target standalone `sbx` only; §5.7 surfaces breakage fast |
| Existing users have no upgrade path | **Live** | §5.2 blocks any release |
| Git-safety server is unobservable | **Shipped** | §5.3 shipped |
| User-defined providers not supported | **Shipped** | §5.4 reverse proxy |
| Docker deprecates `sbx` | Low likelihood | foundry-git-safety already runs against any backend; fall back to current docker architecture via git revert |
| Linux microVM docs still say "legacy container" | Docs-only | Phase 0 confirmed otherwise on sbx v0.26.1 |

---

## 7. Decision Gates

### Gate A — Cut a pre-release (0.21.0-rc)
Requires: §5.2 (migration) **and** §5.3 (observability) shipped. Everything else can follow behind a feature flag or in follow-up releases.

### Gate B — Cut a stable release (0.21.0)
Requires Gate A plus: §5.1 (wrapper integrity) shipped, §5.6 security audit signed off, one user has successfully migrated end-to-end.

### Gate C — Deprecate `main` architecture
Requires Gate B plus: 30 days of production use across ≥3 users without a critical regression.

### Gate D — Enable §5.5 (deep policy sidecar) by default
Requires: a concrete user request, and evidence Docker's domain-level policy is insufficient for that use case. Do not build speculatively.

---

## 8. What This Plan Explicitly Defers

- Phase 4's full deep policy engine at §5.5 depth — generalized method/path/body enforcement is scoped, but SSE streaming, per-provider gateways, and MITM for non-base-URL providers are out.
- Docker Desktop integration (`docker sandbox` plugin) — monitor per U27, do not target.
- DNS-level filtering — track as U28 in the questions doc; may be impossible inside `sbx`'s network stack.
- Dual-mode operation during migration — decide during §5.2 scoping; likely not worth the complexity.
- Re-adding rate limiting and circuit breaker — folded into §5.5 if we build the sidecar, dropped otherwise.

---

## 9. Links

- `sbx-analysis.md` — original architectural analysis and risk register
- `PLAN-CHECKLIST.md` — actionable checklist mirroring this plan
- `docs/adr/008-sbx-migration.md` — architectural decision record
- `foundry-git-safety/README.md` — standalone package docs
