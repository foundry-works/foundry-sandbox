# foundry-sandbox on `sbx` — Checklist

**Last updated:** 2026-04-20
**Companion to:** `PLAN.md`, `sbx-analysis.md`

Legend: `[x]` done, `[ ]` todo, `[~]` partial / accepted risk.

---

## Completed Work (for reference)

### Phase 0 — Validation Spike — **COMPLETE**

- [x] Git wrapper injection via `sbx exec -u root`
- [x] Credential isolation verified (`env | grep -i anthropic` empty)
- [x] Privileged injection security review — no sandbox escape
- [x] Linux microVM confirmed on sbx v0.26.1 / Fedora 43
- [x] `sbx reset` destroys wrapper (accepted; persistence strategy = template bake)
- [x] Agent can remove wrapper (accepted; watchdog is §5.1)

### Phase 1 — Monitor — **ONGOING**
- [x] Track Docker Sandboxes releases and blog
- [x] Confirm experimental status, licensing (proprietary, free for standalone)
- [x] Confirm no git-policy features in `sbx` roadmap
- [x] Document CLI divergence (`docker sandbox` v0.12.0 vs `sbx` v0.24.1+)
- [ ] Re-validate credential isolation on macOS when hardware available

### Phase 2 — Extract `foundry-git-safety` — **COMPLETE** (727 tests)
All checkboxes from the prior checklist remain done. Package lives at
`foundry-git-safety/` with 29 test files. Highlights:
- [x] Standalone service (auth, HTTP server, CLI)
- [x] Branch isolation, ref output filter, push/commit validation
- [x] GitHub API filter (method/path/body)
- [x] `foundry.yaml` config schema + workspace discovery
- [x] Wrapper script (`wrapper.sh`) installable via `sbx exec` or template
- [x] 727 unit + integration tests passing
- [ ] Troubleshooting guide (defer to §Documentation below)
- [ ] Performance benchmark (folded into §5.6)

### Phase 3.0–3.3 — Backend Migration — **COMPLETE**
- [x] `foundry_sandbox/sbx.py` — 20 wrappers over `sbx` CLI
- [x] `SbxSandboxMetadata` model, paths, state rewrites
- [x] All `cast` commands rewritten (`new`, `start`, `stop`, `destroy`,
      `attach`, `list`, `info`, `config`, `status`, `refresh-creds`,
      `destroy-all`, `git-mode`, `help`)
- [x] Deleted: `build`, `prune`, `upgrade`
- [x] `foundry_sandbox/git_safety.py` — integration bridge
- [x] `unified-proxy/` entirely removed (~67k lines)
- [x] Docs updated: architecture, getting-started, operations, ADR-008, CHANGELOG

---

## Remaining Work

### §5.1 Wrapper Integrity Enforcement — **HIGH**

- [ ] Build git wrapper into a custom `sbx template` (via `sbx template save`)
  - [ ] Template build script in `scripts/`
  - [ ] `cast new` accepts `--template <name>` and selects foundry's template by default
  - [ ] Document template refresh on `sbx` upgrades
- [ ] Host-side wrapper watchdog
  - [ ] Poll `sbx exec <name> -- sha256sum /usr/local/bin/git` on interval
  - [ ] Re-inject wrapper on checksum mismatch or missing file
  - [ ] Emit metric + log on every re-injection event
  - [ ] Runs under `cast` supervision, or as optional systemd/launchd service
- [ ] Surface wrapper status in CLI
  - [ ] `cast info <name>` shows wrapper checksum + last verified timestamp
  - [ ] `cast list` flags sandboxes with wrapper drift
- [ ] Tests
  - [ ] Integration: agent `rm /usr/local/bin/git` → watchdog re-installs within N seconds
  - [ ] Integration: `sbx reset` → template-baked wrapper present on fresh sandbox
  - [ ] Negative: watchdog fails closed if `sbx exec` errors
- [ ] Documentation: `docs/security/wrapper-integrity.md` explaining model and residual risk

### §5.2 Migration Path for Existing 0.20.x Users — **HIGH**

- [ ] `cast migrate-to-sbx` command
  - [ ] Snapshot `~/.sandboxes/` to timestamped backup directory
  - [ ] Enumerate existing compose-based sandboxes; emit plan before acting
  - [ ] Translate host credentials → `sbx secret set -g` (anthropic, github, openai, …)
  - [ ] Translate `CastNewPreset` JSON presets to new field set; flag dropped fields
  - [ ] Dry-run mode (`--plan`) prints actions without executing
- [ ] Rollback procedure
  - [ ] Documented steps: `pip install foundry-sandbox==0.20.x && cast migrate-from-sbx`
  - [ ] `cast migrate-from-sbx` restores snapshot directory
  - [ ] Tested on at least one real 0.20.x installation
- [ ] Breaking-changes document
  - [ ] `docs/migration/0.20-to-0.21.md` — removed flags, changed paths, gone providers
  - [ ] Linked from CHANGELOG.md
- [ ] Scope decision: dual-mode operation
  - [ ] ADR captures decision (yes/no) and rationale
  - [ ] If yes: define transition window and flag semantics

### §5.3 Observability — **HIGH**

- [ ] `foundry-git-safety` server endpoints
  - [ ] `GET /health` — liveness + config validity
  - [ ] `GET /ready` — dependencies reachable (workspace, config, secret store)
  - [ ] `GET /metrics` — Prometheus format
    - [ ] operation counter (by verb, sandbox, outcome)
    - [ ] latency histogram (by verb)
    - [ ] policy-decision counter (by rule, outcome)
    - [ ] wrapper re-injection counter (from §5.1 watchdog)
- [ ] Structured decision log
  - [ ] JSON lines to `~/.foundry/logs/decisions.jsonl` by default
  - [ ] Every allow/deny with: timestamp, sandbox, branch, rule, verb, outcome
  - [ ] Rotation policy (size-based)
- [ ] Alert-rule templates
  - [ ] `docs/observability/alerts.yaml` with Prometheus alert rules
  - [ ] Documented severity and response for each
- [ ] Runbook
  - [ ] `docs/operations.md` addendum: common failure modes and diagnostic steps
  - [ ] How to collect a support bundle (`cast diagnose` idea)
- [ ] `cast diagnose` command
  - [ ] Gathers `sbx diagnose` output + git-safety health + logs
  - [ ] Outputs JSON or human-readable
  - [ ] Redacts secrets before emitting

### §5.4 User-Defined Credential Injection — **MEDIUM**

- [ ] Restore `config/user-services.yaml` schema (Pydantic)
- [ ] Standalone HTTP proxy (or extension to git-safety server)
  - [ ] Reads declared services, injects headers by host match
  - [ ] Host-side only; credentials never reach VM
  - [ ] HTTPS SNI routing (no MITM)
- [ ] Integration with `sbx`
  - [ ] `sbx policy allow network <sidecar-host>` wired up by `cast new`
  - [ ] Route decision documented
- [ ] Tests
  - [ ] Integration: declared Tavily/Perplexity endpoints get headers, others don't
  - [ ] Negative: undeclared host gets no injection, no placeholder leak
- [ ] Documentation
  - [ ] `docs/configuration.md` section for user services
  - [ ] Migration note: which services were auto-included in 0.20.x

### §5.5 Deep Policy Sidecar (was Phase 4) — **MEDIUM**

- [ ] Promote `github_filter.py` logic into generalized request inspector
  - [ ] Extract host/method/path/body rule engine
  - [ ] Keep the GitHub rules as a bundled policy set
- [ ] General rule format
  - [ ] YAML schema: `{host, method, path_pattern, body_jsonpath, action}`
  - [ ] Pydantic validation
  - [ ] Example rulesets for common providers
- [ ] Per-container rate limiting
  - [ ] Token-bucket by sandbox ID
  - [ ] Configurable limits
- [ ] Circuit breaker
  - [ ] Fail-closed behavior on upstream errors above threshold
  - [ ] Automatic half-open recovery
- [ ] Enable/disable toggle
  - [ ] Off by default; enabled via `foundry.yaml` or `cast new --deep-policy`
- [ ] Documentation
  - [ ] When to enable and example threat models addressed
  - [ ] Performance impact measurements

### §5.6 Chaos, Security Audit, Performance — **MEDIUM**

- [ ] Chaos tests
  - [ ] Kill `sbx` daemon mid-operation; verify safe failure
  - [ ] Kill `foundry-git-safety` server mid-push; verify wrapper returns non-zero, no partial write
  - [ ] Simulate network partition between VM and host safety server
  - [ ] Corrupted `sbx reset` (interrupted) — verify recovery
- [ ] Security audit
  - [ ] HMAC rotation procedure documented and tested
  - [ ] Wrapper-injection privilege review (who can call `sbx exec -u root`)
  - [ ] Credential-leak audit through the git-safety HTTP path
  - [ ] Privilege-escalation review: can a malicious wrapper response compromise the host?
  - [ ] External security review (optional but recommended before Gate B)
- [ ] Performance baselines vs 0.20.x proxy
  - [ ] Clone, status, fetch, push latency
  - [ ] First-request vs steady-state
  - [ ] Multiple concurrent sandboxes
  - [ ] Published in `docs/operations.md`

### §5.7 `sbx` Version Pinning and Drift Detection — **LOW**

- [ ] Pin tested-good `sbx` version in `foundry_sandbox/sbx.py`
  - [ ] Constant for min/max-supported version
  - [ ] `find_sbx_binary()` enforces version check; clear error on drift
- [ ] Weekly CI drift job
  - [ ] Runs `sbx --version` against latest release
  - [ ] Opens GitHub issue if it moves outside supported range
- [ ] Create `docs/sbx-compatibility.md` with tested-against matrix

### §5.8 Deferred / Nice-to-Have

- [ ] DNS-level filtering — investigate feasibility inside `sbx` network stack
- [ ] Native `sbx template` integration for presets
- [ ] Track `docker sandbox` CLI convergence (U27)
- [ ] SSE streaming proxy for major providers (performance, not security)

---

## Documentation Follow-Ups

- [ ] `foundry-git-safety/docs/troubleshooting.md`
- [ ] `foundry-git-safety/docs/migration.md` (from foundry-sandbox 0.20.x)
- [ ] `docs/security/wrapper-integrity.md` (§5.1)
- [ ] `docs/migration/0.20-to-0.21.md` (§5.2)
- [ ] `docs/observability/alerts.yaml` (§5.3)
- [ ] Runbook addendum to `docs/operations.md` (§5.3)
- [ ] Update `docs/security/security-model.md` to reflect wrapper integrity model

---

## Open Questions

| # | Question | Blocks |
|---|----------|--------|
| U7 | Does `sbx` support user-defined service credential injection? | §5.4 scope |
| U9 | Can a custom CA be trusted inside the VM? | §5.5 MITM option |
| U12 | Do templates persist injected binaries across `sbx reset`? | §5.1 |
| U13 | Can file sync be disabled for specific paths? | §5.1 hardening |
| U20 | Can `sbx exec --privileged` be restricted by policy? | §5.1 threat model |
| U26 | Linux microVM official support timeline (docs still say legacy)? | Linux messaging |
| U27 | Will `docker sandbox` and `sbx` converge? | §5.7 target surface |
| U28 | Is DNS-level filtering achievable inside `sbx` networking? | §5.8 |

---

## Decision Gates (mirrors `PLAN.md` §7)

### Gate A — Pre-release `0.21.0-rc`
- [ ] §5.2 migration command shipped
- [ ] §5.3 observability shipped (health + metrics + decision log)
- [ ] Rollback procedure tested
- [ ] CHANGELOG entry

### Gate B — Stable `0.21.0`
- [ ] Gate A complete
- [ ] §5.1 wrapper integrity shipped
- [ ] §5.6 security audit signed off
- [ ] At least one external user successfully migrated end-to-end
- [ ] Known-issues list published

### Gate C — Deprecate `main` architecture
- [ ] Gate B complete
- [ ] 30 days of production use across ≥3 users
- [ ] No P0 regressions

### Gate D — Enable §5.5 deep policy by default
- [ ] Concrete user request on record
- [ ] Evidence `sbx` domain-level policy is insufficient for that case
- [ ] §5.5 shipped behind opt-in flag and used in anger by ≥1 user first

---

## Alternative Scenarios (watch list)

| Scenario | Trigger | Response |
|----------|---------|----------|
| Docker deprecates `sbx` | Announcement, or 6+ months silent | Revert branch, resume 0.20.x maintenance; `foundry-git-safety` still ships |
| Breaking `sbx` CLI change | §5.7 drift job fires | Pin to older version, patch wrappers, re-test |
| Docker ships git-safety natively | Roadmap mention or policy feature landed | Re-scope `foundry-git-safety` to delta only |
| Linux microVM regresses to containers | Docs or release notes say so | Ship Linux-legacy notice; keep macOS/Windows on microVM |
| Wrapper-removal attacks seen in wild | Incident report | Accelerate §5.1; consider disabling `sbx exec --privileged` for agents |
