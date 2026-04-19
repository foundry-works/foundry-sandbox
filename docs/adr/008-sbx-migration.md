# ADR-008: Migration to Docker sbx Backend

## Status

Accepted

Date: 2026-04-19

Supersedes: ADR-001 (Unified Proxy Architecture), ADR-002 (Container Identity), ADR-004 (DNS Integration), ADR-005 (Failure Modes), ADR-007 (API Gateways)

## Context

In March 2026, Docker launched Docker Sandboxes (`sbx`), a microVM-based sandboxing system for running AI coding agents. After a one-week validation spike (Phase 0, see `docs/sbx-phase0-report.md`), we confirmed:

1. **MicroVM isolation works on Linux** — sbx v0.26.1 on Fedora 43 provides separate kernel isolation (sandbox kernel 6.12.44 vs host 6.17.8)
2. **Git wrapper injection is feasible** — wrapper can be installed via `sbx exec --user root` and routes git operations through the host-side git safety server via the sbx HTTP proxy
3. **Credential isolation works** — `sbx secret set -g` stores API keys on the host; sandboxes never see real credentials
4. **No git safety features exist in sbx** — Docker's policy system is network-only (domain allow/deny); no git operation guardrails, protected branches, or branch isolation
5. **Wrapper is removable by agent** — the agent has root inside the microVM and can delete the wrapper, falling back to unrestricted git

The existing docker-compose backend required significant maintenance: container lifecycle management, network configuration, a full mitmproxy-based proxy, Squid forward proxy, API gateways, DNS filtering, iptables rules, and a complex entrypoint system. Docker sbx handles most of this natively.

## Decision

Migrate the sandbox backend from docker-compose to Docker's `sbx` CLI:

1. **Extract git safety as standalone service** — `foundry-git-safety` runs on the host as a daemon (Flask on port 8083), independent of any container runtime. This was completed in Phase 2 (727 tests passing).
2. **Replace docker-compose with sbx CLI** — All sandbox lifecycle operations (`create`, `run`, `stop`, `rm`, `exec`, `ls`) delegate to the `sbx` binary. The `foundry_sandbox.sbx` module wraps all subprocess calls.
3. **Use sbx for credential injection** — `sbx secret set -g` replaces the unified proxy's credential injection pipeline. API keys are stored on the host and injected into HTTP headers by sbx's proxy.
4. **Use sbx for network policy** — `sbx policy` replaces Squid, mitmproxy, iptables, and the DNS filter with a simpler domain-based allow/deny system.
5. **Delete the entire `unified-proxy/` directory** — The proxy's functionality is replaced by sbx (network, credentials) and foundry-git-safety (git operations, policy enforcement).
6. **Delete docker-specific commands** — `cast build`, `cast prune`, and `cast upgrade` are no longer needed.

## Consequences

### Positive

- **Dramatically simpler architecture** — No more mitmproxy, Squid, API gateways, DNS filter, iptables, circuit breaker, or SQLite container registry
- **Stronger isolation** — MicroVM (separate kernel) vs container (shared kernel)
- **Reduced maintenance** — Docker manages the sandbox runtime, networking, and credential injection
- **Clearer separation of concerns** — sbx handles isolation and networking; foundry-git-safety handles git policy; `cast` handles orchestration
- **Smaller codebase** — Removed thousands of lines of proxy infrastructure code
- **Better tested git safety** — 727 tests for the extracted git safety layer (vs scattered proxy tests)

### Negative

- **Experimental dependency** — Docker Sandboxes is still labeled "Experimental" and has had breaking changes between `docker sandbox` and `sbx` CLIs
- **Wrapper removable by agent** — Unlike bind-mounted wrappers in docker-compose, the sbx wrapper is a regular file the agent can delete. Mitigated by template-based injection (`sbx template save`).
- **Lost fine-grained network control** — sbx policy is domain-level only (no method/path/body filtering, no MITM for custom providers). The old proxy supported method-level API filtering and body inspection.
- **No Linux install docs from Docker** — Install artifacts exist but documentation still says "MicroVM-based sandboxes require macOS or Windows." MicroVM isolation confirmed on Linux with sbx v0.26.1.
- **Proprietary license** — Docker Sandboxes is proprietary (free for individual use, team/enterprise requires sales contact)

### Neutral

- **User-facing CLI unchanged** — `cast new`, `cast attach`, `cast list`, etc. work identically; only the backend changes
- **Git worktree strategy unchanged** — Still uses bare repos + worktrees on the host
- **Git safety configuration unchanged** — `foundry.yaml` schema is the same

## Alternatives Considered

1. **Keep docker-compose + overlay sbx** — Maintain both backends. Rejected: doubles maintenance burden, unclear when to use which.
2. **Wait for Docker sbx GA** — Delay migration until Docker Sandboxes is GA. Rejected: no GA timeline announced; git safety extraction is valuable independently.
3. **Replace Docker entirely (e.g., Firecracker)** — Run our own microVM system. Rejected: massive engineering effort, Docker sbx provides 90% of what we need.

## References

- `docs/sbx-phase0-report.md` — Phase 0 validation spike report
- `docs/sbx-docker-questions.md` — Open questions for Docker team
- `foundry-git-safety/` — Extracted git safety package
- `foundry_sandbox/sbx.py` — sbx CLI wrapper module
- `foundry_sandbox/git_safety.py` — Git safety integration bridge
- `foundry_sandbox/commands/new_sbx.py` — sbx sandbox creation logic
- Docker Sandboxes docs: `docs.docker.com/ai/sandboxes/`
- Docker blog: "Docker Sandboxes: Run Agents in YOLO Mode, Safely" (March 31, 2026)
- Docker blog: "Why MicroVMs: The Architecture Behind Docker Sandboxes" (April 16, 2026)
