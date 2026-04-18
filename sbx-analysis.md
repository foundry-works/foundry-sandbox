# Rearchitecting foundry-sandbox on Docker's Native `sbx`

**Date:** 2026-04-18
**Branch:** sbx
**foundry-sandbox version:** 0.20.15

---

## 1. Executive Summary

Docker has shipped a native `sbx` CLI (`docker sbx`) that provides microVM lifecycle, network policies, secret management, file synchronization, and multi-agent support out of the box. This document analyzes whether foundry-sandbox (`cast`) should be rearchitected as a layer on top of Docker's `sbx` rather than orchestrating Docker primitives directly.

> **Important:** Docker Sandboxes uses **microVMs** (separate kernels per sandbox via macOS virtualization.framework or Windows Hyper-V), NOT containers. This is a fundamental architectural difference from foundry-sandbox's container-based approach. MicroVMs provide hypervisor-level isolation without shared kernels.

**Bottom line:** Docker's `sbx` already provides credential isolation through a network-level HTTP/HTTPS proxy (secrets never enter the VM), eliminating the primary reason foundry-sandbox built its own proxy layer. This changes the calculus significantly — Docker's `sbx` covers the bulk of foundry-sandbox's infrastructure concerns (microVM lifecycle, networking, secret management, credential injection, git worktrees). The remaining differentiators are git shadow mode (operation-level mediation, protected branches, push restrictions), deep API policy enforcement (method/path/body-level), and branch visibility isolation. A rearchitecture could eliminate roughly 72% of foundry-sandbox's codebase.

**Caveat:** Docker Sandboxes is currently marked **"Experimental"** in official Docker documentation. This carries meaningful risk for production adoption (see Section 7.7 and Risk Register).

---

## 2. Current foundry-sandbox Architecture

### 2.1 Component Map

```
┌─────────────────────────────────────────────────────────────────────┐
│  Host                                                               │
│                                                                     │
│  ┌──────────────┐    ┌─────────────────────────────────────────┐   │
│  │  cast CLI    │    │  unified-proxy container                 │   │
│  │  (Python)    │    │  ├── API gateways (ports 9848-9852)     │   │
│  │              │    │  ├── Squid forward proxy (8080)          │   │
│  │  Commands:   │    │  ├── mitmproxy (8081) [conditional]     │   │
│  │  new/start   │    │  ├── Git API server (8083)              │   │
│  │  attach/stop │    │  ├── DNS filter (53)                    │   │
│  │  destroy/... │    │  ├── Container registry (SQLite)        │   │
│  │              │    │  └── Internal API (Unix socket)         │   │
│  └──────┬───────┘    └──────────────┬──────────────────────────┘   │
│         │                           │                               │
│         │  docker-compose           │  Docker networks              │
│         │                           │  ├── credential-isolation     │
│         ▼                           │  └── proxy-egress             │
│  ┌──────────────┐                   │                               │
│  │  dev         │◄──────────────────┘                               │
│  │  container   │                                                   │
│  │  (sandbox)   │   git wrapper ──► Git API (8083)                 │
│  │              │   HTTP_PROXY ──► Squid (8080)                    │
│  │              │   *_BASE_URL ──► Gateways (9848-9852)            │
│  └──────────────┘                                                   │
│                                                                     │
│  ~/.sandboxes/repos/     Bare git repositories                      │
│  ~/.sandboxes/worktrees/ Git worktrees per sandbox                  │
│  ~/.sandboxes/claude-config/  AI tool configs per sandbox           │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Codebase Size by Concern

| Concern | Files | Lines | Ownership |
|---------|-------|-------|-----------|
| Container lifecycle (docker.py, compose.py, image.py, container_*.py, foundry_plugin.py) | 7 | ~3,160 | Docker-level orchestration |
| Network management (network.py, proxy.py) | 2 | ~860 | Docker-level orchestration |
| Git worktree management (git_worktree.py, git.py, git_path_fixer.py) | 3 | ~1,090 | Shared with Docker sbx |
| Proxy — git safety (git_api, git_operations, branch_isolation, git_policies, git_command_validation, branch_output_filter, branch_types, git_subprocess, github-*, git_proxy addon) | 12 | ~6,870 | Foundry-specific (keep) |
| Proxy — credential infrastructure (credential_injector, policy_engine, dns_filter, container_identity, metrics, rate_limiter, circuit_breaker, registry, internal_api, security_policies, user_services, gateways, token managers, oauth_managers) | 21 | ~6,300 | Foundry-specific (delete) |
| CLI commands (commands/) | 23 | ~4,980 | Foundry-specific |
| Stubs / entrypoints | 5 | ~1,015 | Mix |
| Config / models / utils | 26 | ~6,860 | Foundry-specific |
| **Total** | ~99 | **~30,700** | |

---

## 3. Docker's Native `sbx` Capabilities

### 3.1 Architecture

Docker Sandboxes uses a **hybrid architecture: lightweight microVMs containing private Docker daemons and containers**. Key implications:

- **Separate kernels** — Each sandbox runs its own OS kernel via a custom Virtual Machine Manager (VMM), providing hypervisor-level isolation (no shared kernel attacks)
- **Private Docker daemon per sandbox** — Each microVM runs its own isolated Docker daemon. The agent container runs inside this daemon. Containers in one sandbox cannot see containers or images from another (or from the host)
- **Three hypervisor backends** — macOS virtualization.framework, Windows Hyper-V Platform, and **Linux KVM**. All three are architecturally supported; the KVM backend exists in the VMM but no standalone Linux install instructions have been published yet
- **Standalone CLI — Docker Desktop NOT required** — The launch blog (March 31, 2026) explicitly states: *"Docker Sandboxes are standalone; you don't need Docker Desktop."* Docker Desktop integration is listed as "coming soon." Install via `brew install docker/tap/sbx` (macOS) or `winget install Docker.sbx` (Windows)
- **File synchronization, not bind-mounts** — The host workspace is synced bidirectionally to the VM. Files appear at the same absolute paths as on the host. This is NOT a Docker bind-mount; it's a sync daemon. This has major implications for injecting custom binaries (see Section 5.2).
- **Only HTTP/HTTPS is proxied** — Raw TCP, UDP, ICMP, and other non-HTTP protocols are **blocked at the network layer**. SSH git operations (`git@github.com:...`) would NOT be credential-injected. Only HTTPS git operations work through the proxy. DNS resolution is handled by the host-side proxy, not the sandbox VM.
- **No arbitrary volume mounts** — Only the workspace path and additional read-only workspace paths are supported (via `sbx create claude . /path/to/docs:ro`). No general-purpose volume mounting.
- **No `--entrypoint` flag** — The entrypoint cannot be customized at creation time. Custom images can be built via `-t <tag>` (`sbx template save`) which captures the full filesystem state.
- **Historical context** — Before Docker Desktop 4.58, sandboxes were regular Docker containers. The 4.58 release migrated to the microVM architecture. Users on 4.57 get container-based sandboxes (visible in `docker ps`).

### 3.2 Feature Matrix

| Feature | Docker `sbx` | foundry-sandbox (`cast`) |
|---------|-------------|--------------------------|
| **Isolation model** | Hybrid: MicroVM + private Docker daemon (hypervisor) | Container (namespace) |
| **Container lifecycle** | `create`, `run`, `stop`, `rm`, `ls` | `new`, `start`, `stop`, `destroy`, `list` |
| **Multi-agent support** | 8 agents (claude, codex, copilot, gemini, kiro, opencode, shell, docker-agent) | 4 agents (claude, gemini, codex, opencode) |
| **Git worktrees** | `--branch` flag (including `auto`) | `--branch` flag via git_worktree.py |
| **Network policies** | `policy allow/deny network`, 3 default profiles (allow-all, balanced, deny-all) | Custom allowlist.yaml + Squid + DNS filter + mitmproxy |
| **Policy conflict resolution** | Deny takes precedence over allow | Hierarchical evaluation |
| **IP address policies** | Supported — IP addresses valid as policy resources | Supported — with encoding-aware blocking |
| **Secret management** | `secret set` (global `-g` or per-sandbox), 9 services, **network-level proxy injection** — secrets never in VM | Proxy-injected placeholders, never in container |
| **Port publishing** | `ports --publish/--unpublish`, default HOST_IP 127.0.0.1 | `cast` doesn't have this (manual docker) |
| **Templates** | `template save/load/ls/rm` — full image snapshots | Preset system (config-only, not image) |
| **Sandbox save** | `sbx template save` — persist sandbox as reusable template image | Not supported |
| **Sandbox reset** | `sbx reset` — reset entire `sbx` installation (all sandboxes, policies, secrets, daemon) | Not supported |
| **Diagnostics** | `diagnose` with JSON/github-issue output | None |
| **Resource limits** | `--cpus`, `--memory` | Not exposed in CLI |
| **Exec** | `sbx exec` with full docker-exec flags | `cast attach` via tmux |
| **Interactive mode** | `sbx` with no command opens full TUI dashboard (live CPU/memory, keyboard lifecycle, network governance); `sbx run -it` for interactive sessions | `cast attach` via tmux |
| **Multiple workspaces** | `sbx create claude . /path/to/docs:ro` | Single workspace |
| **OAuth flows** | `secret set --oauth` (openai/global only) | Manual token setup |
| **Custom images** | `-t <tag>` to use saved templates | Custom Dockerfile |
| **`docker sandbox` CLI** | Separate CLI integrated into Docker CLI (not `sbx`): create, exec, inspect, ls, network, reset, rm, run, save, stop, version. Note: `docker sandbox save` loads into host Docker daemon; `sbx template save` loads into sandbox runtime's image store. | N/A |

### 3.3 What Docker `sbx` Does Well

1. **Zero-config agent onboarding** — `sbx run claude .` and you're running. No proxy setup, no compose files, no credential placeholder generation.
2. **Balanced default policy** — A `balanced` profile that allows common dev traffic (package registries, APIs) and blocks everything else. Foundry-sandbox requires a hand-maintained 60+ domain allowlist.
3. **Template system** — Save entire sandbox images (with installed packages, tools, configs) and reuse them. Templates can be exported to tar files for sharing across hosts (`sbx template save --output`) and loaded elsewhere (`sbx template load`). Foundry-sandbox only saves CLI flags as presets.
4. **Diagnostics** — Built-in diagnostic tool with JSON output and Docker support upload.
5. **Broader agent coverage** — 8 agents vs 4, including copilot, kiro, and docker-agent (Docker's own agent).
6. **Multiple workspaces** — Mount additional directories read-only in a single command.
7. **Resource controls** — CPU and memory limits exposed as first-class flags.
8. **Sandbox persistence** — `sbx template save` persists sandbox as reusable template image; `sbx template load` imports shared templates from tar files.
9. **Interactive TUI dashboard** — Running `sbx` with no command opens a full terminal UI showing live sandbox cards with CPU/memory usage, keyboard-driven lifecycle management (`c` create, `s` start/stop, `Enter` attach, `x` shell, `r` remove), and a network governance panel for monitoring connections and managing allow/block rules. Switch panels with `tab`, help with `?`.
10. **Per-sandbox secret scoping** — Secrets can be global (`-g`) or scoped to individual sandboxes.

---

## 4. The Gap Analysis

### 4.1 What Docker `sbx` Cannot Replace

These are the features that make foundry-sandbox unique and would need to survive any rearchitecture:

#### A. Credential Isolation Through Proxy Injection

**How foundry-sandbox does it:**
- Sandbox receives `CRED_PROXY_<hex>` placeholder values, never real API keys
- Unified proxy intercepts all outbound requests, strips placeholders, injects real credentials
- Works across all protocols: HTTP, HTTPS (via MITM), git
- Container identity verified by IP + optional header

**How Docker `sbx` does it:**
- `sbx secret set -g github` stores secrets on the host
- **The sandbox proxy injects credentials at the network level** — confirmed by official Docker documentation ([docs.docker.com/ai/sandboxes/security/](https://docs.docker.com/ai/sandboxes/security/)): *"API keys are injected into HTTP headers by the host-side proxy. Credential values never enter the VM."*
- `gh auth status` shows "not logged in" inside the sandbox — real credentials are never exposed to the VM
- Supports 9 services: anthropic, aws, github, google, groq, mistral, nebius, openai, xai
- OAuth flow support (`secret set --oauth`) for OpenAI (openai/global only)
- Secrets can be scoped globally (`-g`) or per-sandbox

**Assessment: Docker `sbx` already has credential isolation.** This is confirmed by Docker's official security documentation, not just inference from behavior. The fundamental architecture is identical: a host-side proxy intercepts outbound HTTP/HTTPS requests and injects real credentials into headers. Real credentials never enter the VM.

**Remaining nuance:**
1. **Non-HTTP protocols blocked:** Only HTTP/HTTPS traffic is proxied. Raw TCP, UDP, ICMP, and SSH are blocked at the network layer. This means SSH git operations (`git@github.com:...`) will NOT receive credential injection. Only HTTPS git (`https://github.com/...`) works.
2. **Provider coverage:** Docker supports 9 services. Foundry-sandbox additionally covers Tavily, Perplexity, Semantic Scholar, and Zhipu via MITM injection, plus arbitrary user-defined services via `config/user-services.yaml`.
3. **Injection mechanism depth:** Foundry uses dedicated API gateways for major providers (streaming SSE relay, per-container rate limits, circuit breakers). Docker's proxy is simpler — HTTP header injection without per-endpoint controls.
4. **Custom CA / MITM:** Foundry uses mitmproxy for providers that lack base URL support. Docker's proxy likely does not support custom CA certificates inside the VM, so MITM-dependent providers may not work.

**Severity: LOW** — The core security property (secrets never in VM) is preserved by Docker `sbx`. Minor gaps exist for niche providers, non-HTTP protocols, and custom injection patterns.

#### B. Git Shadow Mode

**How foundry-sandbox does it:**
- `.git` directory hidden from sandbox (bind-mount `/dev/null` + tmpfs overlay)
- `git` binary replaced with authenticated wrapper (`git-wrapper.sh`)
- All git operations proxied through HMAC-signed API to server-side bare repo
- Server enforces: protected branches, force-push blocking, branch deletion blocking, push file restrictions, branch isolation, push size limits

**How Docker `sbx` does it:**
- `--branch` creates a git worktree
- No mention of git operation mediation, protected branches, or push restrictions

**The gap:** Docker `sbx` gives the agent full git access with no guardrails. An AI agent could force-push to main, delete release branches, push to `.github/workflows/`, or access other sandboxes' branches.

**Injection challenge:** Because Docker Sandboxes uses file synchronization (not bind-mounts), the git wrapper cannot be injected by mounting a host file into the VM. Instead, it must be installed via `sbx exec <name> -u root` to copy the wrapper into place and set permissions. This is more fragile than bind-mounting and could be undone by the agent (who has full sudo). See Section 5.2 for approach.

**Severity: HIGH** — Git safety is a core security pillar protecting against AI mistakes.

#### C. API Gateway Layer

**How foundry-sandbox does it:**
- 5 dedicated aiohttp gateways (Anthropic, OpenAI, GitHub, Gemini, ChatGPT)
- Accept plaintext HTTP on internal Docker network
- Validate container identity
- Inject credentials
- Forward to HTTPS upstream with streaming SSE relay
- Per-gateway rate limiting, circuit breaking, metrics

**How Docker `sbx` does it:**
- Unknown. Likely relies on the built-in HTTP/HTTPS proxy for header injection without dedicated per-provider gateways.

**The gap:** The gateway layer provides:
1. **Streaming performance** — SSE relay without buffering long-running responses
2. **Credential injection without MITM** — Major providers don't need TLS interception
3. **Container-scoped rate limiting** — Per-sandbox burst and sustained limits
4. **GitHub-specific policy enforcement** — Block merges, releases, PR closes

**Severity: MEDIUM** — Performance and per-container controls matter at scale, but basic functionality works without gateways.

#### D. Deep Policy Engine

**How foundry-sandbox does it:**
- Hierarchical evaluation: container-specific → sandbox-wide → global → default deny
- IP literal blocking (all encodings: decimal, octal, hex, integer, IPv6 brackets)
- Endpoint path enforcement (segment-aware matching)
- GitHub API blocklist (merge, release, deploy keys, Actions secrets)
- Body inspection for security-relevant PATCH operations
- DNS-level filtering with NXDOMAIN for blocked domains
- Fail-closed behavior throughout

**How Docker `sbx` does it:**
- Domain-level and IP-level allow/deny (exact + wildcard)
- Three preset profiles (allow-all, balanced, deny-all)
- Deny rules take precedence over allow rules
- Policy log with JSON output (`sbx policy log`)
- `sbx policy ls` shows active rules and reasons

**The gap:** Docker's policy system is coarse-grained (domain/IP-level only). Foundry-sandbox enforces policies at the HTTP method + path + body level. An agent allowed to reach `api.github.com` can do anything; foundry-sandbox allows GET/POST to most endpoints but blocks merges, releases, and webhook management.

**Severity: MEDIUM-HIGH** — Domain-level policies protect against data exfiltration but not against authorized-but-dangerous operations.

#### E. Branch Visibility Isolation

**How foundry-sandbox does it:**
- `git branch`, `for-each-ref`, `ls-remote`, `show-ref`, `log --decorate` output filtered
- Each sandbox sees only its own branch + well-known branches (main, develop, etc.)
- SHA arguments verified as ancestors of allowed branches
- Fail-closed: sandboxes without branch identity cannot execute git operations

**How Docker `sbx` does it:**
- Worktree isolation provides directory isolation but no ref visibility filtering

**The gap:** Multiple sandboxes sharing a bare repo can see each other's branches. Information leakage risk for multi-tenant scenarios.

**Severity: MEDIUM** — Matters for organizations running multiple concurrent sandboxes on the same repo.

### 4.2 Feature Comparison Table

| Feature | Docker `sbx` | foundry-sandbox | Gap? |
|---------|:------------:|:---------------:|:----:|
| MicroVM lifecycle | ✅ | — (containers) | Different model |
| 8 AI agents | ✅ | ❌ (4) | Docker wins |
| Git worktree creation | ✅ | ✅ | — |
| Branch auto-generation | ✅ (`--branch auto` on `sbx run`; not documented on `sbx create`) | ❌ | Docker wins (partial) |
| Network allow/deny (domain) | ✅ | ✅ | — |
| Network allow/deny (IP) | ✅ | ✅ | — |
| Network policy (method+path+body) | ❌ | ✅ | **Depth gap** |
| Balanced default policy | ✅ | ❌ (manual allowlist) | Docker wins |
| Deny-takes-precedence | ✅ | ✅ | — |
| Secret storage | ✅ | ✅ (via proxy) | — |
| Secrets never in VM | ✅ (confirmed by Docker docs) | ✅ | — |
| Per-sandbox secret scoping | ✅ | ✅ | — |
| Git operation mediation | ❌ | ✅ | **Critical gap** |
| Protected branch enforcement | ❌ | ✅ | **High gap** |
| Branch visibility filtering | ❌ | ✅ | Medium gap |
| API gateways with streaming | ❌ | ✅ | Medium gap |
| Per-container rate limiting | ❌ | ✅ | Medium gap |
| Circuit breaker (fail-closed) | ❌ | ✅ | Low gap |
| Push file restrictions | ❌ | ✅ | High gap |
| DNS-level filtering | ❌ | ✅ | Medium gap |
| Port publishing | ✅ | ❌ | Docker wins |
| Templates (image snapshots) | ✅ (save/load/ls/rm, export to tar for sharing) | ❌ (config presets) | Docker wins |
| Sandbox save/reset | ✅ (`sbx reset` resets entire installation, not per-sandbox) | ❌ | Docker wins (with caveats) |
| Interactive mode | ✅ (full TUI dashboard with live status, keyboard lifecycle, network governance) | ✅ (tmux) | Docker wins |
| Diagnostics | ✅ | ❌ | Docker wins |
| Resource limits (CPU/memory) | ✅ | ❌ | Docker wins |
| Multiple workspaces | ✅ | ❌ | Docker wins |
| OAuth flows | ✅ (openai/global) | ❌ | Docker wins |
| Docker authentication required | ✅ (`sbx login`/`sbx logout`) — but standalone use may not require Docker account | ❌ (uses host credentials) | Foundry wins (clearer) |
| Custom images (-t) | ✅ | ✅ | — |
| User-defined API services | ❌ | ✅ | Foundry wins |
| CI/CD pipeline protection | ❌ | ✅ | High gap |
| SSH protocol support | ❌ (blocked) | ✅ | **Foundry wins** |
| Arbitrary volume mounts | ❌ (workspace only) | ✅ | Foundry wins |
| Custom entrypoint | ❌ (use templates) | ✅ | Foundry wins |
| Linux host support | ❓ KVM backend exists in VMM, no install docs published | ✅ | Foundry wins (for now) |
| Preset system | ❌ (templates instead) | ✅ | Different approach |

---

## 5. Proposed Rearchitecture

### 5.1 High-Level Design

```
┌──────────────────────────────────────────────────────────────────────┐
│  Layer 3: Foundry Additive Layer (what we build)                     │
│                                                                      │
│  ┌──────────────┐  ┌─────────────────────────────────────────────┐  │
│  │  Git Safety  │  │  Deep Policy Engine                         │  │
│  │  Server      │  │  (method/path/body)                         │  │
│  │              │  │                                             │  │
│  │  ┌────────┐  │  │  - GitHub blocklist (merges, releases)     │  │
│  │  │ Branch │  │  │  - Push file restrictions                   │  │
│  │  │ isol.  │  │  │  - Body inspection for PATCH operations     │  │
│  │  ├────────┤  │  │  - Per-container rate limiting              │  │
│  │  │ Push   │  │  │  - Circuit breaker (fail-closed)            │  │
│  │  │ guards │  │  └─────────────────────────────────────────────┘  │
│  │  ├────────┤  │                                                    │
│  │  │ HMAC   │  │  NOTE: Credential isolation proxy is NO LONGER   │
│  │  │ auth   │  │  needed here — Docker's sbx already provides it  │
│  │  └────────┘  │  via network-level proxy injection.               │
│  └──────────────┘  Confirmed by official Docker security docs.      │
│                                                                      │
│  ┌─────────────────┐                                                │
│  │  cast CLI       │  Translates cast commands → sbx commands +     │
│  │  (thin wrapper) │  configures git-safety layer only              │
│  └────────┬────────┘                                                │
│           │                                                         │
├───────────┼─────────────────────────────────────────────────────────┤
│           ▼                                                         │
│  Layer 2: Docker `sbx` (what Docker provides)                       │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Each sandbox is a microVM containing:                        │ │
│  │  ┌─────────────────┐  ┌──────────────────────────────────┐   │ │
│  │  │ Private Docker  │  │  Agent container                 │   │ │
│  │  │ daemon          │──│  (Claude, Codex, Copilot, etc.)  │   │ │
│  │  └─────────────────┘  └──────────────────────────────────┘   │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌─────────┐ ┌──────────┐ │
│  │MicroVM   │ │ Network   │ │ Secret   │ │ Git     │ │ Port     │ │
│  │lifecycle │ │ policy    │ │ storage  │ │worktree │ │publish   │ │
│  └──────────┘ │ + cred    │ │ + proxy  │ └─────────┘ └──────────┘ │
│  ┌──────────┐ │ injection │ │ injection│ ┌─────────┐ ┌──────────┐ │
│  │Templates │ └───────────┘ └──────────┘ │ Multi-  │ │TUI dash- │ │
│  │(images)  │ ┌───────────┐ ┌──────────┐ │workspace│ │  board   │ │
│  └──────────┘ │Diag-      │ │Resource  │ └─────────┘ └──────────┘ │
│  ┌──────────┐ │nostics    │ │limits    │ ┌─────────┐ ┌──────────┐ │
│  │Save/Reset│ └───────────┘ └──────────┘ │Sandbox  │ │Cred     │ │
│  └──────────┘                            │exec     │ │isolation│ │
│                                          └─────────┘ │(HTTP/S  │ │
│                                                      │only)    │ │
│                                                      └──────────┘ │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 1: Host Hypervisor                                            │
│           macOS virtualization.framework │ Windows Hyper-V           │
│           Linux KVM (backend exists, no install docs yet)            │
│                                                                      │
│  NOTE: sbx is standalone — Docker Desktop NOT required               │
└──────────────────────────────────────────────────────────────────────┘
```

### 5.2 How It Would Work

Since Docker's `sbx` already handles credential isolation via its built-in proxy, the foundry layer only needs to add git safety and deep policy enforcement.

#### `cast new` becomes:

```bash
# 0. Authenticate with Docker (may be optional for standalone use)
sbx login

# 1. Store credentials on the host (Docker's proxy injects them)
sbx secret set -g anthropic -t "$ANTHROPIC_API_KEY"
sbx secret set -g github -t "$(gh auth token)"

# 2. Create sandbox via Docker sbx (handles microVM, worktree, network, cred injection)
#    NOTE: Workspace paths are mirrored identically in the VM
#    NOTE: Agent arguments require -- separator: sbx run claude -- --continue
sbx create --name <name> --branch <branch> claude <workspace>

# 3. Configure network policy (use Docker's built-in)
#    NOTE: sbx policy set-default must be run before custom rules
#    NOTE: sbx policy reset stops all running sandboxes
sbx policy set-default balanced
sbx policy allow network <extra-domains>

# 4. [Foundry layer] Start git safety server alongside sandbox
#    This is the ONLY additive component needed
foundry-git-safety start --sandbox <name> \
  --protected-branches main,develop,release \
  --push-restrictions .github/workflows/,Makefile

# 5. [Foundry layer] Install git wrapper into running sandbox
#    NOTE: Cannot bind-mount (file sync, not volumes). Must install via exec.
#    NOTE: The wrapper file must be placed in the workspace on the host first;
#    file sync mirrors it to the same path inside the VM, then sbx exec copies
#    it to /usr/local/bin/ where it replaces the system git.
#    sbx exec supports: -u (user), -e (env vars), -w (workdir), --privileged, -d (detach), -i/-t (interactive)
sbx exec <name> -u root -- bash -c \
  "cp <workspace>/git-wrapper.sh /usr/local/bin/git && chmod 755 /usr/local/bin/git"
#    Alternative: inject GIT_PROXY_COMMAND or other env vars via -e flag
#    Alternative: build wrapper into a custom template for persistence across resets
```

**Git wrapper injection is the critical challenge.** Docker Sandboxes uses file synchronization, not bind-mounts. The wrapper must be installed via `sbx exec` as root. This means:
- The agent (who has full sudo) could remove or replace the wrapper
- A `sbx reset` destroys the entire installation (all sandboxes, policies, secrets) — it is NOT a per-sandbox operation. Use `--preserve-secrets` to keep secrets.
- The wrapper must be re-injected after any reset
- An alternative is to build the wrapper into a custom template (`sbx template save`) so it survives resets

#### Credential flow (handled entirely by Docker's sbx):

```
AI Agent in microVM
  ├── HTTP/HTTPS API requests → Docker's built-in proxy → injects real credentials → upstream
  ├── HTTPS git ops → Docker's built-in proxy → injects GitHub token → github.com
  ├── SSH git ops → BLOCKED (non-HTTP protocols not proxied)
  └── git (wrapper) → Foundry git safety server → policy check → bare repo
```

No sidecar proxy needed. Docker's built-in proxy handles credential isolation for all 9 supported services. However, **only HTTP/HTTPS traffic is proxied** — SSH, raw TCP, UDP, and ICMP are blocked at the network layer.

### 5.3 Code That Gets Deleted

Since Docker's `sbx` handles credential isolation natively, the entire unified-proxy (except the git safety components) can be removed.

| Module | Lines | Fate |
|--------|-------|------|
| Container lifecycle (docker.py, compose.py, image.py, container_*.py, foundry_plugin.py) | ~3,160 | **Delete** — `sbx` handles this |
| Network management (network.py, proxy.py) | ~860 | **Delete** — `sbx policy` handles this |
| Git worktree management (git_worktree.py, git.py, git_path_fixer.py) | ~1,090 | **Delete** — `sbx --branch` handles this |
| Proxy credential infrastructure (credential_injector, policy_engine, dns_filter, container_identity, metrics, rate_limiter, circuit_breaker, registry, internal_api, security_policies, user_services, gateways, token managers, oauth_managers) | ~6,300 | **Delete** — Docker's proxy handles this |
| `constants.py` (Docker paths, timeouts) | ~270 | **Simplify** |
| `commands/new*.py`, `commands/start.py` | ~2,425 | **Rewrite** — thin `sbx` wrappers |
| `commands/destroy.py`, `commands/stop.py` | ~320 | **Delete** — delegate to `sbx rm/stop` |
| `commands/list_cmd.py`, `commands/info.py`, `commands/status.py` | ~395 | **Simplify** — delegate to `sbx ls` |
| `commands/build.py` | ~45 | **Delete** — `sbx` manages images |
| `commands/preset.py` | ~105 | **Rewrite** — wrap `sbx template` |
| `commands/attach.py`, `commands/prune.py`, `commands/upgrade.py` | ~665 | **Delete/Simplify** |
| Credential setup, API keys, user services | ~1,360 | **Delete** — `sbx secret` handles this |
| Stubs (AGENTS.md, CLAUDE.md), entrypoints | ~610 | **Delete** — `sbx` manages agent setup |
| Other config/utils (validate, state, paths, tmux, tui, ide, etc.) | ~4,500 | **Simplify/Delete** |
| **Total deleted** | **~22,300** | |

### 5.4 Code That Gets Kept/Rewritten

| Module | Lines | Fate |
|--------|-------|------|
| Git safety modules (git_api, git_operations, branch_isolation, git_policies, git_command_validation, branch_output_filter, branch_types, git_subprocess, github-api-filter, github_config, github_gateway, git_proxy addon) | ~6,870 | **Keep** — core git safety value |
| `stubs/git-wrapper.sh` | ~400 | **Keep** — git command interception (install via `sbx exec`) |
| `foundry_sandbox/cli.py` | ~235 | **Rewrite** — thin `sbx` wrapper |
| `foundry_sandbox/config.py` | ~140 | **Keep** — sandbox metadata |
| `foundry_sandbox/models.py` | ~175 | **Keep** — Pydantic models |
| `commands/git_mode.py` | ~235 | **Keep** — host/sandbox toggle (may need rewrite for file-sync model) |
| `commands/refresh_creds.py` | ~225 | **Rewrite** — `sbx secret` integration |
| Security policies (`security_policies.py`) | ~310 | **Keep** — GitHub blocklist |
| **Total kept/rewritten** | **~8,600** | |

**Net reduction: ~30,700 lines → ~8,600 lines (72% reduction)**

---

## 6. Pros

### 6.1 Reduced Maintenance Burden (~72% less code)

Docker handles microVM lifecycle, networking, secret management, credential injection, and git worktrees. foundry-sandbox no longer needs to:
- Assemble docker-compose YAML with subnet calculations
- Manage Docker volumes and tmpfs mounts
- Implement network mode switching (limited/host-only/none)
- Build custom Docker images with agent-specific tooling
- Track Docker API changes and compose file format versions
- **Maintain the proxy credential infrastructure** (~6,300 lines: credential injector, policy engine, DNS filter, API gateways, rate limiter, circuit breaker, token managers, OAuth managers)

**Estimated effort saved:** ~22,300 lines, ~72% of the codebase. The remaining ~8,600 lines are focused purely on git safety — the one area Docker `sbx` doesn't cover.

### 6.2 Faster Feature Availability

Docker `sbx` ships with features foundry-sandbox doesn't have:
- **Templates (image snapshots)** — Persist installed packages and tool versions
- **Sandbox save/reset** — Persist or reset running sandbox state
- **Port publishing** — `sbx ports` with default HOST_IP 127.0.0.1
- **Diagnostics** — Built-in troubleshooting
- **Resource limits** — CPU and memory controls
- **More agents** — Copilot, Kiro, docker-agent (8 vs 4)
- **OAuth flows** — `sbx secret set --oauth` for OpenAI
- **Multiple workspaces** — Read-only mounts for docs/references
- **Auto branch generation** — `--branch auto`
- **Interactive mode** — `sbx run -it`

### 6.3 Better Developer Experience

```bash
# Current foundry-sandbox
cast new --branch feature/login claude /path/to/project
# → generates compose YAML, creates subnet, provisions volumes, starts proxy...

# On Docker sbx
sbx run --branch feature/login claude /path/to/project
# → Docker handles everything natively
```

The "just works" factor is significantly higher. Docker invests in onboarding, documentation, and installer tooling that foundry-sandbox would benefit from.

### 6.4 Docker Ecosystem Integration

- **Docker Desktop integration** — "Coming soon" per launch blog. Sandboxes will be visible in Docker Dashboard.
- **`docker sandbox` CLI** — Separate CLI surface integrated into Docker CLI (not `sbx`): create, exec, inspect, ls, network, reset, rm, run, save, stop, version. Note: `docker sandbox save` loads into host Docker daemon; `sbx template save` loads into sandbox runtime image store.
- **Docker Hub** — Agent images maintained by Docker
- **Enterprise features** — Docker's RBAC, audit logging, etc. (licensing unclear)

### 6.5 Simpler Upgrade Path

Agent tooling changes rapidly (Claude Code, Gemini CLI, Codex all update weekly). Docker `sbx` maintains agent images, so foundry-sandbox doesn't need to track version bumps, breaking changes, and new auth mechanisms for each agent.

### 6.6 Stronger Isolation Model

MicroVMs provide hypervisor-level isolation (separate kernels) vs. container-level isolation (shared kernel). This is a security improvement:
- No kernel exploit vector between sandboxes
- No shared kernel namespace attacks
- Hardware-enforced memory boundaries

---

## 7. Cons

### 7.1 Potential Depth Gaps in Docker's Credential Isolation (MEDIUM)

Docker's `sbx` provides network-level credential injection with real secrets never entering the VM (see Section 4.1.A for full analysis). This section summarizes the residual depth gaps:

1. **Provider coverage:** Docker covers 9 services. Foundry adds Tavily, Perplexity, Semantic Scholar, Zhipu, and arbitrary user-defined services.
2. **Injection mechanism depth:** Foundry's dedicated API gateways (streaming SSE relay, per-container rate limits, circuit breakers) are more sophisticated than Docker's HTTP header injection.
3. **Policy depth:** Foundry enforces method/path/body-level policies; Docker is domain-level only.
4. **Non-HTTP protocols:** SSH, raw TCP, UDP, and ICMP are blocked. Foundry supports all protocols.

**Mitigation:** Request Docker add user-defined service support; keep a lightweight policy layer for API-level restrictions; accept domain-level granularity for most cases; ensure git uses HTTPS.

### 7.2 Dependency on Docker's Release Cadence

Foundry-sandbox would become dependent on Docker's `sbx` for:
- Bug fixes in microVM lifecycle
- New agent support
- Security patches
- Feature additions (e.g., custom proxy injection points)

If Docker deprecates or changes `sbx`, foundry-sandbox must adapt. This is vendor dependency risk.

### 7.3 Reduced Control Over Security Posture

Docker `sbx` makes security decisions that foundry-sandbox can't override:
- How secrets are stored and transmitted
- What capabilities the VM receives
- Default filesystem permissions
- Network stack configuration (HTTP/HTTPS only)
- File synchronization behavior

If Docker's defaults don't match foundry-sandbox's threat model, the rearchitecture weakens security.

### 7.4 Abstraction Leaks and Edge Cases

Any abstraction over `sbx` will have edge cases where `sbx`'s behavior doesn't match what foundry-sandbox needs. Examples:
- `sbx` uses file sync, not bind-mounts — git wrapper injection requires `sbx exec`, not volume mounting
- `sbx` does not support custom entrypoints — must use templates (`-t`) instead
- `sbx` does not support arbitrary volume mounts — only workspace paths
- `sbx` does not support SSH protocol — only HTTP/HTTPS is proxied
- Agent with full sudo can remove injected git wrapper
- `sbx reset` destroys the entire installation (all sandboxes, policies, secrets, daemon) — not a per-sandbox reset

Each leak requires a workaround, potentially negating the simplification benefit.

### 7.5 Docker Account Requirements (Unclear)

`sbx` has `login`/`logout` commands, and the launch blog (March 31, 2026) states: *"Docker Sandboxes are standalone; you don't need Docker Desktop"* and *"Individual developers can install and run Docker Sandboxes today, standalone, no Docker Desktop license required."* However, `sbx login` exists and some features (enterprise policy management, credential vaults) may require authentication. The exact account requirements for standalone use are unclear.
- Foundry-sandbox currently requires no external account — it uses host-level credentials directly
- Enterprise/team features (centralized policies, credential vaults) may involve licensing tiers but no specifics are published
- `cast` would need to handle login state if `sbx login` is required for credential injection

### 7.6 `sbx policy reset` Stops Running Sandboxes

Removing all custom policies via `sbx policy reset` stops any running sandboxes. This means policy changes cannot be hot-reloaded — they require a sandbox restart cycle.

### 7.11 Host Communication Requires Proxy (Phase 0 Finding)

Sandboxes cannot directly reach host ports. All host-bound traffic must route through the HTTP proxy at `gateway.docker.internal:3128`. Direct connections to other host ports connect but receive empty responses. The git wrapper must use `host.docker.internal` as the target hostname and route through `--proxy http://gateway.docker.internal:3128`.

### 7.12 Linux MicroVM Confirmed (Phase 0 Finding)

The analysis originally stated "Linux users can use legacy container-based sandboxes with Docker Desktop 4.57." This is **outdated for sbx v0.26.1**. On Linux, `sbx` creates microVMs with a separate kernel (6.12.44 vs host 6.17.8), providing the same hypervisor-level isolation as macOS/Windows. This removes the Linux support blocker from the risk register.

### 7.7 Testing Complexity

Testing becomes harder because:
- Tests need Docker `sbx` installed (not just Docker Engine)
- `sbx` behavior may differ across versions
- Integration tests must account for `sbx` state management
- CI pipeline needs `sbx` setup
- MicroVM behavior may differ from container behavior in subtle ways

### 7.8 Migration Cost

- Existing users have `cast` workflows, scripts, and muscle memory
- `.sandboxes/` directory structure would change
- Git worktree management would differ (file sync vs bind-mount)
- Proxy configuration would be eliminated entirely
- Documentation rewrite
- Linux-only users may not be supported

### 7.9 Experimental Status (HIGH)

Docker Sandboxes is explicitly marked **"Experimental"** in official Docker documentation. It launched March 31, 2026 with the blog post *"Docker Sandboxes: Run Agents in YOLO Mode, Safely"* and received an architecture deep-dive on April 16, 2026 (*"Why MicroVMs: The Architecture Behind Docker Sandboxes"*). No GA timeline has been announced. This means:
- **Very new** — Less than 3 weeks old as of this analysis. Rapid iteration likely.
- **No stability guarantees** — APIs, CLI commands, and behavior may change without notice
- **No SLA** — Docker may not prioritize bug fixes or security patches
- **Possible deprecation** — Docker could discontinue the feature
- **Limited documentation** — Some behaviors are undocumented or underdocumented (e.g., interactive mode, balanced policy specifics, `sbx save` vs `sbx template save`)
- **Breaking changes expected** — Between experimental and GA, significant changes are likely

**This is the single largest risk.** Building a production system on an experimental foundation means absorbing the risk of Docker changing or removing the feature.

### 7.10 Platform Limitations (MEDIUM)

- **Docker Desktop NOT required** — `sbx` is a standalone CLI. Install via `brew install docker/tap/sbx` (macOS) or `winget install Docker.sbx` (Windows). Docker Desktop integration is "coming soon."
- **macOS and Windows documented; Linux KVM backend exists but no install docs** — The VMM has three hypervisor backends: Apple virtualization.framework, Windows Hyper-V Platform, and Linux KVM. The architecture blog (April 16, 2026) states: *"A developer on a MacBook gets the same isolation guarantees and startup performance as a developer on a Linux workstation."* However, no Linux install command has been published.
- **Linux users currently excluded** — Foundry-sandbox currently runs on any Docker Engine host including Linux servers. Linux KVM support appears architecturally ready but is not yet documented for end users.
- **File sync limitations** — Bidirectional sync may have edge cases with large repos, binary files, or concurrent modifications

---

## 8. Gaps That Must Be Filled

### 8.1 Must-Have Gaps (block the rearchitecture)

| # | Gap | Effort | Approach |
|---|-----|--------|----------|
| G1 | Git operation mediation | Medium | Git API server + wrapper injection via `sbx exec` |
| G2 | Protected branch enforcement | Low | Runs in git API server (existing code) |
| G3 | Push file restrictions | Low | Runs in git API server (existing code) |
| G4 | Custom binary injection | Medium | `sbx exec -u root` to install wrapper; or embed in custom template |
| G5 | Git wrapper persistence | Medium | Build into custom template via `sbx template save`, or re-inject after `sbx reset` |

### 8.2 Should-Have Gaps (important for feature parity)

| # | Gap | Effort | Approach |
|---|-----|--------|----------|
| G6 | API gateways with SSE streaming | Medium | Sidecar proxy with gateways |
| G7 | Per-container rate limiting | Low | In proxy (existing code) |
| G8 | Branch visibility isolation | Low | In git API server (existing code) |
| G9 | GitHub API blocklist (merges, releases) | Low | In policy engine (existing code) |
| G10 | DNS-level filtering | Medium | In proxy (existing code) — may not be possible with Docker's network stack |
| G11 | SSH git protocol support | Low | Configure all git operations to use HTTPS URLs |

### 8.3 Nice-to-Have Gaps (can defer)

| # | Gap | Effort | Approach |
|---|-----|--------|----------|
| G12 | User-defined API services | Low | YAML config + proxy |
| G13 | Git mode toggle (host/sandbox) | Medium | Rewrite to use `sbx exec`; file sync changes path semantics |
| G14 | Self-merge prevention | Low | In policy engine (existing code) |
| G15 | Credential redaction UX | Low | Shell wrapper |

### 8.4 Unknown — Needs Investigation

**Resolved questions** (11 of 21 answered):

| # | Answer |
|---|--------|
| U1 | Secrets: network-level proxy injection, never in VM (Docker security docs) |
| U2 | Custom binaries: no bind-mounts, file sync only, use `sbx exec -u root` |
| U3 | Entrypoint: no `--entrypoint` flag, use custom templates (`-t`) |
| U4 | Filesystem: microVM with private Docker daemon per sandbox, agent has root |
| U5 | Compose: no, sandboxes are standalone microVMs |
| U6 | Daemon: custom VMM with Apple HVF / Windows HVP / Linux KVM backends |
| U11 | Linux: KVM backend exists, architecture blog confirms support, no install docs |
| U14 | GA timeline: none announced, launched March 31, 2026 as experimental |
| U16 | Auth: no Docker Desktop license required for standalone; `sbx login` may be optional |
| U17 | `sbx save` is shorthand for `sbx template save`; `docker sandbox save` is separate |
| U18 | Interactive: full TUI dashboard with live cards, keyboard lifecycle, network governance |
| U19 | Balanced policy: intentionally unpublished, 5 categories, auditable via `sbx policy ls` |

**Resolved questions (Phase 1 research, 2026-04-18):**

| # | Answer | Source |
|---|--------|--------|
| U8 | **No API-level policies.** `sbx policy` is network-only (domain/IP allow/deny). No method/path/body enforcement. Foundry policy layer is needed. | docs.docker.com/ai/sandboxes/network-policies/, sbx CLI reference |
| U10 | **Proprietary license (Docker Inc.).** Individual standalone use is free (confirmed by launch blog). Team/enterprise controls require contacting sales — no published pricing. | github.com/docker/sbx-releases (LICENSE), docker.com/products/docker-sandboxes/ |
| U21 | **Linux install artifacts published** at github.com/docker/sbx-releases (.deb for Ubuntu, .rpm for Rocky Linux 8). BUT docs still say Linux gets **legacy container-based sandboxes**, NOT microVMs. KVM backend exists but is not yet activated. | github.com/docker/sbx-releases README, docs.docker.com/ai/sandboxes/ |

**Additional findings (Phase 1):**

| # | Finding | Impact |
|---|---------|--------|
| U22 | Docker Sandboxes commitment: 2 blog posts in 3 weeks, active GitHub issue responses, nightly builds. However, <3 weeks old and still Experimental. | Medium — active development but no GA commitment |
| U23 | **Breaking change reported:** `docker sandbox` (Desktop plugin, v0.12.0) diverged from standalone `sbx` (v0.24.1) with no migration path. Community forum: "Docker Sandbox COMPLETELY changed in a minor update." | High — version instability during experimental phase |
| U24 | **No git policy features** in any documentation, CLI reference, or roadmap. Policy system exclusively manages network access. | Low — Foundry's differentiation is secure |
| U25 | GitHub repo: `docker/sbx-releases` (releases only, no source code). 7 stable releases + nightly builds available. | Medium — no source access for auditing |

**Open questions (updated):**

| # | Question | Impact |
|---|----------|--------|
| U7 | Does `sbx` support user-defined service credential injection? | Medium — determines if custom providers work |
| U9 | Does `sbx` allow custom CA certificates inside the VM? | Low — only needed if MITM for niche providers |
| U12 | What happens to injected binaries after `sbx reset`? | Medium — affects git wrapper persistence strategy |
| U13 | Can file sync be configured or disabled for specific paths? | Medium — affects git wrapper installation approach |
| U15 | Does `sbx create` support `--branch auto` (only documented on `sbx run`)? | Low — affects workflow if `create` and `run` must be separate steps |
| U20 | Can `sbx exec --privileged` be restricted by policy? | High — determines if git wrapper is enforceable against a determined agent |
| U26 | When will Linux get microVM-based sandboxes (not just legacy containers)? | High — current Linux support is container-based only, not hypervisor-isolated |
| U27 | Will `docker sandbox` and `sbx` converge, or remain two separate systems? | Medium — affects which CLI surface to target for migration |

---

## 9. Alternative Approaches

### 9.1 Option A: Full Rearchitecture (Conditional Recommendation)

Replace all Docker orchestration and the entire unified-proxy with `sbx` calls. Keep only the git safety layer (git API server, branch isolation, push restrictions). Delete ~72% of the codebase.

**When to choose:** Docker `sbx` credential isolation meets security requirements, git wrapper injection via `sbx exec` works reliably, experimental status is acceptable for your use case, and Linux support is not immediately required (KVM backend exists but no install docs).

**Risk:** Dependency on Docker's proxy depth and experimental status. If Docker's credential injection is less granular than needed, foundry may need to add back policy enforcement. If Docker discontinues or significantly changes `sbx`, the rearchitecture effort is wasted.

### 9.2 Option B: Thin Wrapper — `cast` as a CLI Skin Over `sbx`

Keep the `cast` CLI as a thin wrapper that translates foundry concepts to `sbx` commands:
- `cast new` → `sbx create` + `sbx secret set` + git safety setup
- `cast destroy` → `sbx rm` + git safety teardown
- `cast attach` → `sbx run` (reconnect)

**When to choose:** Want to preserve the `cast` brand and UX while offloading all infrastructure to Docker.

**Risk:** Users may prefer `sbx` directly if `cast` adds little value.

### 9.3 Option C: Git Safety Plugin — Focus on the One Missing Piece

Abandon the CLI entirely. Build foundry's git safety as a standalone tool that works with any `sbx` sandbox:
- `foundry-git-safety enable <sandbox-name>` — installs wrapper via `sbx exec`, starts git API
- `foundry-git-safety disable <sandbox-name>` — removes wrapper
- Configuration via `foundry.yaml` in the workspace

**When to choose:** Docker's `sbx` handles everything else well and foundry wants to focus on its unique differentiator.

**Risk:** Smaller scope but also smaller moat. Docker could add git safety features natively. Git wrapper is fragile (agent can remove it, resets destroy it).

### 9.4 Option D: Docker `sbx` Extension/Plugin

If Docker offers a plugin mechanism, build the git safety layer as an official extension:
- Auto-injects git wrapper on sandbox creation
- Provides `sbx git-policy` commands for configuration
- Integrates with Docker Dashboard

**When to choose:** Docker offers an extension API. Best outcome for ecosystem alignment.

**Risk:** May not exist. Would require partnership with Docker.

### 9.5 Option E: Wait and Watch (Recommended Short-Term)

Given Docker Sandboxes' experimental status and platform limitations (macOS/Windows only, no Linux), maintain the current architecture and monitor Docker's GA timeline. Begin extracting the git safety layer as a standalone module that could be adapted to `sbx` later.

**When to choose:** Production stability matters more than code reduction. Linux support is required. Want to avoid building on an experimental foundation.

**Risk:** May miss the window for ecosystem alignment if Docker moves quickly.

---

## 10. Recommendation

### Recommended Approach: Option E (Wait and Watch) with Option C Preparation

Given the experimental status, platform limitations, and git wrapper injection challenges, the recommended path is:

1. **Short-term:** Maintain current architecture. Monitor Docker Sandboxes GA timeline and feature development.
2. **Medium-term:** Extract git safety layer as a standalone module, decoupled from the proxy infrastructure.
3. **Long-term:** When Docker Sandboxes reaches GA with Linux support, migrate to Option A or C.

### Phase 1: Monitor and Validate (Ongoing)

1. Track Docker Sandboxes releases and GA timeline
2. Test `sbx` credential isolation — verify `env | grep -i anthropic` returns nothing inside the VM
3. Test git wrapper injection via `sbx exec -u root`
4. Test `sbx reset` behavior with injected binaries
5. Verify Linux support plans
6. Review licensing terms when available

### Phase 2: Extract Git Safety Layer (2-3 weeks, can start now)

Extract and decouple the git safety components from the proxy:
1. Git API server as a standalone service (no proxy dependency)
2. Git wrapper that can be installed via `sbx exec` or bind-mount
3. Branch isolation and push restrictions
4. Configuration via workspace-level `foundry.yaml`

### Phase 3: Conditional Migration (When Docker Sandboxes GA)

If Docker Sandboxes reaches GA with acceptable terms:
1. Migrate `cast` as thin wrapper over `sbx`
2. Replace proxy with Docker's built-in credential injection
3. Use extracted git safety layer as the only additive component
4. Maintain backward compatibility during transition

### What NOT to do

1. Don't keep the unified-proxy running alongside Docker's `sbx` — that would duplicate credential injection and add complexity without value.
2. Don't build on experimental software for production use without a fallback plan.
3. Don't assume Docker's proxy depth is sufficient without testing niche providers.
4. Don't abandon Linux support without understanding the user base impact.

---

## 11. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Docker Sandboxes remains experimental indefinitely | Medium | High | Maintain current architecture; extract git safety as standalone |
| Docker proxy depth insufficient for some providers | Medium | Medium | Keep user-defined service support; request Docker add extensibility |
| Git wrapper can't be reliably injected | Medium | High | Use `sbx exec` as root; build into custom template; investigate file sync hooks |
| Agent removes injected git wrapper (`sbx exec --privileged` available) | High | High | Build wrapper into template; monitor and re-inject; investigate if `--privileged` can be restricted (U20) |
| Docker deprecates `sbx` | Low | Critical | Keep git safety as standalone tool; maintain current architecture as fallback |
| Docker licensing blocks commercial use | Low | Critical | Legal review before adoption; standalone use is currently free |
| Migration breaks existing users | High | Medium | Compatibility shim, phased rollout |
| Docker adds git safety features natively | Medium | Medium | Focus on policy depth beyond what Docker ships |
| Performance regression (file sync vs bind-mount) | Medium | Medium | Benchmark early in prototype |
| Linux users excluded (KVM backend exists, no install docs) | Medium | Medium | Wait for Linux install docs; maintain dual architecture if needed |
| `sbx reset` destroys entire installation (all sandboxes, policies, secrets, daemon) | High | Medium | Build wrapper into template; re-inject after reset; use `--preserve-secrets` |
| Breaking changes during experimental phase (launched March 31, 2026) | High | Medium | Pin to specific `sbx` version; extensive version testing |
| Docker account requirements unclear for standalone use | Medium | Low | Verify auth requirements; document for users |
| `sbx policy reset` stops running sandboxes | Medium | Medium | Avoid policy resets during active sessions; batch policy changes |
| `balanced` policy allowlist is opaque and unauditable | Medium | Medium | Test with `sbx policy ls` on actual installation; maintain explicit allow/deny rules on top |

---

## 12. Conclusion

The discovery that Docker's `sbx` already provides network-level credential injection (confirmed by official Docker security documentation) fundamentally changes the rearchitecture calculus. The proxy's credential infrastructure — ~6,300 lines across 21 files — exists to solve a problem Docker now solves natively. The real question is no longer "can we build on sbx?" but "when should we build on sbx?"

The answer is **git safety**: operation-level mediation, protected branch enforcement, branch visibility isolation, push file restrictions, and the git wrapper authentication layer. These represent ~6,870 lines of code (~22% of the codebase) across 12 files, plus ~1,700 lines of supporting CLI/config code, and are the genuine differentiator that Docker's `sbx` doesn't address.

However, several factors argue for caution rather than immediate migration:

1. **Experimental status** — Docker Sandboxes is explicitly experimental with no stability guarantees. It launched March 31, 2026 — less than 3 weeks old as of this writing. No GA timeline has been announced.
2. **Platform in flux** — Standalone CLI (no Docker Desktop required) with macOS and Windows support. Linux KVM backend exists in the VMM but no install docs published yet. Foundry-sandbox currently supports any Docker Engine host including Linux servers.
3. **File sync architecture** — Git wrapper injection is more fragile with file sync than with bind-mounts. The agent has full sudo and can remove the wrapper (`sbx exec --privileged` is available).
4. **Non-HTTP protocol blocking** — SSH git operations are blocked; foundry-sandbox supports all protocols.
5. **No arbitrary volume mounts** — Only workspace paths supported, limiting flexibility.
6. **Opaque defaults** — The `balanced` policy's allowlist is intentionally unpublished (only auditable via `sbx policy ls` on a live installation). This reduces transparency compared to foundry-sandbox's inspectable allowlist.

A rearchitecture that adopts Docker's `sbx` for everything except git safety would reduce the codebase by 72%, eliminate maintenance of the proxy/middleware stack, and gain features foundry-sandbox doesn't have (templates, TUI dashboard, diagnostics, port publishing, more agents, resource limits, hypervisor-level isolation with private Docker daemons). But it should wait for Docker Sandboxes to reach GA with Linux support.

**The recommended path is Option E (Wait and Watch) with Option C preparation:** Extract the git safety layer as a standalone module now, maintain the current architecture, and migrate when Docker Sandboxes is production-ready with published Linux install instructions.
