# Architecture

This document explains the technical design of Foundry Sandbox: how components fit together, why certain decisions were made, and how data flows through the system.

## Contents

- [System Overview](#system-overview)
- [Sandbox Lifecycle](#sandbox-lifecycle)
- [Git Worktree Strategy](#git-worktree-strategy)
- [Docker Container Design](#docker-container-design)
- [State Management](#state-management)
- [Entrypoint Flow](#entrypoint-flow)
- [Component Interactions](#component-interactions)
- [Unified Proxy Architecture](#unified-proxy-architecture)
- [Service Dependencies](#service-dependencies)

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                       HOST SYSTEM                           │
│                                                             │
│  cast ──► foundry_sandbox.cli ──► commands/*.py              │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │               DOCKER CONTAINER                       │   │
│  │                                                      │   │
│  │  ┌──────────────────────────────────────────────┐   │   │
│  │  │         SECURITY CONTROLS                     │   │   │
│  │  │   (see docs/security/security-model)            │   │   │
│  │  │                                               │   │   │
│  │  │  • Read-only filesystem    (Docker)           │   │   │
│  │  │  • Network isolation       (Docker/dns/ipt)   │   │   │
│  │  │  • Credential isolation    (unified-proxy)    │   │   │
│  │  │  • Branch isolation        (git_operations)   │   │   │
│  │  │  • Git safety              (git_policies)     │   │   │
│  │  └──────────────────────────────────────────────┘   │   │
│  │                                                      │   │
│  │  /workspace ◄─── volume mount (git worktree)        │   │
│  │  /home/ubuntu ◄─ tmpfs (ephemeral; ~/.claude persisted)│   │
│  │  /tmp, /var ◄─── tmpfs (ephemeral)                  │   │
│  │  / (root) ◄────── read-only filesystem              │   │
│  │                                                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ~/.sandboxes/                                              │
│    ├── repos/      (bare git repositories)                  │
│    ├── worktrees/  (checked-out code per sandbox)           │
│    └── claude-config/ (AI tool configs per sandbox)         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Sandbox Lifecycle

```
cast new repo        cast attach       cast stop         cast destroy
    │                  │               │                │
    ▼                  ▼               ▼                ▼
┌────────┐       ┌────────┐      ┌────────┐       ┌────────┐
│ Clone  │──────▶│Running │◀────▶│Stopped │──────▶│Removed │
│ Setup  │       │        │      │        │       │        │
└────────┘       └────────┘      └────────┘       └────────┘
                     │               ▲
                     │               │
                     └───────────────┘
                        cast start
```

**States:**
- **Clone/Setup** - Repository cloned, worktree created, container started
- **Running** - Container active, tmux session available
- **Stopped** - Container stopped, worktree preserved on disk
- **Removed** - All resources cleaned up (including sandbox branch cleanup from bare repo)

## Git Worktree Strategy

Instead of cloning a full repository for each sandbox, we use git's worktree feature:

```
~/.sandboxes/
├── repos/
│   └── github.com/
│       └── owner/
│           └── repo.git/          # Bare repository (shared)
│               ├── HEAD
│               ├── objects/       # All git objects
│               └── worktrees/     # Worktree metadata
│
└── worktrees/
    ├── repo-sandbox-20240115-1430/   # Sandbox 1
    │   ├── .git                      # Points to bare repo
    │   └── (working files)
    │
    └── repo-feature-branch/          # Sandbox 2
        ├── .git                      # Points to same bare repo
        └── (working files)
```

**Benefits:**
- **Disk efficiency** - Git objects stored once, shared across sandboxes
- **Fast creation** - No network clone for subsequent sandboxes
- **Branch isolation** - Each sandbox has its own branch/working directory
- **Easy cleanup** - Delete worktree, bare repo stays for other sandboxes

## Docker Container Design

### Read-Only Root Filesystem

The container runs with `read_only: true` in docker-compose.yml. This is the primary security boundary:

```yaml
services:
  dev:
    read_only: true
```

Even if an AI runs `/bin/rm -rf /`, the operation fails because the filesystem is immutable.

### Tmpfs Mounts (Ephemeral Storage)

Writable areas are RAM-backed and cleared on container stop:

```yaml
tmpfs:
  - /tmp:mode=1777,size=512m
  - /var/tmp:mode=1777,size=256m
  - /run:mode=755,size=64m
  - /var/cache/apt:mode=755,size=256m
  - /var/lib/apt/lists:mode=755,size=128m
  - /home/ubuntu:mode=755,uid=1000,gid=1000,size=2g
```

**Why tmpfs for /home?**
- Most AI tool configs don't persist across restarts (except `~/.claude`, which is persisted per sandbox)
- Prevents accumulation of cached data
- Forces explicit config management via host mounts

### Volume Mounts

```yaml
volumes:
  - ${WORKSPACE_PATH}:/workspace    # Git worktree (read-write)
  - ${HOME}/.foundry-mcp:/home/ubuntu/.foundry-mcp  # Metrics (persistent)
```

Only the workspace and specific config directories are persisted to the host.

## State Management

Each sandbox has associated state stored on the host:

```
~/.sandboxes/
├── worktrees/<name>/           # Git worktree (the code)
└── claude-config/<name>/       # Sandbox config + overrides
    ├── claude/                 # Persisted ~/.claude
    ├── docker-compose.override.yml
    └── metadata.json           # Sandbox metadata (repo, branch, mounts)
```

### Metadata File

Created by `cast new`, records sandbox configuration:

```json
{
  "repo_url": "https://github.com/owner/repo",
  "branch": "feature-branch",
  "from_branch": "main",
  "network_mode": "limited",
  "sync_ssh": 0,
  "ssh_mode": "disabled",
  "allow_pr": false,
  "mounts": ["/data:/data"],
  "copies": []
}
```

## Entrypoint Flow

Container startup uses two entrypoints depending on mode:

```
Container Start
      │
      ├─────────────────────────────────────┐
      │ (credential isolation enabled)      │ (standard mode)
      ▼                                     │
entrypoint-root.sh (as root)                │
  • Set up DNS firewall (iptables)          │
  • Overlay .git with tmpfs                 │
  • Drop privileges (gosu)                  │
      │                                     │
      ▼                                     ▼
entrypoint.sh (as ubuntu) ◄─────────────────┘
  • Create /home directories (tmpfs is empty)
  • Fix ownership of root-created dirs
  • Set up npm prefix for local installs
  • Configure Claude onboarding
  • Copy proxy stubs (credential isolation mode)
  • Apply proxy gitconfig (credential isolation mode)
  • Trust mitmproxy CA (if mounted)
      │
      ▼
Execute passed command (default: /bin/bash)
```

**Note:** DNS configuration (`/etc/resolv.conf`, `/etc/hosts`) is handled at compose level via `dns:` and `extra_hosts:` directives, not by `entrypoint-root.sh`. Docker 29+ makes these files read-only when `read_only: true` is set.

### Git Path Translation

Worktrees reference the bare repo by absolute path. Since host and container have different paths, the **host script** (`foundry_sandbox/container_setup.py`) fixes these paths after copying the repos directory—not the container entrypoint.

For the full directory tree with file-level descriptions, see [Code Organization](development/contributing.md#code-organization) in the contributing guide.

## Component Interactions

```
User runs: cast new owner/repo
              │
              ▼
┌─────────────────────────────────┐
│ cast → foundry_sandbox.cli      │
│  - Click CLI dispatch           │
│  - validate_environment         │
│  - dispatch to commands/new.py  │
└─────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ commands/new.py                 │
│  - validate repo URL, API keys  │
│  - ensure bare repo exists      │
│  - create worktree              │
│  - set up Claude config         │
│  - prepopulate foundry skills   │
│  - docker compose up            │
└─────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ Docker Container (starting)     │
│  - entrypoint-root.sh (unified-proxy) │
│  - entrypoint.sh runs           │
└─────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ commands/new.py (continued)     │
│  - setup unified-proxy session  │
│    (if credential isolation)    │
│  - copy configs to container    │
│  - install workspace perms      │
│  - apply network restrictions   │ ← after container starts
│  - attach via tmux              │
│  - rollback on failure          │
└─────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ Docker Container (ready)        │
│  - network restrictions active  │
│  - user shell ready             │
└─────────────────────────────────┘
```

## Unified Proxy Architecture

The unified-proxy handles credential isolation, API proxying, and security policy enforcement for sandboxed containers. It runs three subsystems: dedicated API gateways for high-traffic providers, a Squid forward proxy for domain allowlisting, and a conditional mitmproxy instance for providers that require TLS interception.

```
┌──────────────────────────────────────────────────────────────────┐
│                        UNIFIED PROXY                              │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │              API GATEWAYS (aiohttp)                          │ │
│  │                                                              │ │
│  │  :9848  Anthropic gateway  ──► api.anthropic.com (HTTPS)     │ │
│  │  :9849  OpenAI gateway     ──► api.openai.com    (HTTPS)     │ │
│  │  :9850  GitHub gateway     ──► api.github.com    (HTTPS)     │ │
│  │  :9851  Gemini gateway     ──► generativelanguage.. (HTTPS)  │ │
│  │  :9852  ChatGPT gateway    ──► chatgpt.com  (HTTP)  │ │
│  │  :443   ChatGPT gateway    ──► chatgpt.com  (TLS)   │ │
│  │                                                              │ │
│  │  Shared infrastructure:                                      │ │
│  │    gateway_base.py         — app factory, forwarding, errors │ │
│  │    gateway_middleware.py    — identity, metrics, circuit      │ │
│  │                              breaker, rate limiter            │ │
│  │    security_policies.py    — GitHub policy enforcement        │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │         SQUID FORWARD PROXY (:8080)                          │ │
│  │                                                              │ │
│  │  Allowed domains   → direct HTTPS tunnel (SNI, no decrypt)  │ │
│  │  MITM domains      → cache_peer to mitmproxy (:8081)        │ │
│  │  IP literals       → deny (all encodings blocked)           │ │
│  │  Unknown domains   → deny                                   │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │     MITMPROXY (:8081, conditional)                           │ │
│  │                                                              │ │
│  │  ┌────────────────────────────────────────────────────────┐  │ │
│  │  │              Addon Chain                               │  │ │
│  │  │                                                        │  │ │
│  │  │  container_identity → policy_engine → dns_filter       │  │ │
│  │  │  → credential_injector → git_proxy → rate_limiter      │  │ │
│  │  │  → circuit_breaker → metrics                           │  │ │
│  │  └────────────────────────────────────────────────────────┘  │ │
│  │                                                              │ │
│  │  Active only when MITM-required provider credentials are     │ │
│  │  configured (Gemini, Tavily, Semantic Scholar, Perplexity,   │ │
│  │  Zhipu) or DNS filtering is enabled.                         │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────────┐   │
│  │ Internal API│  │  Container  │  │  Git API (:8083)       │   │
│  │ (Flask)     │  │  Registry   │  │  HMAC-authenticated    │   │
│  │ (Unix sock) │──│  (SQLite)   │──│  git command execution │   │
│  └─────────────┘  └─────────────┘  └────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### API Gateways

Sandboxes connect to API gateways via provider-specific `*_BASE_URL` environment variables. Gateways accept plaintext HTTP on the internal Docker network, validate container identity, inject real credentials, and forward to the upstream provider over HTTPS. Responses are streamed back chunk-by-chunk without buffering. The GitHub gateway additionally enforces security policies — see [Git Safety](security/security-model.md#git-safety).

For the gateway architecture decision, routing table, shared infrastructure details, and rollback procedures, see [ADR-009](adr/009-api-gateways.md).

### Squid Forward Proxy

Squid handles all non-gateway HTTPS traffic on port 8080, performing SNI-based domain filtering against `config/allowlist.yaml`. Allowed domains are tunnelled without TLS decryption; MITM-required domains are forwarded to mitmproxy; IP literals and unknown domains are denied.

### Mitmproxy (Conditional)

mitmproxy runs on port 8081 when MITM-required provider credentials are configured or DNS filtering is enabled. It handles TLS interception for providers that lack `*_BASE_URL` env var support. When no MITM providers are configured, no CA certificate is generated.

### Container Registration

Containers register with the proxy via the internal API:

```
POST /internal/containers
{
  "container_id": "sandbox-abc123",
  "ip_address": "172.17.0.2",
  "ttl_seconds": 0,
  "metadata": {
    "sandbox_name": "my-project",
    "repo": "owner/repo",
    "sandbox_branch": "feature-branch",
    "from_branch": "main",
    "allow_pr": false
  }
}
```

Registrations persist in SQLite. TTL-based expiration is disabled by default (`ttl_seconds: 0`); registrations are removed explicitly on sandbox destroy.

### Git API Server (Shadow Mode)

In credential isolation mode, the `.git` directory is hidden from sandboxes (bind-mounted to `/dev/null`). All git operations are proxied through a git API server on the unified-proxy container:

```
┌─────────────────────┐          ┌──────────────────────────────┐
│   SANDBOX CONTAINER │          │       UNIFIED PROXY          │
│                     │          │                              │
│  git push origin    │          │   ┌───────────────────────┐  │
│       │             │  HTTP    │   │   Git API Server      │  │
│       ▼             │  POST    │   │   (port 8083)         │  │
│  /usr/local/bin/git ├─────────►│   │                       │  │
│  (git-wrapper.sh)   │          │   │  • HMAC-SHA256 auth   │  │
│                     │          │   │  • Policy enforcement  │  │
│  • Intercepts git   │          │   │  • Executes real git   │  │
│  • Builds JSON body │          │   │  • Returns JSON result │  │
│  • Signs with HMAC  │          │   └───────────────────────┘  │
│                     │          │                              │
│  .git → /dev/null   │          │  /git-workspace (bind mount) │
│  (hidden)           │          │  /home/ubuntu/.sandboxes/    │
│                     │          │    repos/ (bare repos)       │
└─────────────────────┘          └──────────────────────────────┘
```

**How it works:**

1. `stubs/git-wrapper.sh` is bind-mounted at `/usr/local/bin/git`, taking precedence over `/usr/bin/git`
2. For commands under `/workspace`, the wrapper serializes arguments as JSON and sends an HMAC-signed HTTP request to the git API (port 8083)
3. For commands outside `/workspace`, the wrapper falls through to the real `/usr/bin/git`
4. Each sandbox has a unique HMAC secret (provisioned at creation time) stored in a shared Docker volume
5. The git API authenticates requests, applies policy checks (force-push blocking, branch deletion blocking, repo authorization), validates branch isolation via `branch_isolation.py`, then executes the real git command against the bare repository
6. `git_operations.py` uses `fcntl.flock` to serialize concurrent fetch operations per bare repo, preventing corruption from parallel fetches

## Service Dependencies

```
unified-proxy ───────> dev (sandbox)
```

The unified proxy must be healthy before the sandbox starts:

```yaml
depends_on:
  unified-proxy:
    condition: service_healthy
```

The healthcheck verifies the internal API is responsive via Unix socket:

```yaml
healthcheck:
  test: ["CMD", "curl", "-sf", "--unix-socket", "/var/run/proxy/internal.sock", "http://localhost/internal/health"]
  interval: 5s
  timeout: 5s
  retries: 5
  start_period: 10s
```

## See Also

- [Security Model](security/security-model.md) — Threats, defenses, and hardening
- [Commands](usage/commands.md) — Full command reference
