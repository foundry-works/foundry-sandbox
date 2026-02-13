# Architecture

This document explains the technical design of Foundry Sandbox: how components fit together, why certain decisions were made, and how data flows through the system.

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
│  │  │   (see docs/security/security-architecture)   │   │   │
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
  • Configure DNS → unified-proxy                 │
  • Add internal services to /etc/hosts     │
  • Set up DNS firewall (iptables)          │
  • Mask /proc/kcore                         │
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

### Git Path Translation

Worktrees reference the bare repo by absolute path. Since host and container have different paths, the **host script** (`foundry_sandbox/container_setup.py`) fixes these paths after copying the repos directory—not the container entrypoint.

## Code Organization

```
foundry-sandbox/
├── Dockerfile              # Container image definition
├── docker-compose.yml      # Container runtime config
├── entrypoint.sh           # Container startup script (user)
├── entrypoint-root.sh      # Root wrapper (credential isolation)
├── install.sh              # Installation script
├── completion.bash         # Bash tab completion
├── pyproject.toml          # Python package definition (entry point: cast)
│
├── foundry_sandbox/        # Python package (orchestration layer)
│   ├── cli.py              # Click CLI group with alias resolution
│   ├── _bridge.py          # JSON envelope dispatcher for shell→Python calls
│   ├── legacy_bridge.py    # Compatibility adapter for _bridge_* commands
│   ├── constants.py        # Configuration defaults (replaces lib/constants.sh)
│   ├── config.py           # JSON config I/O utilities
│   ├── models.py           # Pydantic data models
│   ├── paths.py            # Path resolution (SandboxPaths)
│   ├── utils.py            # Logging/formatting helpers
│   ├── docker.py           # Docker/compose operations
│   ├── git.py              # Git operations with retry
│   ├── git_worktree.py     # Worktree management
│   ├── state.py            # Metadata persistence (JSON, atomic writes)
│   ├── network.py          # Docker network configuration
│   ├── proxy.py            # Unified proxy registration
│   ├── validate.py         # Input validation
│   ├── credential_setup.py # Container credential provisioning
│   ├── container_io.py     # Container I/O primitives
│   ├── container_setup.py  # Container setup orchestration
│   ├── tool_configs.py     # Tool configuration (Claude, Codex, etc.)
│   ├── foundry_plugin.py   # Foundry MCP plugin setup
│   ├── permissions.py      # Workspace permission rules
│   └── commands/           # Click command implementations
│       ├── new.py          # cast new
│       ├── attach.py       # cast attach
│       ├── list_cmd.py     # cast list
│       ├── destroy.py      # cast destroy
│       └── ...             # Other commands
│
├── unified-proxy/              # Credential isolation proxy
│   ├── addons/                 # mitmproxy addons
│   │   ├── container_identity.py   # Container identification
│   │   ├── credential_injector.py  # API credential injection
│   │   ├── git_proxy.py            # Git protocol handling
│   │   ├── rate_limiter.py         # Rate limiting
│   │   ├── circuit_breaker.py      # Resilience
│   │   ├── policy_engine.py        # Access policies
│   │   ├── dns_filter.py           # DNS filtering
│   │   └── metrics.py              # Observability
│   ├── branch_isolation.py     # Cross-sandbox branch isolation validator
│   ├── git_operations.py       # Sandboxed git command execution (deny-by-default allowlist)
│   ├── git_policies.py         # Protected branch enforcement
│   ├── git_api.py              # Git API TCP server (port 8083)
│   ├── github-api-filter.py    # GitHub API endpoint security filter
│   ├── registry.py             # Container registry (SQLite)
│   ├── internal_api.py         # Flask API for registration
│   └── entrypoint.sh           # Proxy startup script
│
└── safety/                         # Security controls
    ├── sudoers-allowlist           # Sudo command restrictions
    ├── network-firewall.sh         # iptables rules
    ├── network-mode                # Network mode switcher
    ├── proxy-credential-helper     # Git credential helper (proxy)
    ├── proxy-gitconfig             # Git URL rewriting (proxy)
    ├── credential-redaction.sh     # Output masking (not security)
    └── operator-approve            # TTY-based human approval
```

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

The unified-proxy handles all credential isolation and API proxying for sandboxed containers:

```
┌─────────────────────────────────────────────────────────────────┐
│                        UNIFIED PROXY                             │
│                                                                 │
│  ┌─────────────┐    ┌─────────────────────────────────────┐    │
│  │  Internal   │    │           mitmproxy Core             │    │
│  │  API (Flask)│    │                                      │    │
│  │  /containers│    │  ┌─────────────────────────────────┐ │    │
│  │  (Unix sock)│    │  │          Addon Chain            │ │    │
│  └──────┬──────┘    │  │                                 │ │    │
│         │           │  │  container_identity (identify)  │ │    │
│         ▼           │  │  policy_engine (rules)          │ │    │
│  ┌─────────────┐    │  │  dns_filter (DNS allowlist)     │ │    │
│  │  Container  │    │  │  credential_injector (inject)   │ │    │
│  │  Registry   │────┼──│  git_proxy (rewrite URLs)       │ │    │
│  │  (SQLite)   │    │  │  rate_limiter (throttle)        │ │    │
│  └─────────────┘    │  │  circuit_breaker (resilience)   │ │    │
│                     │  │  metrics (observability)        │ │    │
│                     │  └─────────────────────────────────┘ │    │
│                     └─────────────────────────────────────┘    │
│                                                                 │
│  ┌─────────────┐                                                │
│  │ DNS Filter  │  Allowlist-based DNS filtering                 │
│  │ (mitmproxy) │  Returns NXDOMAIN for blocked domains          │
│  └─────────────┘                                                │
└─────────────────────────────────────────────────────────────────┘
```

### Addon Chain

Each request flows through the addon chain in order:

1. **container_identity** - Identifies container by source IP, attaches config to request
2. **policy_engine** - Enforces access policies (evaluated before credentials are injected)
3. **dns_filter** - Filters DNS queries against allowlist (conditional; only when DNS mode enabled)
4. **credential_injector** - Injects API credentials (Anthropic, GitHub, etc.)
5. **git_proxy** - Validates git operations, enforces repo authorization and push policies
6. **rate_limiter** - Per-container, per-upstream rate limiting
7. **circuit_breaker** - Protects against upstream failures
8. **metrics** - Records request/response metrics

Additionally, `github-api-filter.py` runs as a legacy addon loaded after the main chain, filtering dangerous GitHub API operations (repo deletion, secret access, branch protection changes) at the network layer.

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

## Next Steps

- [Security Overview](security/index.md) - Security architecture quick reference
- [Sandbox Threats](security/sandbox-threats.md) - What we protect against
- [Security Architecture](security/security-architecture.md) - Defense in depth details
- [Commands](usage/commands.md) - Full command reference
