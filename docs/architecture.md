# Architecture

This document explains the technical design of Foundry Sandbox: how components fit together, why certain decisions were made, and how data flows through the system.

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                       HOST SYSTEM                           │
│                                                             │
│  sandbox.sh ──► lib/*.sh ──► commands/*.sh                  │
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
│  │  │  • Credential isolation    (gateway)          │   │   │
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
- **Removed** - All resources cleaned up

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

Even if an AI bypasses shell overrides with `/bin/rm -rf /`, the operation fails because the filesystem is immutable.

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
  • Configure DNS → gateway                 │
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
  • Copy proxy stubs (gateway mode)
  • Apply gateway gitconfig (gateway mode)
  • Trust mitmproxy CA (if mounted)
      │
      ▼
Execute passed command (default: /bin/bash)
```

### Git Path Translation

Worktrees reference the bare repo by absolute path. Since host and container have different paths, the **host script** (`lib/container_config.sh`) fixes these paths after copying the repos directory—not the container entrypoint.

## Code Organization

```
foundry-sandbox/
├── sandbox.sh              # Main entry point
├── Dockerfile              # Container image definition
├── docker-compose.yml      # Container runtime config
├── entrypoint.sh           # Container startup script (user)
├── entrypoint-root.sh      # Root wrapper (credential isolation)
├── install.sh              # Installation script
├── completion.bash         # Bash tab completion
│
├── lib/                    # Library modules
│   ├── constants.sh        # Global variables
│   ├── utils.sh            # Helper functions
│   ├── git.sh              # Git operations
│   ├── git_worktree.sh     # Worktree management
│   ├── docker.sh           # Docker/compose helpers
│   ├── state.sh            # Sandbox state management
│   ├── gateway.sh          # Gateway/credential isolation
│   ├── container_config.sh # Container setup (git path fixes)
│   └── ...                 # Other modules
│
├── commands/               # Command implementations
│   ├── new.sh              # cast new
│   ├── attach.sh           # cast attach
│   ├── list.sh             # cast list
│   ├── destroy.sh          # cast destroy
│   └── ...                 # Other commands
│
└── safety/                         # Security controls
    ├── sudoers-allowlist           # Sudo command restrictions
    ├── network-firewall.sh         # iptables rules
    ├── network-mode                # Network mode switcher
    ├── gateway-credential-helper   # Git credential helper (gateway)
    ├── gateway-gitconfig           # Git URL rewriting (gateway)
    ├── shell-overrides.sh          # UX warnings (not security)
    ├── credential-redaction.sh     # Output masking (not security)
    └── operator-approve            # TTY-based human approval
```

## Component Interactions

```
User runs: cast new owner/repo
              │
              ▼
┌─────────────────────────────────┐
│ sandbox.sh                      │
│  - source lib/*.sh              │
│  - export_docker_env            │
│  - validate_environment         │
│  - dispatch to commands/new.sh  │
└─────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ commands/new.sh                 │
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
│  - entrypoint-root.sh (gateway) │
│  - entrypoint.sh runs           │
└─────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ commands/new.sh (continued)     │
│  - setup gateway session        │
│    (if credential isolation)    │
│  - copy configs to container    │
│  - install workspace perms      │
│  - apply network restrictions   │ ← after container starts
│  - attach via tmux              │
└─────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ Docker Container (ready)        │
│  - network restrictions active  │
│  - user shell ready             │
└─────────────────────────────────┘
```

## Next Steps

- [Security Overview](security/index.md) - Security architecture quick reference
- [Sandbox Threats](security/sandbox-threats.md) - What we protect against
- [Security Architecture](security/security-architecture.md) - Defense in depth details
- [Commands](usage/commands.md) - Full command reference
