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
│  │  │            SAFETY LAYERS                      │   │   │
│  │  │                                               │   │   │
│  │  │  Layer 1: Shell Overrides (UX warnings)      │   │   │
│  │  │  Layer 2: Credential Redaction (mask secrets)│   │   │
│  │  │  Layer 3: Operator Approval (human-in-loop)  │   │   │
│  │  │  Layer 4: Sudoers Allowlist (kernel-enforced)│   │   │
│  │  │  Layer 5: Network Isolation (iptables)       │   │   │
│  │  │  Layer 6: Read-only Root (Docker enforced)   │   │   │
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
  - /home/ubuntu:mode=755,uid=1000,gid=1000,size=1g
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

When a container starts, `entrypoint.sh` runs:

```
Container Start
      │
      ▼
Create /home directories (tmpfs is empty; ~/.claude is mounted)
      │
      ▼
Set up npm prefix for local installs
      │
      ▼
API keys from environment (docker-compose)
      │
      ▼
Fix git worktree paths (host → container)
      │
      ▼
Execute passed command (default: /bin/bash)
```

### Git Path Translation

Worktrees reference the bare repo by absolute path. Since host and container have different home directories (e.g., `/home/username` vs `/home/ubuntu`), the entrypoint fixes these paths at startup.

## Code Organization

```
foundry-sandbox/
├── sandbox.sh              # Main entry point
├── Dockerfile              # Container image definition
├── docker-compose.yml      # Container runtime config
├── entrypoint.sh           # Container startup script
├── completion.bash         # Bash tab completion
│
├── lib/                    # Library modules
│   ├── constants.sh        # Global variables
│   ├── utils.sh            # Helper functions
│   ├── git.sh              # Git operations
│   ├── git_worktree.sh     # Worktree management
│   ├── docker.sh           # Docker/compose helpers
│   ├── state.sh            # Sandbox state management
│   └── ...                 # Other modules
│
├── commands/               # Command implementations
│   ├── new.sh              # cast new
│   ├── attach.sh           # cast attach
│   ├── list.sh             # cast list
│   ├── destroy.sh          # cast destroy
│   └── ...                 # Other commands
│
└── safety/                     # Security guardrails
    ├── shell-overrides.sh      # Layer 1: Shell functions
    ├── credential-redaction.sh # Layer 2: Credential masking
    ├── operator-approve        # Layer 3: Human approval
    ├── sudoers-allowlist       # Layer 4: Sudo restrictions
    ├── network-firewall.sh     # Layer 5: Network isolation
    └── network-mode            # Layer 5: Mode switcher
```

## Component Interactions

```
User runs: cast new owner/repo
              │
              ▼
┌─────────────────────────────────┐
│ sandbox.sh                      │
│  - parse command                │
│  - source lib/*.sh              │
│  - dispatch to commands/new.sh  │
└─────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ commands/new.sh                 │
│  - validate repo URL            │
│  - ensure bare repo exists      │
│  - create worktree              │
│  - set up Claude config         │
│  - docker compose up            │
│  - copy configs to container    │
│  - attach via tmux              │
└─────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ Docker Container                │
│  - entrypoint.sh runs           │
│  - safety layers active         │
│  - user shell ready             │
└─────────────────────────────────┘
```

## Next Steps

- [Security: Threat Model](security/threat-model.md) - What we protect against
- [Security: Safety Layers](security/safety-layers.md) - Defense in depth details
- [Commands](usage/commands.md) - Full command reference
