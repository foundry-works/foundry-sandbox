# Architecture

This document explains the technical design of Foundry Sandbox: how components fit together, why certain decisions were made, and how data flows through the system.

## Contents

- [System Overview](#system-overview)
- [Sandbox Lifecycle](#sandbox-lifecycle)
- [Git Worktree Strategy](#git-worktree-strategy)
- [sbx Backend](#sbx-backend)
- [Git Safety Layer](#git-safety-layer)
- [Host State Layout](#host-state-layout)
- [Networking Model](#networking-model)
- [Component Interactions](#component-interactions)

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         HOST SYSTEM                              │
│                                                                  │
│  cast ──► foundry_sandbox.cli ──► commands/*.py                  │
│       │                                                          │
│       ├── sbx CLI (Docker Sandboxes runtime)                     │
│       │    └── creates/manages microVM sandboxes                 │
│       │                                                          │
│       └── foundry-git-safety (standalone service)                │
│            ├── Git API server (port 8083)                        │
│            ├── Deep policy sidecar (opt-in)                      │
│            └── Policy enforcement (branch, push, command)        │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   SBX MICROVM                             │   │
│  │                                                           │   │
│  │  ┌────────────────────────────────────────────────────┐  │   │
│  │  │         SECURITY CONTROLS                           │  │   │
│  │  │   (see docs/security/security-model.md)             │  │   │
│  │  │                                                     │  │   │
│  │  │  • MicroVM isolation      (sbx / Docker)           │  │   │
│  │  │  • Network policy          (sbx policy)             │  │   │
│  │  │  • Credential injection    (sbx secrets)            │  │   │
│  │  │  • Branch isolation        (foundry-git-safety)     │  │   │
│  │  │  • Git safety              (foundry-git-safety)     │  │   │
│  │  └────────────────────────────────────────────────────┘  │   │
│  │                                                           │   │
│  │  /workspace ◄─── file sync (git worktree on host)        │   │
│  │  /usr/local/bin/git ◄─── git wrapper (policy enforced)   │   │
│  │                                                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ~/.sandboxes/                                                   │
│    ├── repos/       (bare git repositories)                      │
│    ├── worktrees/   (checked-out code per sandbox)               │
│    └── claude-config/ (AI tool configs per sandbox)              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Sandbox Lifecycle

```
cast new repo        cast attach       cast stop         cast destroy
    │                  │               │                │
    ▼                  ▼               ▼                ▼
┌────────┐       ┌────────┐      ┌────────┐       ┌────────┐
│ Setup  │──────▶│Running │◀────▶│Stopped │──────▶│Removed │
│        │       │        │      │        │       │        │
└────────┘       └────────┘      └────────┘       └────────┘
                     │               ▲
                     │               │
                     └───────────────┘
                        cast start
```

**States:**
- **Setup** - Bare repo cloned, worktree created, `sbx create` provisions microVM, git wrapper injected
- **Running** - Sandbox active, `sbx exec` available for interactive use
- **Stopped** - Sandbox stopped via `sbx stop`, worktree preserved on host
- **Removed** - `sbx rm` removes sandbox, worktree and config cleaned up

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

## sbx Backend

The `sbx` CLI (Docker Sandboxes) manages microVM-based sandbox lifecycle. All sandbox operations go through the `foundry_sandbox.sbx` module, which wraps `sbx` subprocess calls.

### Supported Operations

| Function | sbx Command | Purpose |
|----------|-------------|---------|
| `sbx_create` | `sbx create --name N AGENT PATH` | Create microVM, mount host worktree |
| `sbx_run` | `sbx run NAME` | Start a stopped sandbox |
| `sbx_stop` | `sbx stop NAME` | Stop a running sandbox |
| `sbx_rm` | `sbx rm NAME` | Remove sandbox entirely |
| `sbx_ls` | `sbx ls --json` | List sandboxes (JSON output) |
| `sbx_exec` | `sbx exec NAME -- CMD` | Execute command inside sandbox |
| `sbx_exec_streaming` | `sbx exec NAME -- CMD` | Interactive I/O (Popen) |
| `sbx_secret_set` | `sbx secret set -g SERVICE` | Store API key on host |
| `sbx_policy_set_default` | `sbx policy set-default PROFILE` | Set network policy (balanced/allow-all/deny-all) |
| `sbx_policy_allow` | `sbx policy allow network SPEC` | Allow domain/CIDR |
| `sbx_policy_deny` | `sbx policy deny network SPEC` | Deny domain/CIDR |
| `sbx_template_save` | `sbx template save NAME TAG` | Save sandbox as reusable template |
| `sbx_template_load` | `sbx template load TAG` | Load a saved template |
| `sbx_diagnose` | `sbx diagnose` | Run diagnostics |

### Agent Types

The `--agent` flag selects which AI agent runs inside the sandbox:

- `claude` (default) - Claude Code (Anthropic)
- `codex` - OpenAI Codex
- `copilot` - GitHub Copilot
- `gemini` - Google Gemini
- `kiro` - Amazon Kiro
- `opencode` - OpenCode
- `shell` - Plain shell (no AI agent)

### MicroVM Isolation

Each sandbox runs in its own microVM with a separate kernel. This provides stronger isolation than containers:

- **Separate kernel** - Sandbox kernel differs from host (e.g., 6.12.44 inside vs 6.17.8 on host)
- **No shared filesystem** - Only the synced workspace directory is accessible
- **Network isolation** - All outbound traffic routed through sbx's HTTP proxy (`gateway.docker.internal:3128`)
- **Credential injection** - API keys are injected into HTTP headers by sbx's host-side proxy; values never enter the VM

### Credential Management

Credentials are stored on the host via `sbx secret set -g` and injected at runtime:

```
Host: sbx secret set -g anthropic  ← stores ANTHROPIC_API_KEY on host
Sandbox: agent makes API call      ← sbx proxy injects key into HTTP header
```

The sandbox environment never contains real API keys. The `GH_TOKEN` variable is set to `proxy-managed` (a placeholder).

## Git Safety Layer

The git safety layer (`foundry-git-safety`) runs as a standalone host-side service. It intercepts all git operations from sandboxes, applies policy checks, then executes the real git binary on the host.

### Architecture

```
┌─────────────────────────────┐     ┌───────────────────────────────────┐
│       SBX MICROVM            │     │            HOST                    │
│                              │     │                                    │
│  Agent runs: git status      │     │  foundry-git-safety                │
│       │                      │     │  ┌──────────────────────────────┐ │
│       ▼                      │     │  │   Git API Server (port 8083) │ │
│  /usr/local/bin/git          │     │  │                               │ │
│  (git-wrapper-sbx.sh)        │     │  │  1. HMAC-SHA256 auth          │ │
│       │                      │     │  │  2. Command allowlist check    │ │
│       │  HTTP POST           │     │  │  3. Branch isolation filter    │ │
│       │  HMAC-signed         │     │  │  4. Protected branch check     │ │
│       │  via proxy ──────────┼────►│  │  5. File restriction check     │ │
│       │                      │     │  │  6. Rate limit check           │ │
│       │                      │     │  │                               │ │
│       │                      │     │  │  → Execute real git on host    │ │
│       │  ◄───────────────────┼─────│  │  → Return JSON result          │ │
│       │                      │     │  └──────────────────────────────┘ │
│       ▼                      │     │                                    │
│  Prints output               │     │  ~/.sandboxes/                     │
│                              │     │    repos/ (bare repos)             │
└─────────────────────────────┘     └───────────────────────────────────┘
```

### Request Flow

1. Agent runs a git command inside the sandbox
2. `/usr/local/bin/git` (wrapper script) intercepts it
3. Wrapper serializes arguments as JSON, computes HMAC-SHA256 signature
4. Wrapper sends request through `gateway.docker.internal:3128` (sbx HTTP proxy) to `host.docker.internal:8083`
5. Git safety server authenticates HMAC, applies policy checks
6. If allowed, executes real git binary against the bare repository on the host
7. Returns JSON response (exit_code, stdout, stderr) to the wrapper
8. Wrapper prints output and exits with the correct exit code

### Policy Layers

The server enforces six policy layers in order:

1. **HMAC authentication + nonce replay protection** - Rejects unauthenticated or replayed requests
2. **Command allowlist + flag blocklist** - Only explicitly allowed git commands run; dangerous flags like `--force` are blocked
3. **Branch isolation** - Sandbox agents see only their own branch and well-known branches (main, master, develop, production, release/*, hotfix/*)
4. **Protected branch enforcement** - Pushes to main, master, release/*, and production are blocked
5. **File restriction enforcement** - Pushes modifying `.github/workflows/`, CI configs, Makefiles, `.env*` files, etc. are blocked
6. **Rate limiting** - Per-sandbox burst (300), sustained (120/min), and global ceiling (1000/min)

### GitHub API Filtering

When the deep policy sidecar is enabled, dangerous GitHub API operations (PR merges, release creation, webhook management, secrets access) are blocked by YAML-driven request-shape policies while read-only GETs and safe writes are allowed. The bundled `deep-policy-github.yaml` provides the default rule set.

### Wrapper Injection

The git wrapper is installed into the sandbox during `cast new`:

1. `foundry_sandbox/assets/git-wrapper-sbx.sh` is copied to `/usr/local/bin/git` inside the sandbox via `sbx exec --user root`
2. Environment variables (`SANDBOX_ID`, `WORKSPACE_DIR`, `GIT_API_HOST`, `GIT_API_PORT`, `GIT_HMAC_SECRET_FILE`) are written to `/etc/profile.d/foundry-git-safety.sh`
3. The HMAC secret is placed at `/run/foundry/hmac-secret` (tmpfs, outside the VCS tree)

**Note:** The wrapper is a regular file that the agent can remove. For persistence across `sbx reset`, use `cast preset save` to snapshot the full sandbox state (including the wrapper) into a managed template, or use `sbx template save` directly for a raw template. See [Security Model](security/security-model.md) for the full threat analysis.

## Host State Layout

```
~/.sandboxes/
├── repos/                              # Bare git clones
│   └── github.com/
│       └── owner/
│           └── repo.git/
│
├── worktrees/                          # Git worktrees (one per sandbox)
│   ├── repo-feature-branch/
│   │   ├── .foundry/
│   │   │   └── hmac-secret            # HMAC secret for git safety
│   │   ├── .git                        # Points to bare repo
│   │   └── (working files)
│   └── repo-bugfix-123/
│       └── ...
│
├── claude-config/                      # Per-sandbox config + metadata
│   ├── repo-feature-branch/
│   │   ├── metadata.json              # SbxSandboxMetadata
│   │   └── claude/                     # Claude home directory
│   └── repo-bugfix-123/
│       └── ...
│
├── .last-cast-new.json                 # Most recent cast-new invocation
├── .last-attach.json                   # Most recent attach target
├── .version-check.json                 # Version check cache
└── presets/                            # Saved cast-new presets
    └── <name>.json
```

### Metadata File

Each sandbox has a `metadata.json` recording its configuration:

```json
{
  "backend": "sbx",
  "sbx_name": "repo-feature-branch",
  "agent": "claude",
  "repo_url": "https://github.com/owner/repo",
  "branch": "feature-branch",
  "from_branch": "main",
  "network_profile": "balanced",
  "git_safety_enabled": true,
  "allow_pr": false,
  "template": "foundry-git-wrapper:latest",
  "template_managed": false
}
```

### Git Safety Server State

The `foundry-git-safety` server stores its state in two directories on the host:

```
/run/secrets/sandbox-hmac/           # HMAC secrets (one file per sandbox)
    └── <sandbox-name>               # 64-hex-char secret

/var/lib/foundry-git-safety/         # Sandbox registration data
    └── sandboxes/
        └── <sandbox-name>.json      # Branch isolation metadata
```

## Networking Model

All network traffic from sandboxes is routed through sbx's built-in proxy:

```
┌──────────────────┐         ┌──────────────────────────────┐
│  SBX MICROVM     │         │         HOST                  │
│                  │         │                               │
│  Agent ──────────┼──HTTP──►│  gateway.docker.internal:3128 │
│                  │  proxy  │  (sbx HTTP proxy)              │
│                  │         │         │                      │
│  Git wrapper ────┼──HTTP──►│         ├──► host.docker.internal:8083
│                  │         │         │   (foundry-git-safety) │
│                  │         │         │                      │
│                  │         │         ├──► api.anthropic.com  │
│                  │         │         │   (credential injected│
│                  │         │         │    by sbx proxy)      │
│                  │         │         │                      │
│                  │         │         └──► (other allowed     │
│                  │         │              domains per policy)│
└──────────────────┘         └──────────────────────────────┘
```

**Key constraints:**
- Sandboxes cannot reach arbitrary host ports directly
- All traffic must go through `gateway.docker.internal:3128`
- Git safety server is accessible at `host.docker.internal:8083` through the proxy
- Network policy is configurable via `sbx policy` commands (balanced/allow-all/deny-all)

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
│ commands/new_sbx.py             │
│  - validate repo URL, API keys  │
│  - ensure bare repo exists      │
│  - create worktree              │
│  - sbx create (provisions VM)   │
│  - start git safety server      │
│  - generate HMAC secret         │
│  - inject git wrapper           │
│  - copy files / pip install     │
│  - write metadata               │
└─────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ sbx microVM (ready)             │
│  - workspace synced from host   │
│  - git wrapper active           │
│  - agent can run                │
└─────────────────────────────────┘
```

## See Also

- [Security Model](security/security-model.md) — Threats, defenses, and hardening
- [Configuration](configuration.md) — Configuration options and `foundry.yaml`
- [Commands](usage/commands.md) — Full command reference
- [ADR-008: sbx Migration](adr/008-sbx-migration.md) — Decision record for this architecture
