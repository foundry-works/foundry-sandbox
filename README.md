# Foundry Sandbox

Safe, ephemeral workspaces for AI-assisted coding—isolate mistakes, not productivity.

## Overview

AI coding assistants are powerful but imperfect. They can hallucinate destructive commands, misunderstand context, or make changes you didn't intend. Running them directly on your machine means one bad `rm -rf` or `git push --force` away from real damage.

Foundry Sandbox solves this by providing isolated Docker environments with defense-in-depth safety layers. Each sandbox is a disposable git worktree where AI tools can operate freely while multiple safeguards prevent accidents from escaping. You get the productivity of AI assistance with the confidence that mistakes stay contained.

## Key Features

- **Ephemeral Workspaces** - Git worktrees per sandbox; destroy when done with no trace
- **Defense in Depth** - 5 safety layers from shell overrides to read-only root filesystem
- **Multiple AI Tools** - Claude Code, Gemini CLI, Codex CLI, OpenCode, and Cursor Agent pre-installed
- **Fast Creation** - Worktrees share git objects; new sandboxes spin up in seconds
- **Network Control** - Full, limited (whitelist), host-only, or no network access
- **Volume Mounts** - Mount host directories read-write or read-only
- **JSON Output** - All commands support `--json` for scripting and automation

## Prerequisites

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| Docker | 20.10+ | `docker --version` |
| Git | 2.x+ | `git --version` |
| Bash | 4.x+ | `bash --version` |
| tmux | 3.x+ | `tmux -V` |

Linux and macOS supported natively. Windows users need WSL2.

macOS notes:
- Docker Desktop file sharing must include any host paths you plan to mount into the container.
- Example: if you run `cast new owner/repo --mount ~/GitHub/myrepo:/workspace`, add `/Users/<you>/GitHub` in Docker Desktop → Settings → Resources → File Sharing.
- macOS ships Bash 3.2; install Bash 4+ (e.g., `brew install bash`) and run `cast` with the newer bash (e.g., `alias cast='bash ~/.foundry-sandbox/sandbox.sh'`).

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
```

This will:
- Clone to `~/.foundry-sandbox`
- Add the `cast` alias to your shell
- Enable tab completion
- Build the Docker image

### Manual Install

**1. Clone the repository**

```bash
git clone https://github.com/foundry-works/foundry-sandbox.git ~/.foundry-sandbox
```

**2. Add to your shell** (`~/.bashrc` or `~/.zshrc`)

```bash
alias cast='~/.foundry-sandbox/sandbox.sh'
source ~/.foundry-sandbox/completion.bash
```

**3. Reload and build**

```bash
source ~/.bashrc
cast build
```

### Uninstall

```bash
~/.foundry-sandbox/uninstall.sh
```

## Quick Start

**1. Create a sandbox**

```bash
cast new owner/repo
```

**2. Run an AI assistant**

```bash
claude              # Claude Code
gemini              # Gemini CLI
codex               # Codex CLI
opencode            # OpenCode
cursor              # Cursor Agent
```

**3. Commit and push your changes**

```bash
git add -A && git commit -m "Add feature"
git push origin HEAD
```

**4. Destroy when done**

```bash
cast destroy sandbox-name --yes
```

## Usage Examples

### Basic Workflow

```bash
# Create sandbox from a GitHub repo
cast new owner/repo

# You're now in a tmux session at /workspace
# Run your AI tool, make changes, commit, push

# Detach with Ctrl+b, d (keeps sandbox running)
# Or exit the shell
```

### Branch Management

```bash
# Create sandbox from existing branch
cast new owner/repo feature-branch

# Create new branch from main
cast new owner/repo my-feature main
```

### Volume Mounts

```bash
# Mount a local directory (read-write)
cast new owner/repo --copy ~/data:/data

# Mount read-only
cast new owner/repo --copy ~/config:/config:ro
```

### Network Modes

```bash
# Full network access (default)
cast new owner/repo

# Limited to whitelist (GitHub, npm, PyPI, AI APIs)
cast new owner/repo --network=limited

# Local network only
cast new owner/repo --network=host-only

# No network
cast new owner/repo --network=none
```

## How It Works

```
┌────────────────────────────────────────────────────────────┐
│                      HOST SYSTEM                           │
│                                                            │
│  cast new owner/repo                                         │
│       │                                                    │
│       ▼                                                    │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              DOCKER CONTAINER                         │  │
│  │                                                       │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │              SAFETY LAYERS                       │  │  │
│  │  │  Layer 1: Shell Overrides (UX warnings)         │  │  │
│  │  │  Layer 2: Operator Approval (human-in-loop)     │  │  │
│  │  │  Layer 3: Sudoers Allowlist (kernel-enforced)   │  │  │
│  │  │  Layer 4: Network Isolation (iptables)          │  │  │
│  │  │  Layer 0: Read-only Root (Docker enforced)      │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │                                                       │  │
│  │  /workspace ◄── git worktree (your code)              │  │
│  │  /home/ubuntu ◄── tmpfs (resets on stop)              │  │
│  │  / (root) ◄── read-only filesystem                    │  │
│  │                                                       │  │
│  │  Pre-installed: Claude, Gemini, Codex, OpenCode, Cursor │  │
│  │                 Node.js, Go, Python, GitHub CLI        │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  ~/.sandboxes/                                             │
│    ├── repos/      (bare git repos, shared across boxes)   │
│    └── worktrees/  (checked-out code per sandbox)          │
└────────────────────────────────────────────────────────────┘
```

**Git worktrees** share objects across sandboxes—no redundant clones, fast creation.

**Read-only root** means even if all other layers fail, filesystem writes are blocked.

**Tmpfs home** resets on container stop—no accumulated state or leaked credentials.

## Command Reference

### Create and Attach

| Command | Description |
|---------|-------------|
| `cast new owner/repo` | Create sandbox from GitHub repo |
| `cast new owner/repo branch` | Create from existing branch |
| `cast new owner/repo new-branch base` | Create new branch from base |
| `cast attach name` | Attach to running sandbox |
| `cast attach` | Interactive selector (requires fzf) |

### Lifecycle Management

| Command | Description |
|---------|-------------|
| `cast start name` | Start stopped sandbox |
| `cast stop name` | Stop running sandbox (preserves worktree) |
| `cast destroy name` | Remove sandbox and worktree |
| `cast destroy name --yes` | Skip confirmation prompt |

### Status and Info

| Command | Description |
|---------|-------------|
| `cast list` | List all sandboxes |
| `cast list --json` | JSON output for scripting |
| `cast status` | Status of all sandboxes |
| `cast status name` | Status of specific sandbox |
| `cast info` | Combined system info |
| `cast config` | Show configuration |

### Maintenance

| Command | Description |
|---------|-------------|
| `cast prune` | Remove orphaned configs |
| `cast build` | Build/rebuild Docker image |
| `cast help` | Show help message |

## Configuration

### Pre-installed Claude Plugin

The Docker image includes the [claude-foundry](https://github.com/foundry-works/claude-foundry) plugin pre-configured. This provides:
- **foundry-mcp** MCP server with spec-driven development tools
- Skills: `/foundry-spec`, `/foundry-implement`, `/foundry-review`, `/foundry-test`, etc.

No host installation required. The plugin is ready to use immediately in new sandboxes.

To update the plugin version, rebuild the Docker image:
```bash
# Update docker/.claude/plugins/cache/claude-foundry/foundry/<version>/ with new plugin files
./sandbox.sh build
```

### API Keys

The sandbox automatically copies credential files from your host into containers:

| Source | Destination | Purpose |
|--------|-------------|---------|
| `~/.api_keys` | `/home/ubuntu/.api_keys` | API keys (sourced at startup) |
| `~/.gitconfig` | `/home/ubuntu/.gitconfig` | Git configuration |
| `~/.ssh/` | `/home/ubuntu/.ssh/` | SSH keys |
| `~/.config/gh/` | `/home/ubuntu/.config/gh/` | GitHub CLI (from `gh auth login`) |
| `~/.gemini/` | `/home/ubuntu/.gemini/` | Gemini CLI OAuth (from `gemini auth`) |
| `~/.config/opencode/` | `/home/ubuntu/.config/opencode/` | OpenCode config (opencode.json) |
| `~/.local/share/opencode/auth.json` | `/home/ubuntu/.local/share/opencode/auth.json` | OpenCode auth (from `opencode auth login`) |

**Create `~/.api_keys` on your host:**

```bash
cat > ~/.api_keys << 'EOF'
export CLAUDE_CODE_OAUTH_TOKEN="..."   # Get via: claude setup-token
export CURSOR_API_KEY="key-..."
# Deep research providers (foundry-mcp)
export TAVILY_API_KEY="..."
export PERPLEXITY_API_KEY="..."
EOF
chmod 600 ~/.api_keys
```

**For Gemini CLI:** Run `gemini auth` on your host to authenticate. The OAuth credentials in `~/.gemini/` are automatically copied into containers.

**For OpenCode:** Run `opencode auth login` for standard auth. To use subscription-based models:
- [opencode-openai-codex-auth](https://github.com/numman-ali/opencode-openai-codex-auth) - Use OpenAI/Codex with ChatGPT subscription
- [opencode-antigravity-auth](https://github.com/NoeFabris/opencode-antigravity-auth) - Use Gemini with Google AI subscription

Replace the placeholder values with your actual keys. The file is sourced automatically when containers start.

### Debug Output

```bash
SANDBOX_DEBUG=1 cast list          # Debug logging
SANDBOX_VERBOSE=1 cast start name  # Verbose output
```

### Network Whitelist

Add custom domains to the limited network whitelist:

```bash
export SANDBOX_ALLOWED_DOMAINS="api.example.com,internal.corp.com"
cast new owner/repo --network=limited
```

## Safety Layers

Foundry Sandbox uses defense in depth—multiple independent layers that each provide protection:

| Layer | Purpose | Bypass? |
|-------|---------|---------|
| **Layer 1: Shell Overrides** | Friendly warnings for `rm -rf /`, `git push --force`, etc. | Yes (intentional, for human override) |
| **Layer 2: Operator Approval** | Sensitive commands require TTY confirmation | No (AI has no TTY) |
| **Layer 3: Sudoers Allowlist** | Only whitelisted sudo commands allowed | No (kernel enforced) |
| **Layer 4: Network Isolation** | Optional network restrictions | No (iptables/Docker enforced) |
| **Layer 0: Read-only Root** | Filesystem writes blocked at kernel level | No (Docker enforced) |

Layer 1 is designed to be bypassable—it provides UX for non-adversarial AI, not security. The real protection comes from layers 0, 2, 3, and 4, which cannot be bypassed from inside the container.

See [Safety Layers](docs/security/safety-layers.md) for implementation details.

## Limitations

- **Not a security boundary against malicious actors** - Protects against accidental damage from well-intentioned AI, not adversarial attacks
- **Requires Docker** - No native process isolation; container overhead applies
- **Linux/macOS focus** - Windows requires WSL2
- **Shared git history** - All sandboxes share the same bare repo; force-push from one affects others
- **No GPU passthrough** - Standard Docker networking; GPU workloads need additional configuration

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation and first sandbox |
| [Architecture](docs/architecture.md) | Technical design and diagrams |
| [Threat Model](docs/security/threat-model.md) | What we protect against |
| [Safety Layers](docs/security/safety-layers.md) | Defense in depth details |
| [Commands](docs/usage/commands.md) | Full command reference |
| [Workflows](docs/usage/workflows.md) | Common patterns and recipes |
| [Contributing](docs/development/contributing.md) | For contributors |

## Support

- **Issues**: [GitHub Issues](https://github.com/foundry-works/foundry-sandbox/issues)
- **Discussions**: [GitHub Discussions](https://github.com/foundry-works/foundry-sandbox/discussions)

## License

*License information to be added. Consider MIT or Apache 2.0 for open source projects.*
