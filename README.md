# Foundry Sandbox

Safe, ephemeral workspaces for AI-assisted coding—isolate mistakes, not productivity.

## Overview

AI coding assistants are powerful but imperfect. They can hallucinate destructive commands, misunderstand context, or make changes you didn't intend. Running them directly on your machine means one bad `rm -rf` or `git push --force` away from real damage.

Foundry Sandbox solves this by providing isolated Docker environments with defense-in-depth safety layers. Each sandbox is a disposable git worktree where AI tools can operate freely while multiple safeguards prevent accidents from escaping. You get the productivity of AI assistance with the confidence that mistakes stay contained.

## Key Features

- **Ephemeral Workspaces** - Git worktrees per sandbox; destroy when done with no trace
- **Defense in Depth** - 6 safety layers from shell overrides to read-only root filesystem
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

Or from your current repo/branch:

```bash
cast new .
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
cast new owner/repo --mount ~/data:/data

# Mount read-only
cast new owner/repo --mount ~/config:/config:ro

# Copy once at creation time
cast new owner/repo --copy ~/models:/models
```

### Credential Sync

SSH forwarding and API keys sync are both opt-in (agent-only; `~/.ssh` is not copied).

```bash
# Enable SSH agent forwarding
cast new owner/repo --with-ssh

# Enable syncing ~/.api_keys
cast new owner/repo --with-api-keys

# Enable both
cast new owner/repo --with-ssh --with-api-keys
```

Claude plugins and settings persist at `~/.sandboxes/claude-config/<name>/claude` across restarts. SSH is only needed for private Git/marketplace access.

### Network Modes

```bash
# Limited to whitelist (default)
cast new owner/repo

# Full network access
cast new owner/repo --network=full

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
│  │  │  Layer 2: Credential Redaction (masks secrets)  │  │  │
│  │  │  Layer 3: Operator Approval (human-in-loop)     │  │  │
│  │  │  Layer 4: Sudoers Allowlist (kernel-enforced)   │  │  │
│  │  │  Layer 5: Network Isolation (iptables)          │  │  │
│  │  │  Layer 6: Read-only Root (Docker enforced)      │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │                                                       │  │
│  │  /workspace ◄── git worktree (your code)              │  │
│  │  /home/ubuntu ◄── tmpfs (resets; ~/.claude persists)  │  │
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

**Tmpfs home** resets on container stop, except `~/.claude` which persists per sandbox so plugin installs and settings survive.

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
| `cast destroy-all` | Remove all sandboxes |
| `cast destroy-all --yes` | Skip confirmation prompt |

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

### Claude Plugin

The [claude-foundry](https://github.com/foundry-works/claude-foundry) plugin is installed automatically when you create a new sandbox. This provides:
- **foundry-mcp** MCP server with spec-driven development tools
- Skills: `/foundry-spec`, `/foundry-implement`, `/foundry-review`, `/foundry-test`, etc.

No host installation required. The plugin is fetched from GitHub and configured during sandbox creation.

Optional statusline: if you use [cc-context-stats](https://github.com/luongnv89/cc-context-stats), place your `statusline.conf` in `~/.claude/statusline.conf` and it will be copied into new sandboxes. The Docker image includes `claude-statusline`, so the statusline works out of the box.

**Claude LSPs:** the `pyright-lsp` plugin is installed from the official Claude marketplace for type checking support.

### API Keys

The sandbox automatically copies credential files from your host into containers:

| Source | Destination | Purpose |
|--------|-------------|---------|
| `~/.api_keys` | `/home/ubuntu/.api_keys` | API keys (sourced at startup) |
| `~/.claude.json` | `/home/ubuntu/.claude.json` | Claude Code preferences (host file only) |
| `~/.claude/settings.json` | `/home/ubuntu/.claude/settings.json` | Claude Code settings |
| `~/.claude/statusline.conf` | `/home/ubuntu/.claude/statusline.conf` | Optional Claude statusline config (cc-context-stats; `claude-statusline` is bundled in the image) |
| `~/.gitconfig` | `/home/ubuntu/.gitconfig` | Git configuration |
| `~/.ssh/` | `/home/ubuntu/.ssh/` | SSH config/keys (when enabled) |
| `~/.config/gh/` | `/home/ubuntu/.config/gh/` | GitHub CLI (from `gh auth login`) |
| `~/.gemini/` | `/home/ubuntu/.gemini/` | Gemini CLI OAuth (from `gemini auth`) |
| `~/.config/opencode/opencode.json` | `/home/ubuntu/.config/opencode/opencode.json` | OpenCode config |
| `~/.config/opencode/antigravity-accounts.json` | `/home/ubuntu/.config/opencode/antigravity-accounts.json` | OpenCode Antigravity accounts (host file only) |
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

**For Gemini CLI:** Run `gemini auth` on your host to authenticate. The OAuth credentials in `~/.gemini/` are automatically copied into containers. Large Gemini CLI artifacts (e.g. `~/.gemini/antigravity`) are skipped to keep sandboxes lightweight. Sandboxes default to disabling auto-updates, update nags, telemetry, and usage stats unless you set them in `~/.gemini/settings.json`.

**For Codex CLI:** Sandboxes default to disabling update checks and analytics via `~/.codex/config.toml` unless you set them on your host.

**For OpenCode:** Run `opencode auth login` for standard auth. For the best experience, install these plugins on your host first:
- [opencode-openai-codex-auth](https://github.com/numman-ali/opencode-openai-codex-auth) - Use OpenAI/Codex with ChatGPT subscription
- [opencode-gemini-auth](https://github.com/jenslys/opencode-gemini-auth) - Use Gemini CLI subscription

Follow the instructions in each repo to set them up on your host before creating sandboxes.

## Safety Layers

Foundry Sandbox uses defense in depth—multiple independent layers that each provide protection:

| Layer | Purpose | Bypass? |
|-------|---------|---------|
| **Layer 1: Shell Overrides** | Friendly warnings for `rm -rf /`, `git push --force`, etc. | Yes (intentional, for human override) |
| **Layer 2: Credential Redaction** | Masks secrets in command output | Yes (defense in depth) |
| **Layer 3: Operator Approval** | Sensitive commands require TTY confirmation | No (AI has no TTY) |
| **Layer 4: Sudoers Allowlist** | Only whitelisted sudo commands allowed | No (kernel enforced) |
| **Layer 5: Network Isolation** | Optional network restrictions | No (iptables/Docker enforced) |
| **Layer 6: Read-only Root** | Filesystem writes blocked at kernel level | No (Docker enforced) |

Layers 1 and 2 are designed to be bypassable—they provide UX and defense in depth for non-adversarial AI, not security. The real protection comes from layers 3–6, which cannot be bypassed from inside the container.

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

MIT License. See [LICENSE](LICENSE) for details.
