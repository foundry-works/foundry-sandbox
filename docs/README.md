# Foundry Sandbox Documentation

Foundry Sandbox provides ephemeral, isolated development environments for AI-assisted coding. Each sandbox runs in a Docker container with security guardrails that protect your host system and git history from accidental damage, while still giving AI coding assistants (Claude Code, Gemini CLI, Codex CLI, OpenCode) the tools they need to be productive.

The key insight: AI assistants can hallucinate dangerous commands or act without full context. Sandboxes let them work freely while limiting blast radius.

## Key Features

- **Ephemeral workspaces** - Each sandbox gets a fresh git worktree; destroy it when done
- **Security guardrails** - Defense in depth with multiple safety layers
- **Pre-installed AI tools** - Claude Code, Gemini CLI, Codex CLI, OpenCode ready to use
- **Read-only root** - Container filesystem prevents `rm -rf /` even via bypass attempts
- **Tmpfs isolation** - Home directory resets on container restart

## Quick Start

```bash
# Build the sandbox image
./sandbox.sh build

# Create a sandbox from a GitHub repo
cast new owner/repo

# You're now in a tmux session inside the container
# Run your AI assistant:
claude
```

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Installation, setup, and first sandbox |
| [Configuration](configuration.md) | API keys, plugins, and config files |
| [Architecture](architecture.md) | Technical design and diagrams |

### Security

| Document | Description |
|----------|-------------|
| [Security Overview](security/index.md) | Security architecture and quick reference |
| [Sandbox Threats](security/sandbox-threats.md) | AI-as-threat-actor model |
| [Credential Isolation](security/credential-isolation.md) | Credential isolation threat model |
| [Security Architecture](security/security-architecture.md) | Security pillars and defense layers |
| [Network Isolation](security/network-isolation.md) | Network architecture |

### Usage

| Document | Description |
|----------|-------------|
| [Commands](usage/commands.md) | Complete CLI reference |
| [Workflows](usage/workflows.md) | Common patterns |

### Development

| Document | Description |
|----------|-------------|
| [Contributing](development/contributing.md) | How to contribute |

## Quick Reference

```bash
cast new owner/repo              # Create sandbox from main
cast new owner/repo branch       # Create from existing branch
cast new owner/repo new main     # Create new branch from main
cast list                        # List all sandboxes
cast attach name                 # Attach to running sandbox
cast stop name                   # Stop sandbox (preserves worktree)
cast destroy name                # Remove sandbox completely
cast help                        # Show all commands
```
