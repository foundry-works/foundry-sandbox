# Foundry Sandbox Documentation

Foundry Sandbox provides ephemeral, isolated development environments for AI-assisted coding. Each sandbox runs in a Docker container with security guardrails that protect your host system and git history from accidental damage, while still giving AI coding assistants (Claude Code, Gemini CLI, OpenCode) the tools they need to be productive.

The key insight: AI assistants can hallucinate dangerous commands or act without full context. Sandboxes let them work freely while limiting blast radius.

## Key Features

- **Ephemeral workspaces** - Each sandbox gets a fresh git worktree; destroy it when done
- **Security guardrails** - Three-layer defense protects against destructive commands
- **Pre-installed AI tools** - Claude Code, Gemini CLI, OpenCode ready to use
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
| [Architecture](architecture.md) | Technical design and diagrams |
| [Security: Threat Model](security/threat-model.md) | What we protect against and why |
| [Security: Safety Layers](security/safety-layers.md) | Three-layer defense explained |
| [Usage: Commands](usage/commands.md) | Complete command reference |
| [Usage: Workflows](usage/workflows.md) | Common patterns and examples |
| [Contributing](development/contributing.md) | For contributors |

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
