# Foundry Sandbox Documentation

Foundry Sandbox provides ephemeral, isolated development environments for AI-assisted coding. Each sandbox runs in a Docker container with security guardrails that protect your host system, credentials, and git history from accidental damage and supply chain attacks, while still giving AI coding assistants (Claude Code, Gemini CLI, Codex CLI, OpenCode) the tools they need to be productive.

The key insight: AI assistants can hallucinate dangerous commands or act without full context, and malicious dependencies can steal credentials. Sandboxes let them work freely while limiting blast radius.

## Key Features

- **Ephemeral workspaces** - Each sandbox gets a fresh git worktree; destroy it when done
- **Credential isolation** - API keys and tokens never enter the sandbox; injected by proxy at the network level
- **Git shadow mode** - `.git` hidden from sandboxes; all git operations proxied through authenticated API with policy enforcement
- **Security guardrails** - Defense in depth with multiple safety layers
- **Pre-installed AI tools** - Claude Code, Gemini CLI, Codex CLI, OpenCode ready to use
- **Filesystem protection** - Read-only root in base mode; non-root user with network isolation in credential isolation mode
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
| [Operations](operations.md) | Operational procedures and runbook |
| [Observability](observability.md) | Metrics, logging, and alerting |
| [Certificates](certificates.md) | CA certificate management |

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

### Architecture Decision Records

| Document | Description |
|----------|-------------|
| [ADR-001: Unified Proxy Consolidation](adr/001-consolidation.md) | Consolidation of gateway and api-proxy into unified proxy |
| [ADR-002: Container Identity](adr/002-container-identity.md) | Container identity design for proxy authentication |
| [ADR-003: Policy Engine](adr/003-policy-engine.md) | Policy engine design for access control |
| [ADR-004: DNS Integration](adr/004-dns-integration.md) | DNS filtering integration with unified proxy |
| [ADR-005: Failure Modes](adr/005-failure-modes.md) | Failure modes and readiness design |

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
