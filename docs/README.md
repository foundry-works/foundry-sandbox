# Foundry Sandbox Documentation

Foundry Sandbox provides temporary, isolated development environments for AI-assisted coding. Each sandbox runs in a microVM with security controls that protect your host system, credentials, and git history from accidental damage and supply chain attacks, while still giving AI coding assistants (Claude Code, Gemini CLI, Codex CLI, OpenCode) the tools they need to be productive.

The key insight: AI assistants can hallucinate dangerous commands or act without full context, and malicious dependencies can steal credentials. Sandboxes let them work freely while limiting blast radius.

## Key Features

- **Temporary workspaces** - Each sandbox gets a fresh git worktree; destroy it when done
- **Credential isolation** - API keys stored on the host by sbx; injected at the network level, never entering the VM
- **Git shadow mode** - All git operations proxied through authenticated API with policy enforcement (branch isolation, push protection)
- **Layered security** - MicroVM isolation, network policy, credential injection, branch isolation, git safety
- **Pre-installed AI tools** - Claude Code, Gemini CLI, Codex CLI, OpenCode ready to use
- **Multiple agent support** - Choose your agent at creation time (`--agent claude`, `codex`, `gemini`, etc.)

## Quick Start

```bash
# Install prerequisites
brew install docker/tap/sbx        # or see getting-started for other platforms
pip install foundry-git-safety[server]

# Create a sandbox from a GitHub repo
cast new owner/repo

# You're now in an interactive shell inside the sandbox
# Run your AI assistant:
claude
```

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Installation, setup, and first sandbox |
| [Configuration](configuration.md) | API keys, git safety settings, network policy |
| [Architecture](architecture.md) | Technical design and diagrams |
| [Operations](operations.md) | Operational procedures and runbook |
| [sbx Compatibility](sbx-compatibility.md) | Supported sbx versions, tested-against matrix, drift detection |
| [Migration Guide](migration/0.20-to-0.21.md) | Upgrading from 0.20.x to 0.21.x |
| [Observability](observability.md) | Metrics, logging, and alerting |

### Security

| Document | Description |
|----------|-------------|
| [Security Model](security/security-model.md) | Threats, defenses, hardening, and security assumptions — organized by pillar |
| [Wrapper Integrity](security/wrapper-integrity.md) | Wrapper tamper detection and watchdog design |
| [Security Audit 5.6](security/audit-5.6.md) | Internal security audit findings and remediation |

### Usage

| Document | Description |
|----------|-------------|
| [Commands](usage/commands.md) | Complete CLI reference |
| [Workflows](usage/workflows.md) | Common patterns |

### Architecture Decision Records

| Document | Description | Status |
|----------|-------------|--------|
| [ADR-001: Unified Proxy Architecture](adr/001-consolidation.md) | Single-service proxy for credential isolation and request interception | Superseded |
| [ADR-002: Container Identity](adr/002-container-identity.md) | Container identity design for proxy authentication | Superseded |
| [ADR-003: Policy Engine](adr/003-policy-engine.md) | Policy engine design for access control | Accepted |
| [ADR-004: DNS Integration](adr/004-dns-integration.md) | DNS filtering integration with unified proxy | Superseded |
| [ADR-005: Failure Modes](adr/005-failure-modes.md) | Failure modes and readiness design | Superseded |
| [ADR-006: Allowlist Layering](adr/006-allowlist-layering.md) | Layered allowlist architecture for network access | Accepted |
| [ADR-007: API Gateways](adr/007-api-gateways.md) | API gateway routing and credential injection | Superseded |
| [ADR-008: sbx Migration](adr/008-sbx-migration.md) | Migration from docker-compose to Docker sbx backend | Accepted |
| [ADR-009: No Dual-Mode Operation](adr/009-dual-mode-decision.md) | No dual-mode operation during migration | Accepted |
| [ADR-010: User-Service Credential Injection](adr/010-user-service-credential-injection.md) | User-defined service credential injection via reverse proxy | Accepted |
| [ADR-011: Deep Policy Sidecar](adr/011-deep-policy-sidecar.md) | Deep policy sidecar design | Accepted |
| [ADR-012: DNS Filtering Deferred](adr/012-dns-filtering-deferred.md) | DNS-level filtering not achievable with sbx architecture | Accepted |
| [ADR-013: Template-Preset Integration](adr/013-template-preset-integration.md) | Template-preset integration for sbx | Accepted |

### Development

| Document | Description |
|----------|-------------|
| [Contributing](development/contributing.md) | How to contribute |

## Quick Reference

```bash
cast new owner/repo              # Create sandbox from main
cast new owner/repo branch       # Create from existing branch
cast new owner/repo new main     # Create new branch from main
cast new owner/repo feature --agent codex  # Use a different agent
cast list                        # List all sandboxes
cast attach name                 # Attach to running sandbox
cast stop name                   # Stop sandbox (preserves worktree)
cast destroy name                # Remove sandbox completely
cast refresh-creds               # Push API keys to sbx
cast help                        # Show all commands
```
