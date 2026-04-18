# Foundry Sandbox

[![CI](https://github.com/foundry-works/foundry-sandbox/actions/workflows/test.yml/badge.svg)](https://github.com/foundry-works/foundry-sandbox/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/foundry-sandbox)](https://pypi.org/project/foundry-sandbox/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built for Claude Code](https://img.shields.io/badge/Built_for-Claude_Code-cc785c)](https://docs.anthropic.com/en/docs/claude-code)

Ephemeral, batteries-included Docker workspaces that isolate AI coding agents from your credentials and host system.

## What It Does

Foundry Sandbox runs your code and AI assistants inside ephemeral Docker containers where **credentials never enter the sandbox**. A unified proxy on the host holds your real API keys and tokens, injecting them into outbound requests only after policy validation. Code running inside — whether an AI assistant, a build script, or a malicious dependency — never sees the actual credentials.

```
+------------------+     +------------------------------+     +------------------+
|    Sandbox       |     |       Unified Proxy          |     |  External APIs   |
|                  |     |                              |     |                  |
|  AI assistants,  |---->|  API gateways (per-provider) |---->|  GitHub, Claude, |
|  build scripts,  |     |  Network allowlist (Squid)   |     |  OpenAI, Gemini  |
|  your code       |     |  Git policy engine           |     |                  |
|                  |     |                              |     |                  |
|  [no real creds] |     |  [all credentials]           |     |                  |
+------------------+     +------------------------------+     +------------------+
```

Multiple independent security layers provide defense in depth:

| Layer | What it does |
|-------|-------------|
| Credential isolation | API keys never enter the container; injected by proxy on egress |
| Read-only filesystem | Prevents destructive commands (`rm -rf /` is a no-op) |
| Network allowlists | Egress restricted to approved domains only |
| Branch isolation | Each sandbox sees only its own branch; other branches are hidden |
| Git safety | Protected branches, force-push blocking, GitHub API controls |

Each sandbox is a git worktree — create one in seconds, destroy it with zero trace.

## Key Features

**Security**
- Credential isolation via unified proxy (enabled by default)
- Network control: allowlist, host-only, or no network
- Branch isolation and git safety policies

**Developer experience**
- Claude Code, Gemini CLI, and Codex CLI are pre-installed
- Fast creation: worktrees share git objects, new sandboxes spin up in seconds
- Presets and history: save configurations, repeat last command with `cast repeat`
- Spec-driven development: [foundry-mcp](https://github.com/foundry-works/claude-foundry) server pre-configured for Claude Code

**Automation**
- Volume mounts (read-write or read-only)
- All commands support `--json` for scripting

## Quick Start

**1. Install**

```bash
curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
```

Clones to `~/.foundry-sandbox`, adds the `cast` command, enables tab completion, and builds the Docker image. Also available on [PyPI](https://pypi.org/project/foundry-sandbox/) (`pipx install foundry-sandbox`). See [Getting Started](docs/getting-started.md) for manual install, uninstall, and prerequisites.

**2. Set up credentials**

```bash
claude setup-token              # Claude Code
codex login                     # Codex CLI (ChatGPT subscription)
gh auth login                   # GitHub (for private repos and push)
gemini auth                     # Gemini CLI (if using)
```

Credentials stay on the host — the proxy injects them into requests so they never enter the sandbox. See [Configuration](docs/configuration.md) for all supported API keys.

**3. Create a sandbox**

Use the guided wizard to create a new sandbox.

```bash
cast new
```

**4. Work inside**

Launch your favorite AI agent.

```bash
claude              # Claude Code
gemini              # Gemini CLI
codex               # Codex CLI
```

**4. Commit, push**

Ask your AI agent to commit and push changes.

**5. Destroy**

CTRL+D to exit the sandbox, then from host:

```bash
cast destroy <sandbox-name> --yes   # Remove worktree and container
```

## Prerequisites

Docker 20.10+, Git 2.x+, Bash 4+, tmux 3+, Python 3.10+. Linux and macOS supported natively; Windows requires WSL2. macOS ships Bash 3.2 — install 4+ via `brew install bash`.

## Limitations

- **Not a targeted-attack boundary** — defends against supply-chain attacks and AI mistakes, not a determined human attacker with host-level Docker access
- **Requires Docker** — no native process isolation
- **Linux/macOS** — Windows requires WSL2
- **No GPU passthrough** — needs additional Docker configuration

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation and first sandbox |
| [Commands](docs/usage/commands.md) | Full command reference |
| [Workflows](docs/usage/workflows.md) | Common patterns and recipes |
| [Configuration](docs/configuration.md) | API keys, plugins, and config files |
| [Architecture](docs/architecture.md) | Technical design and diagrams |
| [Security Model](docs/security/security-model.md) | Threat model, defenses, and hardening |
| [Operations](docs/operations.md) | Proxy operations runbook |
| [Observability](docs/observability.md) | Metrics and debugging |
| [Contributing](docs/development/contributing.md) | For contributors |

## Support

- **Issues**: [GitHub Issues](https://github.com/foundry-works/foundry-sandbox/issues)
- **Discussions**: [GitHub Discussions](https://github.com/foundry-works/foundry-sandbox/discussions)

## License

MIT License. See [LICENSE](LICENSE) for details.
