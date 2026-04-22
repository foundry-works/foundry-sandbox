# Foundry Sandbox

[![CI](https://github.com/foundry-works/foundry-sandbox/actions/workflows/test.yml/badge.svg)](https://github.com/foundry-works/foundry-sandbox/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/foundry-sandbox)](https://pypi.org/project/foundry-sandbox/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built for Claude Code](https://img.shields.io/badge/Built_for-Claude_Code-cc785c)](https://docs.anthropic.com/en/docs/claude-code)

Ephemeral, batteries-included microVM workspaces that isolate AI coding agents from your credentials and host system.

## What It Does

Foundry Sandbox runs your code and AI assistants inside ephemeral Docker sbx microVMs where **credentials never enter the sandbox**. A host-side git safety server and sbx proxy hold your real API keys and tokens, injecting them into outbound requests only after policy validation. Code running inside — whether an AI assistant, a build script, or a malicious dependency — never sees the actual credentials.

```
+------------------+     +---------------------------+     +------------------+
|    Sandbox       |     |     Host Services         |     |  External APIs   |
|  (microVM)       |     |                           |     |                  |
|  AI assistants,  |---->|  sbx proxy (credentials)  |---->|  GitHub, Claude, |
|  build scripts,  |     |  git safety (policy)      |     |  OpenAI, Gemini  |
|  your code       |     |  HMAC auth, branch guard  |     |                  |
|                  |     |                           |     |                  |
|  [no real creds] |     |  [all credentials]        |     |                  |
+------------------+     +---------------------------+     +------------------+
```

Multiple independent security layers provide defense in depth:

| Layer | What it does |
|-------|-------------|
| MicroVM isolation | Sandbox runs in a lightweight VM with its own kernel |
| Credential injection | API keys stored by sbx; injected at network level, never entering the VM |
| Git safety | All git operations proxied through authenticated API with policy enforcement |
| Branch isolation | Each sandbox sees only its own branch; other branches are hidden |
| Network policy | sbx controls egress; no raw network access from sandbox |
| Wrapper integrity | Watchdog detects tampering with the git wrapper |

Each sandbox is a git worktree — create one in seconds, destroy it with zero trace.

## Key Features

**Security**
- Credential isolation via sbx proxy (enabled by default)
- Git safety: protected branches, force-push blocking, GitHub API controls
- Wrapper integrity watchdog with HMAC-SHA256 authentication
- Branch isolation between concurrent sandboxes

**Developer experience**
- Claude Code, Gemini CLI, Codex CLI, and OpenCode pre-installed
- Fast creation: worktrees share git objects, new sandboxes spin up in seconds
- Presets and history: save configurations, repeat last command with `cast new --last`
- [claude-foundry](https://github.com/foundry-works/claude-foundry) plugin pre-configured for Claude Code

**Automation**
- All commands support `--json` for scripting

## Quick Start

**1. Install**

```bash
curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
```

Clones to `~/.foundry-sandbox`, adds the `cast` command. Also available on [PyPI](https://pypi.org/project/foundry-sandbox/) (`pipx install foundry-sandbox`). See [Getting Started](docs/getting-started.md) for manual install, uninstall, and prerequisites.

**2. Set up credentials**

```bash
claude setup-token              # Claude Code
codex login                     # Codex CLI (ChatGPT subscription)
gh auth login                   # GitHub (for private repos and push)
gemini auth                     # Gemini CLI (if using)
```

Credentials stay on the host — sbx injects them into requests so they never enter the sandbox. See [Configuration](docs/configuration.md) for all supported API keys.

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

**5. Commit, push**

Ask your AI agent to commit and push changes.

**6. Destroy**

CTRL+D to exit the sandbox, then from host:

```bash
cast destroy <sandbox-name> --yes   # Remove worktree and sandbox
```

## Prerequisites

Docker sbx, Git 2.x+, Bash 4+, Python 3.10+. Linux and macOS supported natively; Windows requires WSL2. See [sbx Compatibility](docs/sbx-compatibility.md) for supported sbx versions.

## Limitations

- **Not a targeted-attack boundary** — defends against supply-chain attacks and AI mistakes, not a determined human attacker with host-level access
- **Requires Docker sbx** — no native process isolation without it
- **Linux/macOS** — Windows requires WSL2

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation and first sandbox |
| [Commands](docs/usage/commands.md) | Full command reference |
| [Workflows](docs/usage/workflows.md) | Common patterns and recipes |
| [Configuration](docs/configuration.md) | API keys, plugins, and config files |
| [Architecture](docs/architecture.md) | Technical design and diagrams |
| [Security Model](docs/security/security-model.md) | Threat model, defenses, and hardening |
| [Operations](docs/operations.md) | Operational runbook |
| [Observability](docs/observability.md) | Metrics and debugging |
| [sbx Compatibility](docs/sbx-compatibility.md) | Supported versions and drift detection |
| [Migration Guide](https://github.com/foundry-works/foundry-sandbox/tree/0.22.x/docs/migration/0.20-to-0.21.md) | Upgrading from 0.20.x to 0.21.x |
| [Contributing](docs/development/contributing.md) | For contributors |

## Support

- **Issues**: [GitHub Issues](https://github.com/foundry-works/foundry-sandbox/issues)
- **Discussions**: [GitHub Discussions](https://github.com/foundry-works/foundry-sandbox/discussions)

## License

MIT License. See [LICENSE](LICENSE) for details.
