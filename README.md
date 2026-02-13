# Foundry Sandbox

Safe, ephemeral workspaces for AI-assisted coding—isolate mistakes, not productivity.

## Overview

Your API keys and tokens are exposed to everything running on your machine—including malicious dependencies, compromised tools, and AI assistants that might leak them. Supply chain attacks are increasingly common, and a single `npm install` can run arbitrary code with access to your credentials.

Foundry Sandbox provides ephemeral Docker workspaces where credentials never enter the container. A unified proxy holds your real API keys and tokens on the host, injecting them into outbound requests only after validation. Code running inside the sandbox—whether it's an AI assistant, a build script, or a malicious package—never sees the actual credentials.

Beyond credential isolation, sandboxes provide defense in depth:

- **Read-only filesystem** — Prevents destructive commands like `rm -rf /`
- **Network allowlists** — Egress restricted to approved domains (GitHub, AI APIs, etc.)
- **Disposable worktrees** — Each sandbox is a git worktree; create in seconds, destroy with zero trace
- **Multi-tool ready** — Claude Code, Gemini CLI, Codex CLI, and OpenCode pre-installed

The result: run AI assistants and untrusted code with the confidence that your credentials and host system are protected by multiple independent security layers.

Finally, in addition to providing tight security guardrails, this sandbox is designed to enable spec-driven development using the `foundry-mcp` server and `claude-foundry` plugin, which are automatically installed and pre-configured.

## Key Features

- **Ephemeral Workspaces** - Git worktrees per sandbox; destroy when done with no trace
- **Defense in Depth** - Multiple security pillars enforced by Docker and the kernel
- **Multiple AI Tools** - Claude Code, Gemini CLI, Codex CLI, and OpenCode pre-installed
- **Fast Creation** - Worktrees share git objects; new sandboxes spin up in seconds
- **Network Control** - Limited (allowlist), host-only, or no network access
- **Credential Isolation** - API keys stay outside sandboxes via proxy (enabled by default)
- **Branch Isolation** - Each sandbox restricted to its own git branch; other sandboxes' branches hidden
- **Git Safety** - Protected branch enforcement, force-push blocking, GitHub API operation controls
- **Presets & History** - Save configurations as presets; repeat last command with `cast repeat`
- **Volume Mounts** - Mount host directories read-write or read-only
- **JSON Output** - All commands support `--json` for scripting and automation

## Prerequisites

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| Docker | 20.10+ | `docker --version` |
| Git | 2.x+ | `git --version` |
| Bash | 4.x+ | `bash --version` |
| tmux | 3.x+ | `tmux -V` |
| Python | 3.10+ | `python3 --version` |

Linux and macOS supported natively. Windows users need WSL2. macOS ships Bash 3.2—install Bash 4+ via `brew install bash`. Python 3.10+ is required.

## Installation

### Full install (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
```

This will clone to `~/.foundry-sandbox`, add the `cast` alias to your shell, enable tab completion, and build the Docker image.

For manual installation or uninstall instructions, see [Getting Started](docs/getting-started.md).

### PyPI package

`foundry-sandbox` is published on PyPI and provides the `cast` Python entry point:

```bash
pipx install foundry-sandbox
# or
pip install foundry-sandbox
```

Important: full sandbox operation still requires repository runtime assets (`docker-compose.yml`, `docker-compose.credential-isolation.yml`, `unified-proxy/`, `stubs/`). Use the installer above (or clone the repo and run `pip install -e .`) for a complete setup.

## Quick Start

**1. Create a sandbox**

```bash
cast new
```

The guided wizard walks you through repo selection, branch strategy, and options. It detects your current repo and offers smart defaults.

For scripting or quick one-liners:

```bash
cast new owner/repo              # From GitHub
cast new .                       # From current repo/branch
cast new . feature-branch main   # Create new branch from main
```

**2. Run an AI assistant**

```bash
claude              # Claude Code
gemini              # Gemini CLI
codex               # Codex CLI
opencode            # OpenCode
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

**Tip: Save configurations for reuse**

```bash
cast new owner/repo feature --wd packages/app --save-as myproject  # save preset
cast new --preset myproject                                         # reuse later
cast repeat                                                         # repeat last command
```

## Limitations

- **Not a targeted-attack boundary** - Protects against automated threats (supply chain attacks, credential-stealing packages) and AI mistakes, but not a targeted human attacker with Docker access on the host
- **Requires Docker** - No native process isolation; container overhead applies
- **Linux/macOS focus** - Windows requires WSL2
- **No GPU passthrough** - GPU workloads need additional Docker configuration

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation and first sandbox |
| [Commands](docs/usage/commands.md) | Full command reference |
| [Workflows](docs/usage/workflows.md) | Common patterns and recipes |
| [Configuration](docs/configuration.md) | API keys, plugins, and config files |
| [Architecture](docs/architecture.md) | Technical design and diagrams |
| [Security Overview](docs/security/index.md) | Security architecture quick reference |
| [Sandbox Threats](docs/security/sandbox-threats.md) | AI-as-threat-actor model |
| [Security Architecture](docs/security/security-architecture.md) | Security pillars and defense layers |
| [Credential Isolation](docs/security/credential-isolation.md) | Credential isolation threat model |
| [Network Isolation](docs/security/network-isolation.md) | Network architecture details |
| [Operations](docs/operations.md) | Proxy operations runbook |
| [Observability](docs/observability.md) | Metrics and debugging |
| [Certificates](docs/certificates.md) | CA certificate management |
| [Contributing](docs/development/contributing.md) | For contributors |

## Support

- **Issues**: [GitHub Issues](https://github.com/foundry-works/foundry-sandbox/issues)
- **Discussions**: [GitHub Discussions](https://github.com/foundry-works/foundry-sandbox/discussions)

## License

MIT License. See [LICENSE](LICENSE) for details.
