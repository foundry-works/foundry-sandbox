# Foundry Sandbox

Safe, ephemeral workspaces for AI-assisted coding—isolate mistakes, not productivity.

## Overview

AI coding assistants are powerful but imperfect. They can hallucinate destructive commands, misunderstand context, or make changes you didn't intend. Running them directly on your machine means one bad `rm -rf` or `git push --force` away from real damage.

Foundry Sandbox solves this by providing isolated Docker environments with defense-in-depth safety layers. Each sandbox is a disposable git worktree where AI tools can operate freely while multiple safeguards prevent accidents from escaping. You get the productivity of AI assistance with the confidence that mistakes stay contained.

## Key Features

- **Ephemeral Workspaces** - Git worktrees per sandbox; destroy when done with no trace
- **Defense in Depth** - Multiple security pillars enforced by Docker and the kernel
- **Multiple AI Tools** - Claude Code, Gemini CLI, Codex CLI, and OpenCode pre-installed
- **Fast Creation** - Worktrees share git objects; new sandboxes spin up in seconds
- **Network Control** - Limited (allowlist), host-only, or no network access
- **Credential Isolation** - API keys stay outside sandboxes via proxy (enabled by default)
- **Volume Mounts** - Mount host directories read-write or read-only
- **JSON Output** - All commands support `--json` for scripting and automation

## Prerequisites

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| Docker | 20.10+ | `docker --version` |
| Git | 2.x+ | `git --version` |
| Bash | 4.x+ | `bash --version` |
| tmux | 3.x+ | `tmux -V` |

Linux and macOS supported natively. Windows users need WSL2. macOS ships Bash 3.2—install Bash 4+ via `brew install bash`.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
```

This will clone to `~/.foundry-sandbox`, add the `cast` alias to your shell, enable tab completion, and build the Docker image.

For manual installation or uninstall instructions, see [Getting Started](docs/getting-started.md).

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

## Limitations

- **Not a security boundary against malicious actors** - Protects against accidental damage from well-intentioned AI, not adversarial attacks
- **Requires Docker** - No native process isolation; container overhead applies
- **Linux/macOS focus** - Windows requires WSL2
- **Shared git history** - All sandboxes share the same bare repo; force-push from one affects others
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
| [Contributing](docs/development/contributing.md) | For contributors |

## Support

- **Issues**: [GitHub Issues](https://github.com/foundry-works/foundry-sandbox/issues)
- **Discussions**: [GitHub Discussions](https://github.com/foundry-works/foundry-sandbox/discussions)

## License

MIT License. See [LICENSE](LICENSE) for details.
