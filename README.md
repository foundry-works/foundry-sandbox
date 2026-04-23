# Foundry Sandbox

[![CI](https://github.com/foundry-works/foundry-sandbox/actions/workflows/test.yml/badge.svg)](https://github.com/foundry-works/foundry-sandbox/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/foundry-sandbox)](https://pypi.org/project/foundry-sandbox/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built for Claude Code](https://img.shields.io/badge/Built_for-Claude_Code-cc785c)](https://docs.anthropic.com/en/docs/claude-code)

Ephemeral microVM workspaces that isolate AI coding agents from your host system, credentials, and git history.

## What It Does

Foundry Sandbox runs your code and AI assistants inside Docker `sbx` microVMs. Real credentials stay on the host. Git operations are proxied through `foundry-git-safety`, and outbound API credentials are injected by the host-side proxy instead of being exposed inside the VM.

The goal is practical blast-radius reduction: agents can work freely in an isolated workspace while host state, secrets, and protected git operations stay behind policy boundaries.

## Quick Start

1. Install standalone `sbx` and the `cast` CLI. See [Getting Started](docs/getting-started.md).
2. Authenticate on the host:

```bash
export CLAUDE_CODE_OAUTH_TOKEN="..."   # or ANTHROPIC_API_KEY
gh auth login                          # for private repos and push
```

3. Create a sandbox:

```bash
cast new owner/repo feature-login main
```

4. Attach to it:

```bash
cast attach repo-feature-login
```

5. Work inside `/workspace`, then destroy it when done:

```bash
cast destroy repo-feature-login --yes
```

`cast new` creates the sandbox and prints the follow-up commands. It does not open an interactive shell automatically.

## Core Commands

```bash
cast new owner/repo feature-login main
cast attach repo-feature-login
cast list
cast status repo-feature-login
cast stop repo-feature-login
cast start repo-feature-login
cast refresh-creds --all
cast diagnose
cast destroy repo-feature-login --yes
```

## Documentation

The maintained docs for the current product surface are:

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Install, authenticate, create, attach |
| [Commands](docs/usage/commands.md) | Current CLI reference |
| [Configuration](docs/configuration.md) | Environment variables, credentials, user services |
| [Operations](docs/operations.md) | Runbook and troubleshooting |
| [Security Model](docs/security/security-model.md) | Threat model and enforcement boundaries |
| [Workflows](docs/usage/workflows.md) | Common day-to-day patterns |

The docs set is intentionally small and current-state focused.

## Limitations

- Designed for accidental damage, misconfigured automation, and supply-chain risk, not a determined host-level attacker
- Requires standalone Docker `sbx`
- Linux and macOS work natively; Windows requires WSL2

## License

MIT. See [LICENSE](LICENSE).
