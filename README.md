# Foundry Sandbox

[![CI](https://github.com/foundry-works/foundry-sandbox/actions/workflows/test.yml/badge.svg)](https://github.com/foundry-works/foundry-sandbox/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/foundry-sandbox)](https://pypi.org/project/foundry-sandbox/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built for Claude Code](https://img.shields.io/badge/Built_for-Claude_Code-cc785c)](https://docs.anthropic.com/en/docs/claude-code)

Git policy and workflow layer for AI coding agents running in Docker `sbx` microVMs.

## Why Foundry vs. plain sbx

`sbx` provides the microVM, network policy, and host-side credential injection. Foundry adds the controls `sbx` does not:

| Layer | Provided by |
|-------|-------------|
| MicroVM isolation, network policy, credential injection | `sbx` |
| Git policy: branch isolation, protected branches, file-pattern blocks | Foundry |
| GitHub API filtering: blocks PR merges, release creation, webhook/secret access | Foundry |
| HMAC-authenticated git wrapper with SHA-256 integrity watchdog | Foundry |
| Proxy-URL injection for user-defined services (`TAVILY_API_KEY`, …) | Foundry |
| `cast` CLI: clone → worktree → sandbox → wrapper → metadata in one command | Foundry |

Use `sbx` alone for an ephemeral microVM. Use Foundry when you also want the agent to be unable to push to `main`, merge its own PR, exfiltrate via `.github/workflows/`, or silently replace `/usr/local/bin/git`.

## What It Does

Foundry installs a git wrapper at `/usr/local/bin/git` in each sandbox. Every git command routes through `foundry-git-safety` on the host, which validates refs, enforces branch isolation, blocks pushes to protected branches and sensitive file patterns, filters GitHub API calls, and logs decisions for audit. A host-side watchdog checksums the wrapper and re-injects it if a process inside the sandbox tampers with it.

Repo and user policy live primarily in `foundry.yaml`. Foundry resolves built-in defaults, `~/.foundry/foundry.yaml`, and repo `foundry.yaml`, then compiles git-safety overlays, proxy-backed service env vars, MCP config, and Claude Code config into sandbox artifacts at creation time.

The goal is practical blast-radius reduction: agents can work freely in an isolated workspace while host state, secrets, and protected git operations stay behind policy boundaries.

## Quick Start

1. Install standalone `sbx` and the `cast` CLI. See [Getting Started](docs/getting-started.md).
2. Authenticate on the host:

```bash
export CLAUDE_CODE_OAUTH_TOKEN="..."   # or ANTHROPIC_API_KEY
gh auth login                          # for private repos and push
```

3. Optional: preview the resolved config and generated artifacts:

```bash
cast new owner/repo feature-login main --plan
```

4. Create a sandbox:

```bash
cast new owner/repo feature-login main
```

5. Attach to it:

```bash
cast attach repo-feature-login
```

6. Work inside `/workspace`, then destroy it when done:

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
| [Configuration](docs/configuration.md) | `foundry.yaml`, credentials, MCP, Claude Code, user services |
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
