# Getting Started

This guide walks you through installing Foundry Sandbox and creating your first isolated development environment.

## Prerequisites

- **Docker sbx** — Sandbox runtime (microVM-based isolation). See [sbx Compatibility](sbx-compatibility.md) for supported versions.
- **Git** - Version control
- **Bash** - Shell (Linux/macOS default, WSL2 on Windows)
- **Python** - 3.10+
- **foundry-git-safety** — Git safety service (installed automatically)

Verify your setup:

```bash
sbx --version       # Docker sbx CLI
git --version       # git version 2.x+
python3 --version   # Python 3.10+
```

### Installing Docker sbx

```bash
# macOS
brew install docker/tap/sbx

# Windows
winget install Docker.sbx

# Linux — download from GitHub releases
# https://github.com/docker/sbx-releases
# .deb for Ubuntu 24.04/25.10/26.04, .rpm for Rocky Linux 8
```

### Installing foundry-git-safety

```bash
pip install foundry-git-safety[server]
```

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
```

This installs to `~/.foundry-sandbox` and:
- Installs the `foundry-sandbox` Python package (provides the `cast` CLI)

After installation, reload your shell:

```bash
source ~/.bashrc  # or ~/.zshrc
```

The `cast` CLI is installed automatically by `install.sh` via `pip install -e .` (using the entry point defined in `pyproject.toml`).

### PyPI package

`foundry-sandbox` is published on PyPI and provides the `cast` Python entry point:

```bash
pipx install foundry-sandbox
# or
pip install foundry-sandbox
```

## Creating Your First Sandbox

Run `cast new` with no arguments to launch the guided setup (gum if available, read-based fallback).

### From a GitHub Repository

```bash
cast new owner/repo
```

This will:
1. Clone the repository (if not already cloned)
2. Create a git worktree with a timestamped branch name
3. Create an sbx microVM sandbox with the worktree synced
4. Start the git safety server
5. Inject the git wrapper for policy enforcement
6. Attach you to an interactive shell inside the sandbox

### From an Existing Branch

```bash
cast new owner/repo feature-branch
```

### Create a New Branch

```bash
cast new owner/repo my-new-feature main
```

Creates `my-new-feature` branch starting from `main`.

### Choose an Agent

```bash
# Default is Claude Code
cast new owner/repo feature

# Use a different agent
cast new owner/repo feature --agent codex
cast new owner/repo feature --agent gemini
cast new owner/repo feature --agent shell
```

For all options, see [Commands](usage/commands.md).

## Working in Your Sandbox

Once attached, you're in a bash shell inside the microVM sandbox at `/workspace` (your code).

### Run an AI Assistant

```bash
claude      # Claude Code
gemini      # Gemini CLI
codex       # Codex CLI
opencode    # OpenCode
```

### Navigate and Edit

```bash
# Your code is at /workspace
cd /workspace
ls -la

# Standard tools available
vim file.py
git status
npm install
```

All git operations are automatically routed through the git safety server for policy enforcement (branch isolation, push protection, etc.).

### Exit the Sandbox

```bash
# Exit the interactive shell (sandbox continues running)
exit
```

## Managing Sandboxes

### List All Sandboxes

```bash
cast list
```

### Attach to a Running Sandbox

```bash
cast attach sandbox-name

# Or use fzf selector (if no name provided)
cast attach

# Reattach to last sandbox
cast attach --last
```

### Stop a Sandbox

```bash
cast stop sandbox-name
```

Stops the sandbox but preserves the worktree. Restart with `cast start`.

### Destroy a Sandbox

```bash
cast destroy sandbox-name
```

Removes the sandbox, worktree, and associated configs. You'll be prompted to confirm.

## Environment Variables

```bash
# GitHub - use gh CLI (recommended) or export token directly
gh auth login
export GITHUB_TOKEN="ghp_..."     # required for private repos / push

# Claude Code
export CLAUDE_CODE_OAUTH_TOKEN="..."   # get via: claude setup-token

# API keys are pushed to sbx via cast refresh-creds
cast refresh-creds
```

API keys are stored on the host by sbx and injected into sandbox requests at the network level. They never enter the sandbox VM.

See [Commands: Environment Variables](usage/commands.md#environment-variables) for the full reference including keys for Gemini, Codex, and search providers.

### CI / Non-Interactive Mode

Set `SANDBOX_NONINTERACTIVE=1` to suppress all interactive prompts. When enabled, confirmations default to "yes" and selection prompts use the first option. This is useful for CI pipelines and scripted workflows.

```bash
SANDBOX_NONINTERACTIVE=1 cast destroy sandbox-name
```

## See Also

- [Architecture](architecture.md) — Understand how sandboxes work
- [Security Model](security/security-model.md) — Safety guarantees and threat model
- [Configuration](configuration.md) — Git safety and network policy settings
- [Commands](usage/commands.md) — Full command reference
- [Workflows](usage/workflows.md) — Common patterns and recipes
